/***********************license start***************
 * Copyright (c) 2003-2014  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 *   * Neither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.
 *
 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include <alloca.h>

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_vfio.h"
#include "thunder/nicvf/nic_queues.h"

#define VFIO_DEV_DIR		"/dev/vfio"
#define VFIO_DEV_NODE		VFIO_DEV_DIR "/vfio"
#define IOMMU_GROUP_DIR		"/sys/kernel/iommu_groups"
#define PCI_BAR_OFFSET(b)	(offsetof(struct pci_device_header, bar[b]))

static struct nic_ops vfio_ops;

struct buffed_vfio_irq_set {
	struct vfio_irq_set irq;
	int fds[20];
};

struct trigger_vfio_irq_set {
	struct vfio_irq_set irq;
	uint8_t bits[20];
};

static int nic_vfio_bar_map(int dev_fd, size_t bar, void **addr)
{
	int prot = 0;
	struct vfio_region_info region_info = {
		.argsz = sizeof(region_info),
		.index = bar,
	};

	printf("Getting region info for BAR %zu\n", bar);

	if (ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO,
		  &region_info) < 0) {
		ERR("Couldn't get device region info idx=%zu : %s\n", bar, strerror(errno));
		return -1;
	}
	/* Ignore invalid or unimplemented regions */
	if (0 == region_info.size) {
		printf("Ignoring 0 size BAR %zu unimplemented BAR\n", bar);
		return -1;
	}

	/* Ignore regions that cannot be mmaped */
	if (!(region_info.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
		ERR("Ignoring BAR %zu, as it can't be"
			" mmape'd\n", bar);
		return -1;
	}

	/* Map the device file area from given bar offset */
	prot |= (region_info.flags & VFIO_REGION_INFO_FLAG_READ) ? PROT_READ : 0;
	prot |= (region_info.flags & VFIO_REGION_INFO_FLAG_WRITE) ? PROT_WRITE : 0;
	*addr = mmap(NULL, region_info.size, prot,
		     MAP_SHARED, dev_fd,
		     region_info.offset);
	if (MAP_FAILED == *addr) {
		ERR("Couldn't mmap region: %s\n", strerror(errno));
		return -1;
	}

	printf("Mapped BAR %zu addr=%p size=%llu prot=%d\n",
	       bar, *addr, region_info.size, prot);
	return 0;
}

static int nic_vfio_bar_unmap(int dev_fd, size_t bar, void* addr)
{
	struct vfio_region_info region_info = {
		.argsz = sizeof(region_info),
		.index = bar,
	};

	if (ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO,
		  &region_info) < 0) {
		ERR("Couldn't get device region info idx=%zu : %s\n", bar, strerror(errno));
		return -1;
	}
	/* Ignore invalid or unimplemented regions */
	if (0 == region_info.size) {
		printf("Ignoring 0 size BAR %zu unimplemented BAR\n", bar);
		return -1;
	}
	if (munmap(addr, region_info.size)) {
		ERR("Couldn't unmap region: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int nic_vfio_dma_map(struct nicvf *nic, void* uva, size_t size,
			    uint64_t *iova)
{
	struct vfio_iommu_type1_dma_map dma_map;

	/* Setup a DMA mapping by vfio */
	dma_map = (struct vfio_iommu_type1_dma_map) {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr = (uint64_t)uva,
		.size  = size,
		.iova  = (uint64_t)uva,
	};
	if (ioctl(nic->vfio.cont_fd, VFIO_IOMMU_MAP_DMA, &dma_map) < 0)
	{
		ERR("Couldn't map DMA memory area: %s\n", strerror(errno));
		return -1;
	}

	/* We mapped user virtual address to the same virtual address in device
	 * PCI address space,
	 * Both CPU and NIC see the same memory location under the same
	 * address and we can just return it */
	*iova = (uint64_t)uva;

	return 0;
}

static int nic_vfio_dma_unmap(struct nicvf *nic, void* UNUSED(uva), size_t size,
			      uint64_t iova)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof(dma_unmap),
		.flags = 0,
		.iova  = iova,
		.size  = size,
	};
	if (ioctl(nic->vfio.cont_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap) < 0) {
		ERR("Couldn't unmap DMA memory area: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int nic_vfio_cont_open(void)
{
	int fd;

	fd = open(VFIO_DEV_NODE, O_RDWR);
	if (fd < 0) {
		perror("Couldn't open container device file "
		       VFIO_DEV_NODE);
		return -1;
	}

	if (ioctl(fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
		ERR("Invalid VFIO API version\n");
		return -1;
	}

	if (!ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		ERR("VFIO does not support TYPE1_IOMMU\n");
		return -1;
	}

	return fd;
}

static int nic_vfio_group_open(unsigned group, int cont_fd)
{
	int group_fd;
	struct vfio_group_status group_status;
	char buff[PATH_MAX] = { 0 };

	snprintf(buff, sizeof(buff), VFIO_DEV_DIR "/%u", group);
	group_fd = open(buff, O_RDWR);
	if (group_fd < 0) {
		ERR("Couldn't open group device file %s : %s",
			buff, strerror(errno));
		return -1;
	}

	/* Test the group is viable and available */
	group_status = (struct vfio_group_status) {
		.argsz = sizeof(group_status),
	};
	if ((ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status) < 0) ||
	    !(group_status.flags & VFIO_GROUP_FLAGS_VIABLE) )
	{
		perror("Coudn't get group status or group is not viable "
		       "(ie, not all devices bound for vfio");
		close(group_fd);
		return -1;
	}

	/* Add the group to the container */
	if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &(cont_fd)) < 0) {
		ERR("Couldn't add group to container: %s\n", strerror(errno));
		close(group_fd);
		return -1;
	}

	return group_fd;
}

static int nic_vfio_group_sanitize(unsigned group, char *dev_name)
{
	long name_max;
	DIR *dir;
	struct dirent *direntdev, *direnttmp, *direntres;
	char dirpath[PATH_MAX] = { 0 };

	name_max = pathconf(dirpath, _PC_NAME_MAX);
	if (-1 == name_max) { /* Limit not defined, or error */
		name_max = PATH_MAX; /* take a guess */
	}
	direntdev = alloca(offsetof(struct dirent, d_name) + name_max + 1);
	assert(direntdev);
	direnttmp = alloca(offsetof(struct dirent, d_name) + name_max + 1);
	assert(direnttmp);

	snprintf(dirpath, PATH_MAX, IOMMU_GROUP_DIR "/%u/devices",
		 group);

	dir = opendir(dirpath);
	if (!dir) {
		ERR("Couldn't open sysfs group directory: %s\n", strerror(errno));
		return -1;
	}
	for (;;) {
		if (readdir_r(dir, direntdev, &direntres) ||
		    (!direntres)) {
			ERR("Counldn't fetch sysfs directory entries: %s\n", strerror(errno));
			closedir(dir);
			return -1;
		}
		if (direntdev->d_type != DT_LNK) {
			continue;
		}
		/* here we should get first dir entry which is our PCI dev */
		printf("Found PCI device %s within group %u\n",
		       direntdev->d_name, group);

		strncpy(dev_name, direntdev->d_name, PATH_MAX);
		break;
	}
	/* try if this is the only entry in dir */
	if (readdir_r(dir, direnttmp, &direntres) || direntres ) {
		ERR("More than one device in group!, driver does"
			" not support that!\n");
		return -1;
	}
	if (closedir(dir)) {
		ERR("Couldn't close IOMMU group: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int nic_vfio_pcidev_open(int group_fd, char* dev_name)
{
	struct vfio_device_info device_info;
	int dev_fd;

	/* Get VFIO file descriptor for the device for config */
	dev_fd = ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
	if (dev_fd < 0) {
		ERR("Couldn't not get the file descriptor for"
			" device within a group: %s : %s\n",
			dev_name, strerror(errno));
		return -1;
	}

	/* Get device info, including device region count and IRQ count */
	device_info = (struct vfio_device_info) {
		.argsz = sizeof(device_info),
	};
	if (ioctl(dev_fd, VFIO_DEVICE_GET_INFO, &device_info) < 0)
	{
		ERR("Failed to get info for device: %s\n", strerror(errno));
		close(dev_fd);
		return -1;
	}
	/* Verify that this is PCI device */
	if (!(device_info.flags & VFIO_DEVICE_FLAGS_PCI)) {
		ERR("Device is not PCI device\n");
		close(dev_fd);
		return -1;
	}
	/* Verify that device expose configuration bar region */
	if (device_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX) {
		ERR("Configuration Space not found\n");
		close(dev_fd);
		return -1;
	}

	printf("Got %u regions from config space\n", device_info.num_regions);

	/* Gratuitous device reset */
	if (device_info.flags & VFIO_DEVICE_FLAGS_RESET) {
		printf("Reseting device\n");
		if (ioctl(dev_fd, VFIO_DEVICE_RESET) < 0) {
			ERR("Warning: couldn't reset the device"
				" fd=%i : %s\n",
				dev_fd, strerror(errno));
			/* try to continue */
		}
	}

	return dev_fd;
}

static int nic_vfio_pcidev_headerparse(
	int dev_fd, struct pci_device_header *pci_header)
{
	struct vfio_region_info region_info;

	/* Get and parse device configuration region */
	region_info = ( struct vfio_region_info) {
		.argsz = sizeof(region_info),
		.index = VFIO_PCI_CONFIG_REGION_INDEX,
	};
	if (ioctl(dev_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info) < 0) {
		ERR("Couldn't get device configuration region info: %s\n", strerror(errno));
		close(dev_fd);
		return -1;
	}
	if (0 == region_info.size)
	{
		ERR("Configuration region has 0 bytes!\n");
		close(dev_fd);
		return -1;
	}
	/* Read PCI configuration reagion from provided offset */
	if (pread(dev_fd, pci_header, PCI_DEV_CFG_SIZE,
		  region_info.offset) != PCI_DEV_CFG_SIZE) {
		ERR("Failed to read configuration region: %s\n", strerror(errno));
		close(dev_fd);
		return -1;
	}
	if (pci_header->header_type != PCI_HEADER_TYPE_NORMAL) {
		ERR("Unsupported header type %u",
			pci_header->header_type);
		close(dev_fd);
		return -1;
	}

	/* Verify that this is in fact Cavium VF NIC */
	if ((PCI_VENDOR_ID_CAVIUM != pci_header->vendor_id) ||
	    ((PCI_DEVICE_ID_CN81XX_NIC_VF != pci_header->device_id) &&
	    (PCI_DEVICE_ID_THUNDER_PASS2_NIC_VF != pci_header->device_id) &&
		PCI_DEVICE_ID_THUNDER_PASS1_NIC_VF != pci_header->device_id)) {
		ERR("Device seem not to be a Cavium VNIC %"PRIu16
			" %"PRIu16, pci_header->vendor_id,
			pci_header->device_id);
		close(dev_fd);
		return -1;
	}

	return 0;
}

int nic_vfio_init(struct nicvf *nic, size_t dev_cnt, unsigned dev_grps[])
{
	size_t i;

	/* error checking */
	if (dev_cnt > MAX_QSETS_PER_NIC) {
		return -1;
	}
	/* initialization for detection of blanks during error bailout */
	for (i = 0; i < MAX_QSETS_PER_NIC; i++) {
		struct vfio_vnic_t *vnics = &(nic->vfio.vnics[i]);

		vnics->group_fd = -1;
		vnics->dev_fd = -1;
		vnics->vfio_grp = dev_grps[i];
		memset(&(vnics->pci_header), 0, sizeof(struct pci_device_header));
		nic->qset[i].qset_reg_base = NULL;
	}

	nic->nicvf_type = NICVF_TYPE_VFIO;
	nic->nicvf_ops = &vfio_ops;

	/* Create a new container */
	nic->vfio.cont_fd = nic_vfio_cont_open();
	if (nic->vfio.cont_fd < 0)
		return -1;

	/* Open all SQS groups and add them to container */
	nic->vfio.vnic_cnt = dev_cnt;
	for (i = 0; i < dev_cnt; i++) {
		if (nic_vfio_group_sanitize(
				dev_grps[i], nic->vfio.vnics[i].dev_name))
			goto err_grp;
		int group_fd = nic_vfio_group_open(dev_grps[i], nic->vfio.cont_fd);
		if (group_fd < 0) {
			goto err_grp;
		}
		nic->vfio.vnics[i].group_fd = group_fd;
	}

	/* Finalize the container, enable the IOMMU model we want */
	if (ioctl(nic->vfio.cont_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0)
	{
		ERR("Couldn't set the VFIO_TYPE1_IOMMU for container: %s\n", strerror(errno));
		goto err_grp;
	}

	/* TODO Get info about supported DMA PCI bus ranges */

	/* Get all VNIC's device_fd and verify their Cavium PCI ID's */
	for (i = 0; i < dev_cnt; i++) {
		int dev_fd = nic_vfio_pcidev_open(nic->vfio.vnics[i].group_fd,
						  nic->vfio.vnics[i].dev_name);
		if (dev_fd < 0)
			goto err_dev_fd;
		nic->vfio.vnics[i].dev_fd = dev_fd;
		if (nic_vfio_pcidev_headerparse(
				dev_fd, &nic->vfio.vnics[i].pci_header))
			goto err_dev_fd;
	}

	/* Map all SQS BAR0 */
	for (i = 0; i < dev_cnt; i++) {
		if (nic_vfio_bar_map(
			nic->vfio.vnics[i].dev_fd, VFIO_PCI_BAR0_REGION_INDEX,
			&(nic->qset[i].qset_reg_base))) {
				goto err_bar0_map;
		}
		nic->qset[i].enable = true;
	}
	nic->qset_cnt = dev_cnt;

	/* TODO parse MSIX capabilities */

	return 0;

err_bar0_map:
	for (i = 0; i < dev_cnt; i++) {
		(void)nic_vfio_bar_unmap(
			nic->vfio.vnics[i].dev_fd, VFIO_PCI_BAR0_REGION_INDEX,
			nic->qset[i].qset_reg_base);
	}
err_dev_fd:
	for (i = 0; i < dev_cnt; i++) {
		int fd = nic->vfio.vnics[i].dev_fd;
		if (fd > 0) close(fd);
	}
err_grp:
	for (i = 0; i < dev_cnt; i++) {
		int fd = nic->vfio.vnics[i].group_fd;
		if (fd > 0) close(fd);
	}
	close(nic->vfio.cont_fd);
	return -1;
}

void nic_vfio_close(struct nicvf *nic)
{
	struct vfio_vnic_t *vnic;
	size_t i;
	size_t dev_cnt = nic->vfio.vnic_cnt;

	for (i = 0; i < dev_cnt; i++) {

		vnic = &nic->vfio.vnics[i];

		if (nic_vfio_bar_unmap(
			vnic->dev_fd, VFIO_PCI_BAR0_REGION_INDEX,
			nic->qset[i].qset_reg_base)) {
				ERR("Couldn't unmap the BF configuration BAR\n");
		}

		if (close(vnic->dev_fd)) {
			ERR("Couldn't close the device fd: %s\n", strerror(errno));
		}

		if (ioctl(vnic->group_fd, VFIO_GROUP_UNSET_CONTAINER,
			  &(nic->vfio.cont_fd)) < 0) {
			ERR("Couldn't remove group from container: %s\n", strerror(errno));
		}

		if (close(vnic->group_fd)) {
			ERR("Error durring close: %s\n", strerror(errno));
		}
	}

	if (close(nic->vfio.cont_fd)) {
		ERR("Error durring close: %s\n", strerror(errno));
	}
	memset(nic, 0xff, sizeof(*nic));
}

static struct nic_ops vfio_ops = {
	.nic_dma_map = nic_vfio_dma_map,
	.nic_dma_unmap = nic_vfio_dma_unmap
};

