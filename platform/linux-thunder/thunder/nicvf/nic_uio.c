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

#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_uio.h"
#include <odp_shm_internal.h>

static struct nic_ops uio_ops;

static inline int read_num(const char *filename, const char *fmt, void *val)
{
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL) {
		ERR("Cannot open %s:%s\n", filename, strerror(errno));
		return -ENOENT;
	}
	if (fscanf(f, fmt, val) != 1) {
		ERR("Cannot read %s\n", filename);
		fclose(f);
		return -EINVAL;
	}
	fclose(f);
	return 0;
}

static int nic_uio_map_bar(struct uio_vnic_t *vnic, unsigned bar, void **va)
{
	char filename[PATH_MAX];
	unsigned long bar_size;
	unsigned long bar_offset;

	snprintf(filename, sizeof(filename),
		SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/uio/uio%u/maps/map%u/size",
		PCI_PRI_ARGS(vnic->dev_addr), vnic->uio_num, bar);

	if (read_num(filename, "%lx", &bar_size))
		return -1;

	bar_offset = bar * sysconf(_SC_PAGESIZE);

	*va = mmap(0, bar_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, vnic->dev_fd, bar_offset);
	if (*va == MAP_FAILED) {
		fprintf(stderr, "Cannot map bar %u: %s\n",
			bar, strerror(errno));
		return -1;
	}

	NFO("Bar %u mapped at %p size 0x%lx\n", bar, *va, bar_size);

	return 0;
}

static int nic_uio_find_dev(struct uio_vnic_t *uio_vnic)
{
	char link[PATH_MAX];
	char device[PATH_MAX];
	struct nic_pci_addr *addr;
	int ret;
	char *dev;

	snprintf(link, sizeof(link), "/sys/class/uio/uio%u/device", uio_vnic->uio_num);

	ret = readlink(link, device, sizeof(device));
	if (ret < 0) {
		fprintf(stderr, "Cannot read symbolic link %s: %s\n",
					link, strerror(errno));
		return -1;
	}
	device[ret] = '\0';

	dev = strrchr(device, '/');
	if (dev == NULL) {
		fprintf(stderr, "Malformed device path %s\n",
					device);
		return -1;

	}

	addr = &uio_vnic->dev_addr;
	ret = sscanf(dev, "/"PCI_SCAN_FMT,
		&addr->domain, &addr->bus, &addr->devid, &addr->function);

	if (ret != 4) {
		fprintf(stderr, "Cannot scan device path %s: %s\n",
					device, strerror(errno));
		return -1;
	}

	return 0;
}

static void __attribute__((unused)) nic_pci_addr_to_str(struct nic_pci_addr *addr, char *s, size_t n)
{
	snprintf(s, n, PCI_PRI_FMT, PCI_PRI_ARGS(*addr));
}

static int nic_uio_check_dev(struct uio_vnic_t *uio_vnic)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX];
	uint32_t uio_num = UINT_MAX;
	int len;
	unsigned vendor_id, device_id;

	len = snprintf(path, sizeof(path),SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/",
		PCI_PRI_ARGS(uio_vnic->dev_addr));


	strcpy(path+len, "vendor");
	if (read_num(path, "%x", &vendor_id)) {
		ERR("No vendor id in %s\n", path);
		return -ENOENT;
	}

	strcpy(path+len, "device");
	if (read_num(path, "%x", &device_id)) {
		ERR("No device id in %s\n", path);
		return -ENOENT;
	}

	if ((vendor_id != PCI_VENDOR_ID_CAVIUM) ||
		((PCI_DEVICE_ID_CN81XX_NIC_VF != device_id) &&
		(PCI_DEVICE_ID_THUNDER_PASS2_NIC_VF != device_id) &&
		(PCI_DEVICE_ID_THUNDER_PASS1_NIC_VF != device_id))) {
		ERR("Device %x:%x is not Thunder NIC\n", vendor_id, device_id);
		return -EINVAL;
	}

	strcpy(path+len, "uio");

	dir = opendir(path);
	if (dir  == NULL) {
		ERR("Cannot open dir %s\n",path);
		return errno;
	}

	do {
		ent = readdir(dir);
	} while (ent != NULL && sscanf(ent->d_name, "uio%u", &uio_num) != 1);

	closedir(dir);

	if (uio_num == UINT_MAX) {
		ERR("No uio entry for %s\n", path);
		return -ENOENT;
	}

	return 0;
}

int nic_uio_init(struct nicvf *nic, size_t dev_cnt, unsigned dev[])
{

	struct uio_vnic_t *vnic;
	size_t i;
	int rc;
	char devname[PATH_MAX];

	nic->nicvf_type = NICVF_TYPE_UIO;
	nic->nicvf_ops = &uio_ops;
	nic->uio.vnic_cnt = dev_cnt;
	for (i = 0; i < dev_cnt; i++) {

		vnic = &nic->uio.vnics[i];
		vnic->uio_num = dev[i];

		if ((rc = nic_uio_find_dev(vnic)))
			return rc;

		if ((rc = nic_uio_check_dev(vnic)))
			return rc;

		NFO("Found uio %u dev "PCI_PRI_FMT"\n",
		    vnic->uio_num, PCI_PRI_ARGS(vnic->dev_addr));

		snprintf(devname, sizeof(devname), "/dev/uio%u", vnic->uio_num);
		vnic->dev_fd = open(devname, O_RDWR);
		if (vnic->dev_fd < 0) {
			fprintf(stderr, "Cannot open %s: %s\n",
				devname, strerror(errno));
			return -1;
		}

		nic_uio_map_bar(vnic, 0, &(nic->qset[i].qset_reg_base));
		nic->qset[i].enable = true;
	}
	nic->qset_cnt = dev_cnt;

	/* Find uio resource for given device */


	return 0;
}

int nic_uio_close(struct nicvf * UNUSED(nic))
{
	return 0;
}

static int nic_uio_dma_map(struct nicvf * UNUSED(nic), void* uva,
			   size_t UNUSED(size), uint64_t *iova)
{
	odp_shm_t shm = odp_shm_lookup_addr(uva);
	if (shm == ODP_SHM_INVALID)
		return -ENOENT;
	/* TODO: make sure mem is continuous */
	*iova = odp_shm_phys_addr(shm, uva);
	return 0;
}

static int nic_uio_dma_unmap(struct nicvf * UNUSED(nic), void* UNUSED(uva),
			     size_t UNUSED(size), uint64_t UNUSED(iova))
{
	/* TODO: Find mem by iova or change the interface*/
	return 0;
}

static struct nic_ops uio_ops = {
	.nic_dma_map = nic_uio_dma_map,
	.nic_dma_unmap = nic_uio_dma_unmap
};
