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

#ifndef __THUNDER_NIC_PCI__
#define __THUNDER_NIC_PCI__

#include <stdint.h>

/* PCI device IDs */
#define	PCI_VENDOR_ID_CAVIUM			0x177d
#define	PCI_DEVICE_ID_THUNDER_NIC_PF		0xA01E
#define	PCI_DEVICE_ID_THUNDER_PASS1_NIC_VF	0x0011
#define	PCI_DEVICE_ID_THUNDER_PASS2_NIC_VF	0xA034
#define	PCI_DEVICE_ID_CN81XX_NIC_VF		0xA234

/* PCI BAR nos */
#define	PCI_CFG_REG_BAR_NUM		0
#define	PCI_MSIX_REG_BAR_NUM		4

#define PCI_DEV_CFG_SIZE	256
#define PCI_DEV_CFG_MASK	(PCI_DEV_CFG_SIZE - 1)

struct msix_cap {
	uint8_t	cap;
	uint8_t next;
	uint16_t ctrl;
	uint32_t table_offset;
	uint32_t pba_offset;
};

struct pci_device_header {
	/* Configuration space, as seen by the guest */
	struct {
		uint16_t	vendor_id;
		uint16_t	device_id;
		uint16_t	command;
		uint16_t	status;
		uint8_t		revision_id;
		uint8_t		class[3];
		uint8_t		cacheline_size;
		uint8_t		latency_timer;
		uint8_t		header_type;
		uint8_t		bist;
		uint32_t	bar[6];
		uint32_t	card_bus;
		uint16_t	subsys_vendor_id;
		uint16_t	subsys_id;
		uint32_t	exp_rom_bar;
		uint8_t		capabilities;
		uint8_t		reserved1[3];
		uint32_t	reserved2;
		uint8_t		irq_line;
		uint8_t		irq_pin;
		uint8_t		min_gnt;
		uint8_t		max_lat;
		struct msix_cap msix;
	} __attribute__((packed));
	/* Pad to PCI config space size */
	uint8_t	__pad[PCI_DEV_CFG_SIZE];
};

struct nic_pci_addr {
	uint16_t domain;                /**< Device domain */
	uint8_t bus;                    /**< Device bus */
	uint8_t devid;                  /**< Device ID */
	uint8_t function;               /**< Device function. */
};

#define PCI_PRI_ARGS(p) (p).domain, (p).bus, (p).devid, (p).function

struct nic_pci_id {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsystem_vendor_id;
	uint16_t subsystem_device_id;
};

/** Formatting string for PCI device identifier: Ex: 0000:00:01.0 */
#define PCI_PRI_FMT "%.4"PRIx16":%.2"PRIx8":%.2"PRIx8".%"PRIx8

#define PCI_SCAN_FMT "%04hx:%02hhx:%02hhx.%02hhx"

#endif /* __THUNDER_NIC_PCI__ */
