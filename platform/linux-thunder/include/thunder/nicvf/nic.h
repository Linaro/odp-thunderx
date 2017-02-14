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

#ifndef __THUNDER_NIC__
#define __THUNDER_NIC__

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/pci_regs.h>
#include <linux/vfio.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <sys/epoll.h>

#define VNIC_RSS_SUPPORT
#define DEBUG 0
//#define NIC_QUEUE_STATS
#define VNIC_MULTI_QSET_SUPPORT

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	__typeof__(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#define table_size(_array) (sizeof((_array))/sizeof((_array)[0]))

#ifdef __GNUC__
#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6))

/**
 * _Static_assert was only added in GCC 4.6. Provide a weak replacement
 * for previous versions.
 */
#define _Static_assert(e, s) extern int (*static_assert_checker (void)) \
	[sizeof (struct { unsigned int error_if_negative: (e) ? 1 : -1; })]

#endif
#endif

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/**
 * Compile time assertion-macro - fail compilation if cond is false.
 * @note This macro has zero runtime overhead
 */
#define STATIC_ASSERT(cond, msg)  _Static_assert(cond, msg)

#define check_powerof_2(_x) ({ \
	long x = (_x); \
	((x != 0) && !(x & (x - 1))); })

#define ctz(_x) ({ \
	unsigned int x = (_x); \
	__builtin_ctz(x); })

#define min(_x, _y) ({			\
	__typeof__(_x) _min1 = (_x);	\
	__typeof__(_y) _min2 = (_y);	\
	(void) (&_min1 == &_min2);	\
	_min1 < _min2 ? _min1 : _min2; })

#define max(_x, _y) ({			\
	__typeof__(_x) _max1 = (_x);	\
	__typeof__(_y) _max2 = (_y);	\
	(void) (&_max1 == &_max2);	\
	_max1 > _max2 ? _max1 : _max2; })

#define abs_diff(_x, _y) ({			\
	__typeof__(_x) _a = (_x);	\
	__typeof__(_y) _b = (_y);	\
	(void) (&_a == &_b);	\
	_a > _b ? _a - _b : _b - _a; })

#define wmb() ({			\
	__asm__ __volatile__ ("dmb st" : : : "memory"); })

#define prefetch_read_keep(_ptr) ({	\
	__asm volatile("prfm pldl1keep, %a0\n" : : "p" (_ptr)); })
//	 __builtin_prefetch (_ptr, 0, 3); })
//
#define prefetch_read_stream(_ptr) ({	\
	__asm volatile("prfm pldl1strm, %a0\n" : : "p" (_ptr)); })
//	 __builtin_prefetch (_ptr, 0, 0); })

#define prefetch_store_keep(_ptr) ({	\
	__asm volatile("prfm pstl1keep, %a0\n" : : "p" (_ptr)); })
//	 __builtin_prefetch (_ptr, 1, 3); })
#define prefetch_store_stream(_ptr) ({	\
	__asm volatile("prfm pstl1strm, %a0\n" : : "p" (_ptr)); })
//	 __builtin_prefetch (_ptr, 1, 0); })
#define prefetch_store_stream_l2(_ptr) ({	\
	__asm volatile("prfm pstl2strm, %a0\n" : : "p" (_ptr)); })
#define prefetch_zero(_ptr) ({	\
	__asm volatile("dc zva, %0\n" : : "r" (_ptr)); })

/** Pathname of PCI devices directory. */
#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"

#define ERR(fmt, args...) \
	fprintf(stderr, "%u ERR! " __FILE__ ":%d %s() " fmt, \
		(unsigned)pthread_self(), __LINE__, __func__, ##args)

#if defined(DEBUG) && (DEBUG >= 1)

#define DBG(fmt, args...) \
	fprintf(stderr, "%u DBG? " __FILE__ ":%d %s() " fmt, \
		(unsigned)pthread_self(), __LINE__, __func__, ##args)

#define DBGV(verbose, fmt, args...) \
	fprintf(stderr, "%u DBG%1u " __FILE__ ":%d %s() " fmt, \
		(unsigned)pthread_self(), (unsigned)verbose, \
		__LINE__, __func__, ##args)

#else
#define DBG(fmt, args...)
#define DBGV(fmt, args...)
#endif

#if (DEBUG >= 1)
#define DBGV1(fmt, args...) DBGV(1, fmt, ##args)
#else
#define DBGV1(fmt, args...)
#endif

#if (DEBUG >= 2)
#define DBGV2(fmt, args...) DBGV(2, fmt, ##args)
#else
#define DBGV2(fmt, args...)
#endif

#if (DEBUG >= 3)
#define DBGV3(fmt, args...) DBGV(3, fmt, ##args)
#else
#define DBGV3(fmt, args...)
#endif

#define NFO(fmt, args...) \
	printf("%u NFO " __FILE__ ":%d %s() " fmt, \
	       (unsigned)pthread_self(), __LINE__, __func__, ##args)

#define PERROR(fmt, args...) ERR(fmt ": %s\n", ##args, strerror(errno));

#define UNUSED(x) UNUSED_ ## x __attribute__((unused))

#define ALIGN(x,a)              __ALIGN_MASK((x),(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

#include "odp/helper/eth.h"
#include <odp/api/sync.h>

#include "log2.h"

#include "thunder/nicvf/nic_pci.h"
#include "thunder/nicvf/nic_queues.h"

enum nicvf_type {
	NICVF_TYPE_INVALID,
	NICVF_TYPE_VFIO,
	NICVF_TYPE_UIO,
};

enum nicvf_tns_mode {
	NIC_TNS_BYPASS_MODE = 0,
	NIC_TNS_MODE,
};

enum nicvf_cfg_flags {
	NICVF_CFGFLAG_CHCKSUM_IPV4 = 1,
	NICVF_CFGFLAG_CHCKSUM_UDP = 1 << 1,
	NICVF_CFGFLAG_CHCKSUM_TCP = 1 << 2,
	NICVF_CFGFLAG_NO_RECL_TX_BUFF = 1 << 3,

};

/* forward declaration */
struct nicvf;

struct nic_ops {
	/** Map user virtual address to IO virtual address, means the memory
	 * seen at uva will be seen by device at iova after successfull map */
	int (*nic_dma_map)(struct nicvf *nic, void *uva, size_t size, uint64_t *iova);
	int (*nic_dma_unmap)(struct nicvf *nic, void* uva, size_t size, uint64_t iova);
};

struct nicvf {
	struct queue_set qset[MAX_QSETS_PER_NIC];
	size_t qset_cnt;
	struct queue_desc qdesc;
#ifdef NIC_QUEUE_STATS
	/* epoh will be incremented by consumer thread to give a hint to
	 * producer thread that it should reset the stats and start cumulating
	 * again. Because accessed from multiple threads it is alligned to cache size */
	volatile uint64_t epoh_curr __attribute__((aligned(128)));
#endif

	enum nicvf_type nicvf_type:2;
	uint8_t rbptr_offset;
	uint8_t	tns_mode;
	uint8_t	cpi_alg;
	uint8_t node;
	enum nicvf_cfg_flags cfg_flags:8;
	uint16_t mtu;

	union {
		struct {
			struct uio_vnic_t {
				int dev_fd;   /** file descriptor for device */
				struct nic_pci_addr dev_addr;
				unsigned uio_num;
			} vnics[MAX_QSETS_PER_NIC];
			size_t vnic_cnt;
		} uio;
		struct {
			int cont_fd;  /** file descriptor */
			struct vfio_vnic_t {
				int group_fd; /** group descriptor, only one per container */
				int dev_fd;   /** file descriptor for device */
				unsigned vfio_grp;
				struct pci_device_header pci_header; /* PCI device config header */
				char dev_name[PATH_MAX];
			} vnics[MAX_QSETS_PER_NIC];
			size_t vnic_cnt;

		} vfio;
	};
	struct nic_ops *nicvf_ops;

	pthread_t thread_housekeeping;
	volatile bool housekeeping_work:1;
	volatile bool housekeeping_run:1;

	uint8_t mac_addr[ETH_ALEN];
	struct bgx_link_status link_status;
};

/* --- Taken from Cavium ThunderX NIC driver, file nic.h */

/* Software enumeration of NIC VF Interrupts
 * Thise definitions does not map into HW, it is only purly used in SW for switch/case */
enum {
	NICVF_INTR_ALL = -1,
	NICVF_INTR_CQ = 0,
	NICVF_INTR_SQ,
	NICVF_INTR_RBDR,
	NICVF_INTR_PKT_DROP,
	NICVF_INTR_TCP_TIMER,
	NICVF_INTR_MBOX,
	NICVF_INTR_QS_ERR,
};

#define	NICVF_INTR_CQ_SHIFT		0
#define	NICVF_INTR_SQ_SHIFT		8
#define	NICVF_INTR_RBDR_SHIFT		16
#define	NICVF_INTR_RAZ1_SHIFT		18 /* Reserved */
#define	NICVF_INTR_RAZ2_SHIFT		19 /* Reserved */
#define	NICVF_INTR_PKT_DROP_SHIFT	20
#define	NICVF_INTR_TCP_TIMER_SHIFT	21
#define	NICVF_INTR_MBOX_SHIFT		22
#define	NICVF_INTR_QS_ERR_SHIFT		23

#define	NICVF_INTR_CQ_MASK		(0xFF << NICVF_INTR_CQ_SHIFT)
#define	NICVF_INTR_SQ_MASK		(0xFF << NICVF_INTR_SQ_SHIFT)
#define	NICVF_INTR_RBDR_MASK		(0x03 << NICVF_INTR_RBDR_SHIFT)
#define	NICVF_INTR_PKT_DROP_MASK	(1 << NICVF_INTR_PKT_DROP_SHIFT)
#define	NICVF_INTR_TCP_TIMER_MASK	(1 << NICVF_INTR_TCP_TIMER_SHIFT)
#define	NICVF_INTR_MBOX_MASK		(1 << NICVF_INTR_MBOX_SHIFT)
#define	NICVF_INTR_QS_ERR_MASK		(1 << NICVF_INTR_QS_ERR_SHIFT)
#define NICVF_INTR_ALL_MASK		(0xFFFFFF)

/* MSI-X interrupts */
#define	NIC_PF_MSIX_VECTORS		10
#define	NIC_VF_MSIX_VECTORS		20

/* For CQ timer threshold interrupt */
#define NIC_NS_PER_100_SYETEM_CLK	125
#define NICPF_CLK_PER_INT_TICK		100

/* this function should be used for registers where each queue has its single bit */
static inline __attribute__((always_inline)) void nicvf_vf_reg_write(
	struct queue_set *qset, uint64_t offset, uint64_t val)
{
	uint64_t addr = (uint64_t)(qset->qset_reg_base) + offset;

	/* TODO endian swaping? */
	__asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

/* this function should be used for registers where each queue has its single bit */
static inline uint64_t __attribute__((always_inline)) nicvf_vf_reg_read(
	struct queue_set *qset, uint64_t offset)
{
	uint64_t val;
	uint64_t addr = (uint64_t)(qset->qset_reg_base) + offset;
	/* TODO endian swaping? */
	__asm volatile("ldr %0, [%1]" : "=r" (val) : "r" (addr));
	return val;
}

static inline uint16_t nicvf_dev_id(struct nicvf * nic)
{
	if (nic->nicvf_type == NICVF_TYPE_UIO)
		return nic->uio.vnics[0].dev_addr.devid;
	else if (nic->nicvf_type == NICVF_TYPE_VFIO)
		return nic->vfio.vnics[0].pci_header.device_id;
	else //should never happen
		return 0;
}

static inline unsigned nicvf_dev_num(struct nicvf * nic, size_t num)
{
	if (nic->nicvf_type == NICVF_TYPE_UIO)
		return nic->uio.vnics[num].uio_num;
	else if (nic->nicvf_type == NICVF_TYPE_VFIO)
		return nic->vfio.vnics[num].vfio_grp;
	else //should never happen
		return 0;
}
#endif

