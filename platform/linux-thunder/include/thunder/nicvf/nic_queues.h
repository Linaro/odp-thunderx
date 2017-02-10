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

#ifndef __THUNDERX_NIC_QUEUES__
#define __THUNDERX_NIC_QUEUES__

#include <pthread.h>

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_reg.h"
#include "thunder/nicvf/q_struct.h"

#include <odp_config_internal.h>

/* VF's queue interrupt ranges */
#define	NICVF_INTR_ID_CQ		0
#define	NICVF_INTR_ID_SQ		8
#define	NICVF_INTR_ID_RBDR		16
#define	NICVF_INTR_ID_MISC		18
#define	NICVF_INTR_ID_QS_ERR		19

// --- cut ---

#define RBDR_SIZE0		0ULL /* 8K entries */
#define RBDR_SIZE1		1ULL /* 16K entries */
#define RBDR_SIZE2		2ULL /* 32K entries */
#define RBDR_SIZE3		3ULL /* 64K entries */
#define RBDR_SIZE4		4ULL /* 126K entries */
#define RBDR_SIZE5		5ULL /* 256K entries */
#define RBDR_SIZE6		6ULL /* 512K entries */

#define SND_QUEUE_SIZE0		0ULL /* 1K entries */
#define SND_QUEUE_SIZE1		1ULL /* 2K entries */
#define SND_QUEUE_SIZE2		2ULL /* 4K entries */
#define SND_QUEUE_SIZE3		3ULL /* 8K entries */
#define SND_QUEUE_SIZE4		4ULL /* 16K entries */
#define SND_QUEUE_SIZE5		5ULL /* 32K entries */
#define SND_QUEUE_SIZE6		6ULL /* 64K entries */

#define CMP_QUEUE_SIZE0		0ULL /* 1K entries */
#define CMP_QUEUE_SIZE1		1ULL /* 2K entries */
#define CMP_QUEUE_SIZE2		2ULL /* 4K entries */
#define CMP_QUEUE_SIZE3		3ULL /* 8K entries */
#define CMP_QUEUE_SIZE4		4ULL /* 16K entries */
#define CMP_QUEUE_SIZE5		5ULL /* 32K entries */
#define CMP_QUEUE_SIZE6		6ULL /* 64K entries */

#define MAX_QSETS_PER_NIC		6
#define MAX_QUEUES_PER_QSET		8
#define MAX_QUEUES_PER_NIC		(MAX_QSETS_PER_NIC * MAX_QUEUES_PER_QSET)
#define MAX_RBDR_PER_QSET		2
#define MAX_RBDR_PER_NIC		(MAX_RBDR_PER_QSET * MAX_QSETS_PER_NIC)

/* SIZE2 4k seems to limit xmit from ~18 to ~19 MPPS, depending on SQ_HANDLE_CYCLEGUARD
 * SIZE3 8k does not limit xmit, curr CPU limit it to 33 MPPS (HW has bug limit at 34Mpps) */
#define SND_QSIZE		SND_QUEUE_SIZE3
#define SND_QSIZE_SHIFT		10 /* 1k */
#define SND_QUEUE_LEN		(1ULL << (SND_QSIZE + SND_QSIZE_SHIFT))
#define MIN_SQ_DESC_PER_PKT_XMIT	2

#define CMP_QSIZE		CMP_QUEUE_SIZE0
#define CMP_QSIZE_SHIFT		10 /* 1k */
#define CMP_QUEUE_LEN		(1ULL << (CMP_QSIZE + CMP_QSIZE_SHIFT))

/* SIZE1 16k entries seems to work well, bigger sized seems not increase throughput in l2fw test */
#define RBDR_SIZE		RBDR_SIZE1
#define RBDR_SIZE_SHIFT		13 /* 8k */
#define RCV_BUF_COUNT		(1ULL << (RBDR_SIZE + RBDR_SIZE_SHIFT))
/* TODO: determine safe DROP level */
#define RQ_CQ_DROP		0
//#define RQ_CQ_DROP		((CMP_QUEUE_LEN - SND_QUEUE_LEN) / 256)

/* Buffer / descriptor alignedments */
#define NICVF_RCV_BUF_ALIGN		7
#define NICVF_RCV_BUF_ALIGN_BYTES	(1ULL << NICVF_RCV_BUF_ALIGN)
#define NICVF_CQ_BASE_ALIGN_BYTES	512  /* 9 bits */
#define NICVF_SQ_BASE_ALIGN_BYTES	128  /* 7 bits */

#define NICVF_ALIGNED_ADDR(ADDR, ALIGN_BYTES)	ALIGN(ADDR, ALIGN_BYTES)
#define NICVF_ADDR_ALIGN_LEN(ADDR, BYTES)\
	(NICVF_ALIGNED_ADDR(ADDR, BYTES) - BYTES)
#define NICVF_RCV_BUF_ALIGN_LEN(X)\
	(NICVF_ALIGNED_ADDR(X, NICVF_RCV_BUF_ALIGN_BYTES) - X)

/* Queue enable/disable */
#define NICVF_SQ_EN            (1ULL << 19)

/* Queue reset */
#define NICVF_CQ_RESET		(1ULL << 41)
#define NICVF_SQ_RESET		(1ULL << 17)
#define NICVF_RBDR_RESET	(1ULL << 43)

#define	CQ_WR_FULL	(1ULL << 26)
#define	CQ_WR_DISABLE	(1ULL << 25)
#define	CQ_WR_FAULT	(1ULL << 24)
#define	CQ_CQE_COUNT_MASK ((unsigned long long)0xFFFF << 0)
#define	CQ_ERR_MASK	(CQ_WR_FULL | CQ_WR_DISABLE | CQ_WR_FAULT)

#define SQ_ERR_STOPPED (1ULL << 21)
#define SQ_ERR_SEND    (1ULL << 20)
#define SQ_ERR_DPE     (1ULL << 19)
#define SQ_ERR_MASK    (SQ_ERR_STOPPED | SQ_ERR_SEND | SQ_ERR_DPE)

#define RBDR_FIFO_STATE_SHIFT 62
#define RBDR_FIFO_STATE_MASK (3ULL << RBDR_FIFO_STATE_SHIFT)
#define RBDR_RBDRE_COUNT_MASK  ((uint64_t)0x7FFFF)

/* low mark for SQ handling, spill buffers into local per thread cache */
#define SQ_HANDLE_THRESHOLD 256
/* do not handle SQ more often than given number of CPU timer cycles */
#define SQ_HANDLE_CYCLEGUARD 512
#define RQ_HANDLE_THRESHOLD 256

_Static_assert(SQ_HANDLE_THRESHOLD < SND_QUEUE_LEN / 2,
		   "PKTIO_SQ_THRESHOLD cannot be greater than half of SQ length");
_Static_assert(RQ_HANDLE_THRESHOLD < RCV_BUF_COUNT / 2,
		   "PKTIO_RBDR_THRESHOLD cannot be greater than half of RBDR queue length");

enum rdbr_state {
	RBDR_FIFO_STATE_INACTIVE = 0,
	RBDR_FIFO_STATE_ACTIVE   = 1,
	RBDR_FIFO_STATE_RESET    = 2,
	RBDR_FIFO_STATE_FAIL     = 3
};

enum rq_cache_allocation {
	RQ_CACHE_ALLOC_OFF	= 0,
	RQ_CACHE_ALLOC_ALL	= 1,
	RQ_CACHE_ALLOC_FIRST	= 2,
	RQ_CACHE_ALLOC_TWO	= 3,
};

enum CQ_RX_ERRLVL_E {
	CQ_ERRLVL_MAC,
	CQ_ERRLVL_L2,
	CQ_ERRLVL_L3,
	CQ_ERRLVL_L4,
};

enum CQ_RX_ERROP_E {
	CQ_RX_ERROP_RE_NONE = 0x0,
	CQ_RX_ERROP_RE_PARTIAL = 0x1,
	CQ_RX_ERROP_RE_JABBER = 0x2,
	CQ_RX_ERROP_RE_FCS = 0x7,
	CQ_RX_ERROP_RE_TERMINATE = 0x9,
	CQ_RX_ERROP_RE_RX_CTL = 0xb,
	CQ_RX_ERROP_PREL2_ERR = 0x1f,
	CQ_RX_ERROP_L2_FRAGMENT = 0x20,
	CQ_RX_ERROP_L2_OVERRUN = 0x21,
	CQ_RX_ERROP_L2_PFCS = 0x22,
	CQ_RX_ERROP_L2_PUNY = 0x23,
	CQ_RX_ERROP_L2_MAL = 0x24,
	CQ_RX_ERROP_L2_OVERSIZE = 0x25,
	CQ_RX_ERROP_L2_UNDERSIZE = 0x26,
	CQ_RX_ERROP_L2_LENMISM = 0x27,
	CQ_RX_ERROP_L2_PCLP = 0x28,
	CQ_RX_ERROP_IP_NOT = 0x41,
	CQ_RX_ERROP_IP_CSUM_ERR = 0x42,
	CQ_RX_ERROP_IP_MAL = 0x43,
	CQ_RX_ERROP_IP_MALD = 0x44,
	CQ_RX_ERROP_IP_HOP = 0x45,
	CQ_RX_ERROP_L3_ICRC = 0x46,
	CQ_RX_ERROP_L3_PCLP = 0x47,
	CQ_RX_ERROP_L4_MAL = 0x61,
	CQ_RX_ERROP_L4_CHK = 0x62,
	CQ_RX_ERROP_UDP_LEN = 0x63,
	CQ_RX_ERROP_L4_PORT = 0x64,
	CQ_RX_ERROP_TCP_FLAG = 0x65,
	CQ_RX_ERROP_TCP_OFFSET = 0x66,
	CQ_RX_ERROP_L4_PCLP = 0x67,
	CQ_RX_ERROP_RBDR_TRUNC = 0x70,
};

enum CQ_TX_ERROP_E {
	CQ_TX_ERROP_GOOD = 0x0,
	CQ_TX_ERROP_DESC_FAULT = 0x10,
	CQ_TX_ERROP_HDR_CONS_ERR = 0x11,
	CQ_TX_ERROP_SUBDC_ERR = 0x12,
	CQ_TX_ERROP_IMM_SIZE_OFLOW = 0x80,
	CQ_TX_ERROP_DATA_SEQUENCE_ERR = 0x81,
	CQ_TX_ERROP_MEM_SEQUENCE_ERR = 0x82,
	CQ_TX_ERROP_LOCK_VIOL = 0x83,
	CQ_TX_ERROP_DATA_FAULT = 0x84,
	CQ_TX_ERROP_TSTMP_CONFLICT = 0x85,
	CQ_TX_ERROP_TSTMP_TIMEOUT = 0x86,
	CQ_TX_ERROP_MEM_FAULT = 0x87,
	CQ_TX_ERROP_CK_OVERLAP = 0x88,
	CQ_TX_ERROP_CK_OFLOW = 0x89,
	CQ_TX_ERROP_ENUM_LAST = 0x8a,
};

enum rx_stats_reg_offset {
	RX_OCTS = 0x0,
	RX_UCAST = 0x1,
	RX_BCAST = 0x2,
	RX_MCAST = 0x3,
	RX_RED = 0x4,
	RX_RED_OCTS = 0x5,
	RX_ORUN = 0x6,
	RX_ORUN_OCTS = 0x7,
	RX_FCS = 0x8,
	RX_L2ERR = 0x9,
	RX_DRP_BCAST = 0xa,
	RX_DRP_MCAST = 0xb,
	RX_DRP_L3BCAST = 0xc,
	RX_DRP_L3MCAST = 0xd,
	RX_STATS_ENUM_LAST,
};

enum tx_stats_reg_offset {
	TX_OCTS = 0x0,
	TX_UCAST = 0x1,
	TX_BCAST = 0x2,
	TX_MCAST = 0x3,
	TX_DROP = 0x4,
	TX_STATS_ENUM_LAST,
};

enum rq_sq_stats_reg_offset {
        RQ_SQ_STATS_OCTS = 0x0,
        RQ_SQ_STATS_PKTS = 0x1,
};

/* forward declaration */
struct nicvf;

struct mem_desc {
	size_t		size; /* requested size */
	void		*virt;
	uint64_t	phys;
};

/* Structure for multi thread lockfree ring
 * Two of such structures are needed for multi prodicer multi consumer
 * implementation. Both head and tail indexes are monotonic and need to be
 * accessed with atomic operations */
struct lockfree_ring {
	size_t head;
	size_t tail;
};

/* For some use cases we need to synchronize storage in two different lockfree
 * rings. Such situation takes place in case of VNIC descriptors and memory
 * buffers used for packets. We need to store/retrive two types of pointers from
 * two different rings at the same time, but the indexes of those rings are not
 * synchronized. This is due amount of pointers stored/retrived at each access
 * are different. For those use cases following scattered index union is used,
 * where two 32bit indexes are stored with one 64bit atomic operation */
union scatt_idx {
	struct {
		uint32_t desc;
		uint32_t memseg;
	};
	uint64_t val;
};

/* Structure for multi thread lockfree scattered ring.
 * Please look at description of union scatt_idx for scattered ring.
 * Two of such structures are needed for multi prodicer multi consumer
 * implementation. Both head and tail indexes are monotonic and need to be
 * accessed with atomic operations */
struct lockfree_scatt_ring {
	union scatt_idx head;
	union scatt_idx tail;
};

struct rbdr_stats_t {
	uint64_t epoh_last;
	uint64_t prech_sum;
	uint64_t prech_cnt;
	uint64_t lbuf_max;
	uint64_t lbuf_min;
	uint64_t lbuf_sum;
	uint64_t free_max;
	uint64_t free_min;
	uint64_t free_sum;
	uint64_t probes_cnt;
} __attribute__((aligned(128)));

struct rbdr {
	struct mem_desc mem_desc;
	struct rbdr_entry_t *desc;
	uint32_t	desc_cnt;
	uint32_t	buf_size;
	uint32_t	thresh;		/* Threshold level for interrupt */
	uint32_t	head;		/* Multiproducer head - not connected to HW RBDR head */
	uint32_t	tail;		/* Multiproducer tail - not connected to HW RBDR tail */
	bool		enable;

	struct rbdr_stats_t stats[ODP_THREAD_COUNT_MAX];

} __attribute__((aligned(128)));

struct rcv_queue {
	struct	rbdr	*rbdr_start;
	struct	rbdr	*rbdr_cont;
	uint8_t		cq_qs;  /* CQ's QS to which this RQ is assigned */
	uint8_t		cq_idx; /* CQ index (0 to 7) in the QS */
	uint8_t		cont_rbdr_qs;      /* Continue buffer ptrs - QS num */
	uint8_t		cont_qs_rbdr_idx;  /* RBDR idx in the cont QS */
	uint8_t		start_rbdr_qs;     /* First buffer ptrs - QS num */
	uint8_t		start_qs_rbdr_idx; /* RBDR idx in the above QS */
	uint8_t		caching; /* Cache lines loaded to L2C */
	bool		en_tcp_reassembly;
	bool		enable;
//	struct rcv_queue_stats stats;
} __attribute__((aligned(128)));

struct cq_stats_t {
	 uint64_t epoh_last;
	 uint64_t cq_count_max;
	 uint64_t cq_count_min;
	 uint64_t cq_count_sum;
	 uint64_t probes_cnt;
	 uint64_t cq_handler_calls;
} __attribute__((aligned(128)));

struct cmp_queue {
	struct mem_desc mem_desc;
	union cq_entry_t  *desc; /* copy of cq->mem_desc.base, pointer to CQE's table */
	uint32_t	prod_tail;        /* SW shadow for HW CQ_TAIL */
	struct lockfree_scatt_ring cons;  /* lockfree consumer ring indexes */
	uint32_t	rbdr_refill_mark; /* monotonix index of last rbdr refill
					     updated from cons.tail.membuf */
	uint32_t	desc_cnt;
	bool		enable:1;

	struct cq_stats_t stats[ODP_THREAD_COUNT_MAX];

} __attribute__((aligned(128)));

struct sq_stats_t {
	 uint64_t epoh_last;
	 uint64_t xmit_pkts_sum;
	 uint64_t sq_recl_max;
	 uint64_t sq_recl_min;
	 uint64_t sq_recl_sum;
	 uint64_t sq_count_max;
	 uint64_t sq_count_min;
	 uint64_t sq_count_sum;
	 uint64_t probes_cnt;
	 uint64_t sq_handler_calls;
	 uint64_t xmit_calls;
} __attribute__((aligned(128)));

/* just forward declaration */
struct packet_hdr_t;

struct snd_queue {
	union sq_entry_t *desc;
	struct mem_desc mem_desc;
	struct lockfree_scatt_ring prod;
	struct lockfree_scatt_ring cons;
	struct odp_buffer_hdr_t **bufs_used; /**< pointers to buffers used in sq */
	uint64_t	recycle_time;
	uint16_t	desc_cnt;
	uint16_t	thresh;

	uint8_t		cq_qs;  /* CQ's QS to which this SQ is pointing */
	uint8_t		cq_idx; /* CQ index (0 to 7) in the above QS */
	bool		enable:1;
	bool		pool_poluted:1; /**< Mark that buffers used for TX was not from the same pool as assigned to NIC */

	struct sq_stats_t stats[ODP_THREAD_COUNT_MAX];

} __attribute__((aligned(128)));

struct sw_stats_t {
	struct sq_stats_t sq[MAX_QUEUES_PER_NIC];
	struct cq_stats_t cq[MAX_QUEUES_PER_NIC];
	struct rbdr_stats_t rbdr[MAX_RBDR_PER_NIC];
};

struct hw_stats_t {
	uint64_t rx_bytes_ok;
	uint64_t rx_ucast_frames_ok;
	uint64_t rx_bcast_frames_ok;
	uint64_t rx_mcast_frames_ok;
	uint64_t rx_fcs_errors;
	uint64_t rx_l2_errors;
	uint64_t rx_drop_red;
	uint64_t rx_drop_red_bytes;
	uint64_t rx_drop_overrun;
	uint64_t rx_drop_overrun_bytes;
	uint64_t rx_drop_bcast;
	uint64_t rx_drop_mcast;
	uint64_t rx_drop_l3_bcast;
	uint64_t rx_drop_l3_mcast;
	uint64_t tx_bytes_ok;
	uint64_t tx_ucast_frames_ok;
	uint64_t tx_bcast_frames_ok;
	uint64_t tx_mcast_frames_ok;
	uint64_t tx_drops;
	struct rq_hw_stats_t {
		uint64_t bytes;
		uint64_t pkts;
	} rq_hw_stats[MAX_QUEUES_PER_QSET];
	struct sq_hw_stats_t {
		uint64_t bytes;
		uint64_t pkts;
	} sq_hw_stats[MAX_QUEUES_PER_QSET];
};

#define NIC_MAX_RSS_HASH_BITS		8
#define NIC_MAX_RSS_IDR_TBL_SIZE	(1 << NIC_MAX_RSS_HASH_BITS)
#define RSS_HASH_KEY_SIZE		5 /* 320 bit key */

#ifdef VNIC_RSS_SUPPORT
struct nicvf_rss_info {
	bool enable;
#define	RSS_L2_EXTENDED_HASH_ENA	(1 << 0)
#define	RSS_IP_HASH_ENA			(1 << 1)
#define	RSS_TCP_HASH_ENA		(1 << 2)
#define	RSS_TCP_SYN_DIS			(1 << 3)
#define	RSS_UDP_HASH_ENA		(1 << 4)
#define RSS_L4_EXTENDED_HASH_ENA	(1 << 5)
#define	RSS_ROCE_ENA			(1 << 6)
#define	RSS_L3_BI_DIRECTION_ENA		(1 << 7)
#define	RSS_L4_BI_DIRECTION_ENA		(1 << 8)
	uint64_t cfg;
	uint8_t  hash_bits;
	uint16_t rss_size;
	uint8_t  ind_tbl[NIC_MAX_RSS_IDR_TBL_SIZE];
	uint64_t key[RSS_HASH_KEY_SIZE];
};
#endif

typedef uint64_t bitmap_t;
STATIC_ASSERT((sizeof(bitmap_t) * 8) > MAX_QUEUES_PER_NIC, "Bitmap size is to small for defined nbr of queues per VF");

static inline bitmap_t bitmap_shift(bitmap_t bitmap, uint8_t shift)
{
	return bitmap << shift;
}

static inline odp_bool_t bitmap_test_bit(bitmap_t bitmap, uint8_t shift)
{
	return !!(bitmap & bitmap_shift(1, shift));
}

struct queue_desc {
	pthread_spinlock_t	spin; /* lock to serialize allocation of queues */
	bitmap_t		txq_bitmap; /**< bitmap for queue allocation, each bit represent queue allocation status */
	bitmap_t		rxq_bitmap; /**< bitmap for queue allocation, each bit represent queue allocation status */
	struct	rcv_queue	rq[MAX_QUEUES_PER_NIC];
	struct	cmp_queue	cq[MAX_QUEUES_PER_NIC];
	struct	snd_queue	sq[MAX_QUEUES_PER_NIC];
	struct	rbdr		rbdr[MAX_RBDR_PER_NIC];
};

struct queue_set; /* forward declaration */
#include "thunder/nicvf/nic_mbox.h"

struct queue_set {
	void			*qset_reg_base; /* Register start address for QSet */
	struct nicvf		*nic; /* backpointer */
	uint8_t			qset_idx; /* just for reference which qset this is */
	uint8_t			vf_id;
#ifdef VNIC_RSS_SUPPORT
	struct nicvf_rss_info	rss_info;
#endif
#ifdef NIC_QUEUE_STATS
	struct hw_stats_t last_hw_stats;
#endif

	bool enable:1;
	bool housekeeping:1;
	bool be_en:1;

	union nic_mbx mbx_msg; /** placeholder for recv msg, used betwen worker thread and housekeeping thread */
	pthread_cond_t mbx_cond; /* cond used to signalize worker thread that msg was received */
	pthread_mutex_t mbx_mutex; /* mtx used for concurent access to mbx hw and mbx_msg placeholder */
};

int nicvf_qset_rxq_enable(struct nicvf *nic);
int nicvf_qset_txq_enable(struct nicvf *nic);
int nicvf_qset_rxq_disable(struct nicvf *nic, size_t qidx);
int nicvf_qset_txq_disable(struct nicvf *nic, size_t qidx);
int nicvf_qset_triplet_disableall(struct queue_set *qset);
int nicvf_qset_rxqtxq_disableall(struct nicvf *nic);
void nicvf_qset_preinit(struct queue_set *qset);
int nicvf_qset_init(struct queue_set *qset);
int nicvf_qset_close(struct queue_set *qset);
void nicvf_intr_handler_qserr(struct queue_set *qset);

size_t nicvf_xmit(
	struct nicvf *nic, size_t qidx,
	struct packet_hdr_t * const *pkt, size_t pkt_cnt);
size_t nicvf_recv(
	struct nicvf *nic, size_t qidx, struct packet_hdr_t *pkt_table[],
	size_t budget, uint64_t *order);
size_t nicvf_qset_cq_handler(
	struct nicvf *nic, size_t qidx,
	struct packet_hdr_t* pkt_table[], uint32_t budget,
	union scatt_idx *last_idx);
size_t nicvf_qset_rbdr_handler(struct nicvf *nic, size_t rbdr_idx, size_t qidx, uint64_t free_cnt);
void nicvf_print_queue_stats(struct nicvf *nic);
void nicvf_stathw_get(struct queue_set *qset, struct hw_stats_t * __restrict__ stats);

#endif
