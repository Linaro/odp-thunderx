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

/* enable usleep */
#include <asm-generic/errno-base.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "thunder/nicvf/q_struct.h"
#include "thunder/nicvf/nic_reg.h"
#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_vfmain.h"
#include "thunder/nicvf/nic_mbox.h"
#include "thunder/nicvf/nic_queues.h"
#include "thunder/nicvf/nic_common.h"

#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/system_info.h>
#include <odp/api/shared_memory.h>
#include <odp/api/errno.h>
#include <odp/api/pool.h>
#include <odp/api/packet_flags.h>

#include <odp_debug_internal.h>
//#include <odp_cpu_internal.h>
#include <odp_shm_internal.h>
#include <odp_pool_internal.h>
#include <odp_packet_internal.h>
#include <thunder/odp_pktio_nicvf.h>

#ifndef DISABLE_NIC_FASTPATH_OPTIMIZATIONS

#ifndef OPTIMIZATION_RECV
#define OPTIMIZATION_RECV __attribute__((hot, optimize("O2", "inline-functions")))
#endif

#ifndef OPTIMIZATION_XMIT
#define OPTIMIZATION_XMIT __attribute__((hot, optimize("O2", "inline-functions")))
#endif

#else

#define OPTIMIZATION_RECV
#define OPTIMIZATION_XMIT

#endif

#define nicvf_reg_dump(_qset, _reg) printf(#_reg " = %"PRIx64"\n", nicvf_vf_reg_read(_qset, _reg))
#define nicvf_qreg_dump(_nic, _qidx, _reg) printf(#_reg "[%zu] = %"PRIx64"\n", _qidx, nicvf_qidx_reg_read(_nic, _qidx, _reg))
#define nicvf_rbdr_dump(_nic, _rbdr, _reg) printf(#_reg "[%zu] = %"PRIx64"\n", _rbdr, nicvf_rbdr_reg_read(_nic, _rbdr, _reg))

#define GET_RX_STATS(_qset, _reg) \
	nicvf_vf_reg_read(_qset, NIC_VNIC_RX_STAT_0_13 | ((_reg) << 3))
#define GET_TX_STATS(_qset, _reg) \
	nicvf_vf_reg_read(_qset, NIC_VNIC_TX_STAT_0_4 | ((_reg) << 3))
#define GET_RQ_STATS(_nic, _qidx, _reg) \
	nicvf_qidx_reg_read(_nic, (_qidx), NIC_QSET_RQ_0_7_STAT_0_1 | ((_reg) << 3))
#define GET_SQ_STATS(_nic, _qidx, _reg) \
	nicvf_qidx_reg_read(_nic, (_qidx), NIC_QSET_SQ_0_7_STAT_0_1 | ((_reg) << 3))

void nicvf_dump_regs(struct nicvf *nic);

/* this function should be used for registers where each queue has its single bit */
static inline __attribute__((always_inline)) void nicvf_qidx_reg_write(
	struct nicvf *nic, size_t qidx, uint64_t offset, uint64_t val)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	size_t qirem = qidx % MAX_QUEUES_PER_QSET;
	uint64_t addr = (uint64_t)(qset->qset_reg_base) +
			offset + (qirem << NIC_Q_NUM_SHIFT);
	/* TODO endian swaping? */
	__asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

static inline uint64_t __attribute__((always_inline)) nicvf_qidx_reg_read(
	struct nicvf *nic, size_t qidx, uint64_t offset)
{
	uint64_t val;
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	size_t qirem = qidx % MAX_QUEUES_PER_QSET;
	uint64_t addr = (uint64_t)(qset->qset_reg_base) +
			offset + (qirem << NIC_Q_NUM_SHIFT);
	/* TODO endian swaping? */
	__asm volatile("ldr %0, [%1]" : "=r" (val) : "r" (addr));
	return val;
}

static inline __attribute__((always_inline)) void nicvf_rbdr_reg_write(
	struct nicvf *nic, size_t rbdr_idx, uint64_t offset, uint64_t val)
{
	struct queue_set *qset = &nic->qset[rbdr_idx / MAX_RBDR_PER_QSET];
	size_t rbdr_irem = rbdr_idx % MAX_RBDR_PER_QSET;
	uint64_t addr = (uint64_t)(qset->qset_reg_base) +
			offset + (rbdr_irem << NIC_Q_NUM_SHIFT);
	/* TODO endian swaping? */
	__asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

static inline uint64_t __attribute__((always_inline)) nicvf_rbdr_reg_read(
	struct nicvf *nic, size_t rbdr_idx, uint64_t offset)
{
	uint64_t val;
	struct queue_set *qset = &nic->qset[rbdr_idx / MAX_RBDR_PER_QSET];
	size_t rbdr_irem = rbdr_idx % MAX_RBDR_PER_QSET;
	uint64_t addr = (uint64_t)(qset->qset_reg_base) +
			offset + (rbdr_irem << NIC_Q_NUM_SHIFT);
	/* TODO endian swaping? */
	__asm volatile("ldr %0, [%1]" : "=r" (val) : "r" (addr));
	return val;
}

__attribute__ ((pure))
static inline struct pool_entry_s *nicvf_get_pool(struct nicvf *nic)
{
	pkt_nicvf_t *pkt_nicvf =
		container_of(nic, pkt_nicvf_t, nicvf);
	return pkt_nicvf->pool;
}

__attribute__ ((pure))
static inline size_t nicvf_buffer_from_ptr_offset(struct pool_entry_s *pool)
{
	return pool->hdr_size + pool->pkt_alloc.headroom;
}

static inline void nicvf_buffer_to_ptr_n(
	struct pool_entry_s *pool, size_t n, struct odp_buffer_hdr_t** buf)
{
	size_t i;
	size_t offset = nicvf_buffer_from_ptr_offset(pool);

	for (i = 0; i < n; i++) {
		buf[i] = (struct odp_buffer_hdr_t*)(((uint8_t **)buf)[i] + offset);
	}
}

__attribute__ ((pure))
static inline struct odp_buffer_hdr_t* nicvf_buffer_from_ptr(
	void* virt, size_t offset)
{
	return (struct odp_buffer_hdr_t *) ((uint8_t *)virt - offset);
}

__attribute__ ((pure))
static inline bool nicvf_rxq_active(struct nicvf *nic, size_t qidx)
{
	return bitmap_test_bit(nic->qdesc.rxq_bitmap, qidx);
}

__attribute__ ((pure))
static inline bool nicvf_txq_active(struct nicvf *nic, size_t qidx)
{
	return bitmap_test_bit(nic->qdesc.txq_bitmap, qidx);
}

static inline void nicvf_rxq_switch(struct nicvf *nic, size_t qidx, bool enable)
{
	if (enable) {
		nic->qdesc.rxq_bitmap |= bitmap_shift(1, qidx);
	} else {
		nic->qdesc.rxq_bitmap &= (~(bitmap_shift(1, qidx)));
	}
}

static inline void nicvf_txq_switch(struct nicvf *nic, size_t qidx, bool enable)
{
	if (enable) {
		nic->qdesc.txq_bitmap |= bitmap_shift(1, qidx);
	} else {
		nic->qdesc.txq_bitmap &= (~(bitmap_shift(1, qidx)));
	}
}

__attribute__ ((pure))
static inline bool nicvf_qset_active(struct queue_set *qset)
{
	return !!(qset->enable);
}

/* Warning this function may get into infinite loop if bitmap is empty */
__attribute__ ((pure))
static inline size_t nicvf_queue_next(bitmap_t bitmap, size_t qidx)
{
	do {
		qidx = (qidx + 1) % MAX_QUEUES_PER_QSET;
	} while (bitmap & (1 << qidx));

	return qidx;
}

void nicvf_dump_regs(struct nicvf *nic)
{
	struct queue_set *qset;
	size_t qset_idx;
	size_t qidx;
	size_t mbox;

	for (qset_idx = 0; qset_idx < nic->qset_cnt; qset_idx++) {

		qset = &nic->qset[qset_idx];
		printf("Dump of QSET %zu\n", qset_idx);

		nicvf_reg_dump(qset, NIC_VNIC_CFG);
		/* Mailbox registers */
		for (mbox = 0; mbox < NIC_PF_VF_MAILBOX_SIZE; mbox++)
			nicvf_reg_dump(qset, NIC_VF_PF_MAILBOX_0_1 | (mbox << 3));

		nicvf_reg_dump(qset, NIC_VF_INT);
		nicvf_reg_dump(qset, NIC_VF_INT_W1S);
		nicvf_reg_dump(qset, NIC_VF_ENA_W1C);
		nicvf_reg_dump(qset, NIC_VF_ENA_W1S);
		nicvf_reg_dump(qset, NIC_VNIC_RSS_CFG);
		nicvf_reg_dump(qset, NIC_QSET_RQ_GEN_CFG);

		for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
		     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
		     qidx++) {

			printf("Dump of QUEUE_SET registers%zu\n", qidx);

			/* All completion queue's registers */
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_CFG);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_CFG2);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_THRESH);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_BASE);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_HEAD);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_TAIL);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_DOOR);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_STATUS);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_STATUS2);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_CQ_0_7_DEBUG);

			/* All receive queue's registers */
			nicvf_qreg_dump(nic, qidx, NIC_QSET_RQ_0_7_CFG);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_RQ_0_7_STAT_0_1);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_RQ_0_7_STAT_0_1 | (1 << 3));

			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_CFG);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_THRESH);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_BASE);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_HEAD);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_TAIL);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_DOOR);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_STATUS);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_DEBUG);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_STAT_0_1);
			nicvf_qreg_dump(nic, qidx, NIC_QSET_SQ_0_7_STAT_0_1 | (1 << 3));
		}

		for (qidx = qset_idx * MAX_RBDR_PER_QSET;
		     qidx < (qset_idx + 1) * MAX_RBDR_PER_QSET;
		     qidx++) {

			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_CFG);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_THRESH);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_BASE);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_HEAD);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_TAIL);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_DOOR);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_STATUS0);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_STATUS1);
			nicvf_rbdr_dump(nic, qidx, NIC_QSET_RBDR_0_1_PREFETCH_STATUS);
			printf("-------------------------------------\n");
		}

		printf("=========================================\n");
	}
}

void nicvf_stathw_get(
	struct queue_set *qset, struct hw_stats_t * __restrict__ stats)
{
	struct nicvf *nic = qset->nic;
	size_t qset_idx = qset->qset_idx;
	size_t qirem, qbase_idx;

	stats->rx_bytes_ok = GET_RX_STATS(qset, RX_OCTS);
	stats->rx_ucast_frames_ok = GET_RX_STATS(qset, RX_UCAST);
	stats->rx_bcast_frames_ok = GET_RX_STATS(qset, RX_BCAST);
	stats->rx_mcast_frames_ok = GET_RX_STATS(qset, RX_MCAST);
	stats->rx_fcs_errors = GET_RX_STATS(qset, RX_FCS);
	stats->rx_l2_errors = GET_RX_STATS(qset, RX_L2ERR);
	stats->rx_drop_red = GET_RX_STATS(qset, RX_RED);
	stats->rx_drop_overrun = GET_RX_STATS(qset, RX_ORUN);
	stats->rx_drop_bcast = GET_RX_STATS(qset, RX_DRP_BCAST);
	stats->rx_drop_mcast = GET_RX_STATS(qset, RX_DRP_MCAST);
	stats->rx_drop_l3_bcast = GET_RX_STATS(qset, RX_DRP_L3BCAST);
	stats->rx_drop_l3_mcast = GET_RX_STATS(qset, RX_DRP_L3MCAST);

	stats->tx_bytes_ok = GET_TX_STATS(qset, TX_OCTS);
	stats->tx_ucast_frames_ok = GET_TX_STATS(qset, TX_UCAST);
	stats->tx_bcast_frames_ok = GET_TX_STATS(qset, TX_BCAST);
	stats->tx_mcast_frames_ok = GET_TX_STATS(qset, TX_MCAST);
	stats->tx_drops = GET_TX_STATS(qset, TX_DROP);

	/* Update RQ and SQ stats */
	qbase_idx = qset_idx * MAX_QUEUES_PER_QSET;
	for (qirem = 0; qirem < MAX_QUEUES_PER_QSET; qirem++) {

		struct rq_hw_stats_t * __restrict__ rq_stats =
			&stats->rq_hw_stats[qirem];
		struct sq_hw_stats_t * __restrict__ sq_stats =
			&stats->sq_hw_stats[qirem];

		rq_stats->bytes = GET_RQ_STATS(nic, qbase_idx + qirem, RQ_SQ_STATS_OCTS);
		rq_stats->pkts = GET_RQ_STATS(nic, qbase_idx + qirem, RQ_SQ_STATS_PKTS);
		sq_stats->bytes = GET_SQ_STATS(nic, qbase_idx + qirem, RQ_SQ_STATS_OCTS);
		sq_stats->pkts = GET_SQ_STATS(nic, qbase_idx + qirem, RQ_SQ_STATS_PKTS);
	}
}

#ifdef NIC_QUEUE_STATS
static void nicvf_stathw_diff(struct hw_stats_t * __restrict__ old_stats,
			      struct hw_stats_t * __restrict__ new_stats)
{
	size_t qirem;

	old_stats->rx_bytes_ok =		new_stats->rx_bytes_ok		- old_stats->rx_bytes_ok;
	old_stats->rx_ucast_frames_ok =		new_stats->rx_ucast_frames_ok	- old_stats->rx_ucast_frames_ok;
	old_stats->rx_bcast_frames_ok =		new_stats->rx_bcast_frames_ok	- old_stats->rx_bcast_frames_ok;
	old_stats->rx_mcast_frames_ok =		new_stats->rx_mcast_frames_ok	- old_stats->rx_mcast_frames_ok;
	old_stats->rx_fcs_errors =		new_stats->rx_fcs_errors	- old_stats->rx_fcs_errors;
	old_stats->rx_l2_errors =		new_stats->rx_l2_errors		- old_stats->rx_l2_errors;
	old_stats->rx_drop_red =		new_stats->rx_drop_red		- old_stats->rx_drop_red;
	old_stats->rx_drop_red_bytes =		new_stats->rx_drop_red_bytes	- old_stats->rx_drop_red_bytes;
	old_stats->rx_drop_overrun =		new_stats->rx_drop_overrun	- old_stats->rx_drop_overrun;
	old_stats->rx_drop_overrun_bytes =	new_stats->rx_drop_overrun_bytes- old_stats->rx_drop_overrun_bytes;
	old_stats->rx_drop_bcast =		new_stats->rx_drop_bcast	- old_stats->rx_drop_bcast;
	old_stats->rx_drop_mcast =		new_stats->rx_drop_mcast	- old_stats->rx_drop_mcast;
	old_stats->rx_drop_l3_bcast =		new_stats->rx_drop_l3_bcast	- old_stats->rx_drop_l3_bcast;
	old_stats->rx_drop_l3_mcast =		new_stats->rx_drop_l3_mcast	- old_stats->rx_drop_l3_mcast;
	old_stats->tx_bytes_ok =		new_stats->tx_bytes_ok		- old_stats->tx_bytes_ok;
	old_stats->tx_ucast_frames_ok =		new_stats->tx_ucast_frames_ok	- old_stats->tx_ucast_frames_ok;
	old_stats->tx_bcast_frames_ok =		new_stats->tx_bcast_frames_ok	- old_stats->tx_bcast_frames_ok;
	old_stats->tx_mcast_frames_ok =		new_stats->tx_mcast_frames_ok	- old_stats->tx_mcast_frames_ok;
	old_stats->tx_drops =			new_stats->tx_drops		- old_stats->tx_drops;
	for (qirem = 0; qirem < MAX_QUEUES_PER_QSET; qirem++) {
		struct rq_hw_stats_t * __restrict__ old_rq_stats =
			&old_stats->rq_hw_stats[qirem];
		struct sq_hw_stats_t * __restrict__ old_sq_stats =
			&old_stats->sq_hw_stats[qirem];
		struct rq_hw_stats_t * __restrict__ new_rq_stats =
			&new_stats->rq_hw_stats[qirem];
		struct sq_hw_stats_t * __restrict__ new_sq_stats =
			&new_stats->sq_hw_stats[qirem];
		old_rq_stats->bytes = new_rq_stats->bytes - old_rq_stats->bytes;
		old_rq_stats->pkts = new_rq_stats->pkts - old_rq_stats->pkts;
		old_sq_stats->bytes = new_sq_stats->bytes - old_sq_stats->bytes;
		old_sq_stats->pkts = new_sq_stats->pkts - old_sq_stats->pkts;
	}
}

static void nicvf_statssw_get(struct nicvf *nic, struct sw_stats_t *sw_stat)
{
	size_t qidx, rbdr_idx, thri;
	struct sq_stats_t *stat_sq_dst;
	struct cq_stats_t *stat_cq_dst;
	struct sq_stats_t *stat_sq_src;
	struct cq_stats_t *stat_cq_src;
	struct rbdr_stats_t *stat_rbdr_dst;
	struct rbdr_stats_t *stat_rbdr_src;

	memset(sw_stat, 0, sizeof(*sw_stat));

	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {

		stat_sq_dst = &sw_stat->sq[qidx];
		stat_cq_dst = &sw_stat->cq[qidx];
		stat_cq_dst->cq_count_min = UINT64_MAX;
		stat_sq_dst->sq_recl_min  = UINT64_MAX;
		stat_sq_dst->sq_count_min = UINT64_MAX;

		if (nicvf_rxq_active(nic, qidx) ||
		    nicvf_txq_active(nic, qidx)) {

			for (thri = 0; thri < ODP_THREAD_COUNT_MAX; thri++) {

				stat_sq_src = &nic->qdesc.sq[qidx].stats[thri];
				stat_cq_src = &nic->qdesc.cq[qidx].stats[thri];

				if (stat_cq_src->epoh_last == nic->epoh_curr) {
					stat_cq_dst->epoh_last = nic->epoh_curr; /* to mark that stat are recent */

					stat_cq_dst->cq_count_max =
						max(stat_cq_dst->cq_count_max,
						    stat_cq_src->cq_count_max);
					stat_cq_dst->cq_count_min =
						min(stat_cq_dst->cq_count_min,
						    stat_cq_src->cq_count_min);
					stat_cq_dst->cq_count_sum =
						stat_cq_dst->cq_count_sum +
						stat_cq_src->cq_count_sum;
					stat_cq_dst->probes_cnt =
						stat_cq_dst->probes_cnt +
						stat_cq_src->probes_cnt;
					stat_cq_dst->cq_handler_calls =
						stat_cq_dst->cq_handler_calls +
						stat_cq_src->cq_handler_calls;
				}

				if (stat_sq_src->epoh_last == nic->epoh_curr) {
					stat_sq_dst->epoh_last = nic->epoh_curr; /* to mark that stat are recent */

					stat_sq_dst->xmit_pkts_sum =
						stat_sq_dst->xmit_pkts_sum +
						stat_sq_src->xmit_pkts_sum;
					stat_sq_dst->sq_recl_max =
						max(stat_sq_dst->sq_recl_max,
						    stat_sq_src->sq_recl_max);
					stat_sq_dst->sq_recl_min =
						min(stat_sq_dst->sq_recl_min,
						    stat_sq_src->sq_recl_min);
					stat_sq_dst->sq_recl_sum =
						stat_sq_dst->sq_recl_sum +
						stat_sq_src->sq_recl_sum;
					stat_sq_dst->sq_count_max =
						max(stat_sq_dst->sq_count_max,
						    stat_sq_src->sq_count_max);
					stat_sq_dst->sq_count_min =
						min(stat_sq_dst->sq_count_min,
						    stat_sq_src->sq_count_min);
					stat_sq_dst->sq_count_sum =
						stat_sq_dst->sq_count_sum +
						stat_sq_src->sq_count_sum;
					stat_sq_dst->probes_cnt =
						stat_sq_dst->probes_cnt +
						stat_sq_src->probes_cnt;
					stat_sq_dst->sq_handler_calls =
						stat_sq_dst->sq_handler_calls +
						stat_sq_src->sq_handler_calls;
					stat_sq_dst->xmit_calls =
						stat_sq_dst->xmit_calls +
						stat_sq_src->xmit_calls;
				}
			}
		}
	}

	for (rbdr_idx = 0; rbdr_idx < MAX_RBDR_PER_NIC; rbdr_idx++) {

		if (nicvf_qset_active(&nic->qset[rbdr_idx / MAX_RBDR_PER_QSET])) {

			stat_rbdr_dst = &sw_stat->rbdr[rbdr_idx];
			stat_rbdr_dst->free_min = UINT64_MAX;
			stat_rbdr_dst->lbuf_min = UINT64_MAX;

			for (thri = 0; thri < ODP_THREAD_COUNT_MAX; thri++) {

				stat_rbdr_src = &nic->qdesc.rbdr[rbdr_idx].stats[thri];
				if (stat_rbdr_src->epoh_last != nic->epoh_curr)
					continue;
				stat_rbdr_dst->epoh_last = nic->epoh_curr; /* to mark that stat are recent */

				stat_rbdr_dst->prech_sum =
					stat_rbdr_dst->prech_sum +
					stat_rbdr_src->prech_sum;
				stat_rbdr_dst->prech_cnt =
					stat_rbdr_dst->prech_cnt +
					stat_rbdr_src->prech_cnt;
				stat_rbdr_dst->lbuf_max =
					max(stat_rbdr_dst->lbuf_max,
					    stat_rbdr_src->lbuf_max);
				stat_rbdr_dst->lbuf_min =
					min(stat_rbdr_dst->lbuf_min,
					    stat_rbdr_src->lbuf_min);
				stat_rbdr_dst->lbuf_sum =
					stat_rbdr_dst->lbuf_sum +
					stat_rbdr_src->lbuf_sum;
				stat_rbdr_dst->free_max =
					max(stat_rbdr_dst->free_max,
					    stat_rbdr_src->free_max);
				stat_rbdr_dst->free_min =
					min(stat_rbdr_dst->free_min,
					    stat_rbdr_src->free_min);
				stat_rbdr_dst->free_sum =
					stat_rbdr_dst->free_sum +
					stat_rbdr_src->free_sum;
				stat_rbdr_dst->probes_cnt =
					stat_rbdr_dst->probes_cnt +
					stat_rbdr_src->probes_cnt;
			}
		}
	}

	(nic->epoh_curr)++;
}

static void nicvf_print_rq_swstats(struct nicvf *nic, struct sw_stats_t *sw_stat)
{
	struct snd_queue *sq;
	struct sq_stats_t *sq_stat;
	struct cq_stats_t *cq_stat;
	size_t qidx;
	uint64_t free_cnt, avg, avg2, avg3, avg4;

	printf("qidx cq_count_max  cq_count_min  cq_count_avg probes_cnt "
	       "cq_hndl_calls sq_hndl_calls sq_recl_max sq_recl_min sq_recl_avg "
	       "sq_count_max sq_count_min sq_count_avg xmit_pkts_avg probes_cnt sq_est_free\n");

	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {

		if (!nicvf_rxq_active(nic, qidx))
			continue;

		sq_stat = &sw_stat->sq[qidx];
		cq_stat = &sw_stat->cq[qidx];

		sq = &(nic->qdesc.sq[qidx]);
		free_cnt = (__atomic_load_n(&sq->prod.head.desc, __ATOMIC_ACQUIRE) -
			    __atomic_load_n(&sq->cons.tail.desc, __ATOMIC_RELAXED)) &
			(sq->desc_cnt - 1);
		avg = cq_stat->cq_count_sum / cq_stat->probes_cnt;
		avg2 = sq_stat->sq_recl_sum / sq_stat->probes_cnt;
		avg3 = sq_stat->sq_count_sum / sq_stat->probes_cnt;
		avg4 = sq_stat->xmit_pkts_sum / sq_stat->xmit_calls;

		printf("%4zu   %10"PRIu64"    %10"PRIu64"    %10"PRIu64
		       " %10"PRIu64"    %10"PRIu64"    %10"PRIu64"  %10"PRIu64
		       "  %10"PRIu64"  %10"PRIu64"   %10"PRIu64"   %10"PRIu64
		       "   %10"PRIu64"    %10"PRIu64" %10"PRIu64"  %10"PRIu64,
			qidx,
			cq_stat->cq_count_max,
			cq_stat->cq_count_min != UINT64_MAX ?
				cq_stat->cq_count_min : 0,
			avg,
			cq_stat->probes_cnt,
			cq_stat->cq_handler_calls,
			sq_stat->sq_handler_calls,
			sq_stat->sq_recl_max,
			sq_stat->sq_recl_min != UINT64_MAX ?
				sq_stat->sq_recl_min : 0,
			avg2,
			sq_stat->sq_count_max,
			sq_stat->sq_count_min != UINT64_MAX ?
				sq_stat->sq_count_min : 0,
			avg3,
			avg4,
			sq_stat->probes_cnt,
			free_cnt);

		/* warnings section - see description about each warning */
		if (cq_stat->cq_count_max >= ((CMP_QUEUE_LEN - 1) * (256 - RQ_CQ_DROP-1)) / 256) {
			printf(", red_drop");
			/* See hi_util, this is just higher level of drop ratio */
		} else if (cq_stat->cq_count_max >= ((CMP_QUEUE_LEN - 1) * (256 - RQ_CQ_DROP-10)) / 256 ) {
			printf(", cq_hi_util");
			/* This warning appears if CQ utilization is above certain level, close to
			situation when NIC will start dropping packets. This is not critical but it
			means that line packet ratio is higher than app throughput */
		}
		if (cq_stat->cq_count_max > (avg + 1) * 100) {
			printf(", strange_burst");
			/* This warning shows when RQ is empty by most of the time while also fully
			ocupied from time to time. It meas that it receives big bursts of packets or
			the receiving thread does not process buffers from RQ in constant level of
			processing. This may result in increased jitter of processed packets. */
		}
		if (free_cnt < 10) {
			printf(", sq_est_drop");
			/* This warning shows when SQ is fully occupied. This will result in denying of
			sending packet by ODP API and in turn may lead to packet drop in ODP app. It
			also means that NIC hw is not able to send packet’s at ratio desired by ODP
			app. */
		}
		if (sq_stat->sq_count_max > SND_QUEUE_LEN * 95 / 100) {
			printf(", sq_stat_drop");
		}
		if (sq_stat->sq_recl_min < SQ_HANDLE_THRESHOLD * 2 / 3) {
			printf(", sq_inefic_recl");
		}
		if (sq_stat->sq_recl_max > SND_QUEUE_LEN * 95 / 100) {
			printf(", sq_inefic_recl2");
			/* This wawrinh shows that SQE reclaim process is not
			 * called as frequently as required and there are cycles
			 * which frees almost 95% of send queue. This may leas
			 * to Xmit stalls since there is probably no space in SQ
			 * for new descriptors.
			 * To fix this nicvf_qset_sq_recycle_desc() must be
			 * called in more time consistent manner or just more
			 * frequent. Checking of SQ_HANDLE_THRESHOLD and
			 * SQ_HANDLE_CYCLEGUARD or increase of SND_QSIZE should
			 * be done */
		}
		if (avg > 0 && avg4 < 16) {
			/* This warning says that nicvf_qset_sq_xmit() is called
			 * with quite low amount of packets per single call.
			 * This can lead to inefficient TX since
			 * nicvf_qset_sq_xmit() is designed to perform best when
			 * used with packet bulks */
			printf(", inefic_xmit!");
		}
		printf("\n");
	}
	printf("--------------------------------\n");
}

static void nicvf_print_rbdr_swstats(struct nicvf *nic, struct sw_stats_t *sw_stat)
{
	struct rbdr_stats_t *rbdr_stats;
	struct rbdr_stats_t rbdr_stats_sum;
	size_t rbdr_idx;

	memset(&rbdr_stats_sum, 0, sizeof(rbdr_stats_sum));
	printf("RBDR EPOH   lbuf_max   lbuf_min   lbuf_avg  prech_avg  prech_cnt   "
	       "free_max   free_min   free_avg probes_cnt  real_rbdr\n");

	for (rbdr_idx = 0; rbdr_idx < MAX_RBDR_PER_NIC; rbdr_idx++) {

		if (nicvf_qset_active(&nic->qset[rbdr_idx / MAX_RBDR_PER_QSET])) {

			rbdr_stats = &sw_stat->rbdr[rbdr_idx];
			uint64_t status = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0);
			uint64_t real_rbdr = status & RBDR_RBDRE_COUNT_MASK;

			printf("%4zu %4"PRIx64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64
			       " %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64,
				rbdr_idx,
				rbdr_stats->epoh_last,
				rbdr_stats->lbuf_max,
				rbdr_stats->lbuf_min != UINT64_MAX ?
					rbdr_stats->lbuf_min : 0,
				rbdr_stats->lbuf_sum / rbdr_stats->probes_cnt,
				rbdr_stats->prech_sum / rbdr_stats->prech_cnt,
				rbdr_stats->prech_cnt,
				rbdr_stats->free_max,
				rbdr_stats->free_min != UINT64_MAX ?
					rbdr_stats->free_min : 0,
				rbdr_stats->free_sum / rbdr_stats->probes_cnt,
				rbdr_stats->probes_cnt,
				real_rbdr);

			/* warnings section - see description about each warning */
			if (rbdr_stats->free_max > (RCV_BUF_COUNT * 9 / 10)) {
				printf(", rbdr_low");
				/* This warning is about mostly empty RBDR. It shows when RBDR level is by average
				below 90% of fill-up level. This is critical since NIC will likely not able to
				receive packet. In case of this warning check the RBDR size and refill
				threshold. NOTE packet drop should be limited by CQ length, not by RBDR length. */
			}

			if (rbdr_stats->prech_cnt > 0 &&
			    rbdr_stats->prech_sum == 0) {
				/* This warning tells that during the call of buffer_rawalloc_cache_precharge()
				there was no buffers available in buffer pool. This is critical situation since
				we cannot refill the RBDR. This usually means that buffer pool is to small to
				fulfill the load requirements of your app. In case of this warning declare
				bigger pool or investigate app for possible buffer leaks or unnecessarily long
				buffer processing. */
				printf(", empty_prech");
			}

			if (rbdr_stats->epoh_last < nic->epoh_curr - 1) {
				printf(", stale/old!");
				/* This warning tells that particular QSet statistics are not updated from last
				statistic gathering loop. Do not use printouts from this RBDR for reference
				since they do not represent the current situation. The reason for that might be
				that QSet is not enabled or you app doesn’t called pktio_if_send() or
				pktio_if_recv() in recent time. Those two functions are essential for RBDR
				refill and SQ recycling where we gather the statistics. */
			} else if (rbdr_stats->prech_cnt > 0) {
				printf(" glob_prech!");
				/* This warning is about precharging local cache pool from global buffer pool
				ring.  This is done by calling buffer_rawalloc_cache_precharge() during RBDR
				refill. Such operation is time consuming and should be avoided at all cost or
				the performance will drop significantly.  The general idea for maximal
				performance is that all operations are CPU local including the buffer flow in
				particular pktio. To achieve that RBDR should be refilled only from local cache
				(we should not have to touch global pool ring).  So we must ensure that each
				time we need to refill RBDR this cache will be at least half full (from maximal
				capacity). This way we will be able to perform refill of RBDR with bulk amounts
				of buffers which will decrease the refill count and amortize the cost. Since in
				this operation we consume all cached buffers we hope that it will be filled
				again before we will make next RBDR refill. This fill-up will (hopefully) came
				from freeing (recycling) of buffers used for send operations as well as from
				buffers which was already received and processed by ODP app (app will call
				odp_buffer_free()). Unfortunately we have to be prepared for worst scenario and
				in case such recycle will not happen we have to fill the RBDR from global pool.
				In this case local cache is used only as temporal storage (see
				buffer_rawalloc_cache_precharge() call). If your app is properly tuned the
				buffer flow will be smooth between RBDR refill, packet reception, packet send
				and buffer reclaim (by odp_buffer_free()) and we do not have to use the
				buffer_rawalloc_cache_precharge() call.  If this warning appears you should
				look at buffer flow in your app. It can be that you free buffers in big chunks
				which will overflow cache and it need to be refilled to frequently. You can
				also make final tuning by following defines PKTIO_SQ_THRESHOLD and
				PKTIO_RBDR_THRESHOLD which decides about SQ reclaim and RBDR refill frequency
				ratio. */

			}
			printf("\n");

			if (rbdr_stats->epoh_last == (nic->epoh_curr - 1)) {
				rbdr_stats_sum.prech_sum += rbdr_stats->prech_sum;
				rbdr_stats_sum.prech_cnt += rbdr_stats->prech_cnt;
				rbdr_stats_sum.lbuf_max =
					max(rbdr_stats_sum.lbuf_max, rbdr_stats->lbuf_max);
				if (rbdr_stats->lbuf_min > 0)
					rbdr_stats_sum.lbuf_min =
						min(rbdr_stats_sum.lbuf_min, rbdr_stats->lbuf_min);
				rbdr_stats_sum.lbuf_sum += rbdr_stats->lbuf_sum;
				rbdr_stats_sum.free_max =
					max(rbdr_stats->free_max, rbdr_stats_sum.free_max);
				if (rbdr_stats->free_min > 0)
					rbdr_stats_sum.free_min =
						min(rbdr_stats->free_min, rbdr_stats_sum.free_min);
				rbdr_stats_sum.free_sum += rbdr_stats->free_sum;
				rbdr_stats_sum.probes_cnt += rbdr_stats->probes_cnt;
			}
		}
	}

	printf("TOTA %4"PRIx64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64
	       " %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64,
		nic->epoh_curr,
		rbdr_stats_sum.lbuf_max,
		rbdr_stats_sum.lbuf_min != UINT64_MAX ?
			rbdr_stats_sum.lbuf_min : 0,
		rbdr_stats_sum.lbuf_sum / rbdr_stats_sum.probes_cnt,
		rbdr_stats_sum.prech_sum / rbdr_stats_sum.prech_cnt,
		rbdr_stats_sum.prech_cnt,
		rbdr_stats_sum.free_max,
		rbdr_stats_sum.free_min != UINT64_MAX ?
			rbdr_stats_sum.free_min : 0,
		rbdr_stats_sum.free_sum / rbdr_stats_sum.probes_cnt,
		rbdr_stats_sum.probes_cnt);
	if (rbdr_stats_sum.prech_cnt > 0)
		printf(" glob_prech!");
	if (rbdr_stats_sum.free_max > (RCV_BUF_COUNT * 9 / 10))
		printf(", rbdr_low");
	if (rbdr_stats_sum.prech_cnt > 0 &&
	    rbdr_stats_sum.prech_sum == 0)
		printf(", empty_prech");
	printf("\n");
	printf("--------------------------------\n");
}

static void nicvf_print_queue_hwstats(
	struct queue_set *qset,
	struct hw_stats_t *hw_stats)
{
	size_t qirem;

	printf("HW stats\n"
		"rx_bytes_ok        %10"PRIu64" rx_ucast_frames_ok    %10"PRIu64"\n"
		"rx_bcast_frames_ok %10"PRIu64" rx_mcast_frames_ok    %10"PRIu64"\n"
		"rx_fcs_errors      %10"PRIu64" rx_l2_errors          %10"PRIu64"\n"
		"rx_drop_red        %10"PRIu64" rx_drop_red_bytes     %10"PRIu64"\n"
		"rx_drop_overrun    %10"PRIu64" rx_drop_overrun_bytes %10"PRIu64"\n"
		"rx_drop_bcast      %10"PRIu64" rx_drop_mcast         %10"PRIu64"\n"
		"rx_drop_l3_bcast   %10"PRIu64" rx_drop_l3_mcast      %10"PRIu64"\n"
		"tx_bytes_ok        %10"PRIu64" tx_ucast_frames_ok    %10"PRIu64"\n"
		"tx_bcast_frames_ok %10"PRIu64" tx_mcast_frames_ok    %10"PRIu64"\n"
		"tx_drops           %10"PRIu64"\n",
		hw_stats->rx_bytes_ok,
		hw_stats->rx_ucast_frames_ok,
		hw_stats->rx_bcast_frames_ok,
		hw_stats->rx_mcast_frames_ok,
		hw_stats->rx_fcs_errors,
		hw_stats->rx_l2_errors,
		hw_stats->rx_drop_red,
		hw_stats->rx_drop_red_bytes,
		hw_stats->rx_drop_overrun,
		hw_stats->rx_drop_overrun_bytes,
		hw_stats->rx_drop_bcast,
		hw_stats->rx_drop_mcast,
		hw_stats->rx_drop_l3_bcast,
		hw_stats->rx_drop_l3_mcast,
		hw_stats->tx_bytes_ok,
		hw_stats->tx_ucast_frames_ok,
		hw_stats->tx_bcast_frames_ok,
		hw_stats->tx_mcast_frames_ok,
		hw_stats->tx_drops);
	printf("QIDX   rq_bytes    rq_pkts   sq_bytes    sq_pkts\n");
	for (qirem = 0; qirem < MAX_QUEUES_PER_QSET; qirem++) {

		if ((!nicvf_rxq_active(qset->nic, qset->qset_idx * MAX_QUEUES_PER_QSET + qirem)) ||
		    (!nicvf_txq_active(qset->nic, qset->qset_idx * MAX_QUEUES_PER_QSET + qirem)))
			continue;

		struct rq_hw_stats_t * __restrict__ rq_stats =
			&hw_stats->rq_hw_stats[qirem];
		struct sq_hw_stats_t * __restrict__ sq_stats =
			&hw_stats->sq_hw_stats[qirem];
		printf("%4zu %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64"\n",
			qirem,
			rq_stats->bytes, rq_stats->pkts,
			sq_stats->bytes, sq_stats->pkts);
	}
}

void nicvf_print_queue_stats(struct nicvf *nic)
{
	static uint64_t gbuf_min = UINT64_MAX;

	struct sw_stats_t sw_qset_stat;
	struct hw_stats_t hw_stats_old;
	struct queue_set *qset;
	size_t qset_idx;
	struct pool_entry_s *pool = nicvf_get_pool(nic);
	uint64_t gbuf_cnt;

	printf(" ====== NIC statistics ======\n");

/* buffer pool stats */
	odp_buffer_pool_free_bufs((odp_pool_t)pool, &gbuf_cnt, NULL);
	gbuf_min = min(gbuf_cnt, gbuf_min);
	printf("Global pool gbuf_cnt=%"PRIu64 " gbuf_min=%"PRIu64, gbuf_cnt, gbuf_min);
	if (gbuf_cnt < CMP_QUEUE_LEN)
		printf(" WARNING WARNING WARNING WARNING WARNING WARNING WARNING global pool low!");
	printf("\n--------------------------------\n");

	nicvf_statssw_get(nic, &sw_qset_stat);
	nicvf_print_rq_swstats(nic, &sw_qset_stat);
	nicvf_print_rbdr_swstats(nic, &sw_qset_stat);

/* queue set stats */
	for (qset_idx = 0; qset_idx < nic->qset_cnt; qset_idx++) {

		qset = &nic->qset[qset_idx];

		hw_stats_old = qset->last_hw_stats;
		nicvf_stathw_get(qset, &qset->last_hw_stats);
		nicvf_stathw_diff(&hw_stats_old, &qset->last_hw_stats);
		nicvf_print_queue_hwstats(qset, &hw_stats_old);
	}

}
#endif

#if (DEBUG >= 4)
static void nicvf_dump_packet(void* pktdata, size_t pktsize)
{
	size_t i, j;
	uint8_t data;

	for (i = 0; i < pktsize; i += 16) {
		printf("%04zx:  ", i);

		for (j = i; (j < pktsize) && (j < i + 16); j++) {
			printf("%02x ", ((uint8_t*)pktdata)[j]);
		}
		if (j % 16) {
			for (j = j % 16; j < 16; j++) {
				printf("   ");
			}
		}
		printf(" ");

		for (j = i; (j < pktsize) && (j < i + 16); j++) {
			data = ((uint8_t*)pktdata)[j];
			printf("%c", (data > ' ') && (data < '~') ? data : '.');
		}

		printf("\n");
	}
	printf("\n");
}
#endif

static int nicvf_buffers_alloc(
	struct nicvf *nic, size_t cnt, struct odp_buffer_hdr_t **buff,
	bool cache_only)
{
	struct pool_entry_s *pool = nicvf_get_pool(nic);
	uintptr_t addoffset;

	/* calculate the offset */
	addoffset = nicvf_buffer_from_ptr_offset(pool);
	/* Map the buffers to physical address space for UIO
	 * for VFIO we use the same virtual adresses of buffers as we already
	 * have */
	if (NICVF_TYPE_UIO == nic->nicvf_type) {
		addoffset -= odp_shm_phys_addr_offset(pool->pool_buffer_shm);
	}

	/* Bulk allocate of the buffers */
	if (likely(cache_only)) {
		if (buffer_rawalloc_cache_bulk(pool, cnt, buff, addoffset))
			return -1;
	} else {
		if (buffer_rawalloc_bulk(pool, cnt, buff, addoffset))
			return -1;
	}

	return 0;
}

static void nicvf_buffer_free(struct nicvf *nic, uint64_t phys)
{
	struct pool_entry_s *pool = nicvf_get_pool(nic);
	struct odp_buffer_hdr_t *buf;
	void* virt;
	size_t offset;

	if (NICVF_TYPE_UIO == nic->nicvf_type) {
		virt = odp_shm_virt_addr(pool->pool_buffer_shm, phys);
	} else {
		virt = (void*)phys;
	}

	offset = nicvf_buffer_from_ptr_offset(pool);
	buf = nicvf_buffer_from_ptr(virt, offset);
	buffer_free(pool, buf);
}

static int nicvf_qidx_poll_reg(
	struct nicvf *nic, size_t qidx, uint64_t offset,
	int bit_pos, int bits, uint64_t val)
{
	uint64_t bit_mask;
	uint64_t reg_val;
	int timeout = 10;

	bit_mask = (1ULL << bits) - 1;
	bit_mask = (bit_mask << bit_pos);

	while (timeout) {
		reg_val = nicvf_qidx_reg_read(nic, qidx, offset);
		if (((reg_val & bit_mask) >> bit_pos) == val)
			return 0;
		nanosleep(&(struct timespec) {0, 1000000}, NULL);
		timeout--;
	}
	ERR("Poll on reg 0x%"PRIx64" failed\n", offset);
	return -1;
}

static int nicvf_rbdr_poll_reg(
	struct nicvf *nic, size_t rbdr_idx, uint64_t offset,
	int bit_pos, int bits, uint64_t val)
{
	uint64_t bit_mask;
	uint64_t reg_val;
	int timeout = 10;

	bit_mask = (1ULL << bits) - 1;
	bit_mask = (bit_mask << bit_pos);

	while (timeout) {
		reg_val = nicvf_rbdr_reg_read(nic, rbdr_idx, offset);
		if (((reg_val & bit_mask) >> bit_pos) == val)
			return 0;
		nanosleep(&(struct timespec) {0, 1000000}, NULL);
		timeout--;
	}
	DBGV1("Poll on reg 0x%"PRIx64" failed\n", offset);
	return -1;
}

static void* nicvf_mem_alloc(struct nicvf *nic,
			     struct mem_desc *mem_desc,
			     size_t size, size_t align, const char *name)
{
	void* virt;
	uint64_t phys;

	ODP_ASSERT(check_powerof_2(align)); /* aligment must be power of 2 */
	if (NICVF_TYPE_VFIO == nic->nicvf_type) {
		/* for VFIO we use IOMMU which requires full page aligment, so
		 * it can map whole pages */
		align = odp_max(align, odp_sys_page_size());
		/* additionaly size also must be aligned to page size */
		if (size % align) {
			size_t pages = (size / align) + 1;
			size = pages * align;
		}
	}

	/* Allocate memory for descriptors */
	virt = nic_dma_alloc(size, align, name);
	if (!virt) {
		ERR("Unable to allocate memory size=%zu align=%zu errno=%s\n",
			size, align, odp_errno_str(odp_errno()));
		return NULL;
	}
	ODP_ASSERT(!((uint64_t)virt % align)); /* address aligned? */
	if (nic_dma_map(nic, virt, size, &phys)) {
		ERR("Unable to map memory\n");
		nic_dma_free(virt);
		return NULL;
	}

	mem_desc->size = size;
	mem_desc->virt = virt;
	mem_desc->phys = phys;

	return virt;
}

static void nicvf_mem_free(struct nicvf *nic, struct mem_desc *mem_desc)
{
	if (!mem_desc)
		return;

	(void)nic_dma_unmap(nic, mem_desc->virt, mem_desc->size, mem_desc->phys);
	(void)nic_dma_free(mem_desc->virt);
	mem_desc->virt = NULL;
	mem_desc->phys = 0;
	mem_desc->size = 0;
}

#ifdef VNIC_RSS_SUPPORT
static void nicvf_set_rss_key(struct queue_set *qset)
{
	struct nicvf_rss_info *rss = &qset->rss_info;
	uint64_t addr;
	int idx;

	/* Using the HW reset value for now */
	rss->key[0] = 0xFEED0BADFEED0BAD;
	rss->key[1] = 0xFEED0BADFEED0BAD;
	rss->key[2] = 0xFEED0BADFEED0BAD;
	rss->key[3] = 0xFEED0BADFEED0BAD;
	rss->key[4] = 0xFEED0BADFEED0BAD;

	addr = NIC_VNIC_RSS_KEY_0_4;
	for (idx = 0; idx < RSS_HASH_KEY_SIZE; idx++) {
		nicvf_vf_reg_write(qset, addr, rss->key[idx]);
		addr += sizeof(uint64_t);
	}
}

static int nicvf_rss_init(struct nicvf *nic)
{
	struct nicvf_rss_info *rss = &nic->qset[0].rss_info;
	size_t qidx, idx;
	size_t qcnt;
	int ret;
	uint8_t cpi_alg = nic->cpi_alg;

	/* we need to spread packets betwen enabled queues only */
	qcnt = 0;
	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {
		if (nicvf_rxq_active(nic, qidx))
			qcnt++;
	}

	ret = nicvf_mbox_get_rss_size(&nic->qset[0]);
	if (ret < 0) {
		ERR("Cannot get RSS size from PF\n");
		return -1;
	}
	rss->rss_size = ret;

	if ((qcnt <= 1) || (cpi_alg != CPI_ALG_NONE)) {
		rss->enable = false;
		rss->hash_bits = 0;
		return 0;
	}
	rss->enable = true;

	/* set the RSS key */
	nicvf_set_rss_key(&nic->qset[0]);

	rss->cfg = RSS_IP_HASH_ENA | RSS_TCP_HASH_ENA | RSS_UDP_HASH_ENA;
	nicvf_vf_reg_write(&nic->qset[0], NIC_VNIC_RSS_CFG, rss->cfg);

	rss->hash_bits = ilog2(rounddown_pow_of_two(rss->rss_size));

	for (idx = 0; idx < rss->rss_size; idx++) {
		rss->ind_tbl[idx] = idx % qcnt;
	}

	if (nicvf_mbox_config_rss(&nic->qset[0])) {
		ERR("Cannot config RSS\n");
		return -1;
	}

	return 0;
}
#endif

/* *****************************************************************************
 * RBDR functions
 * *****************************************************************************/

static int nicvf_qset_rbdr_alloc(struct nicvf *nic, size_t rbdr_idx,
				 size_t desc_cnt, size_t buf_size)
{
	struct queue_set *qset = &nic->qset[rbdr_idx / MAX_RBDR_PER_QSET];
	struct rbdr *rbdr = &nic->qdesc.rbdr[rbdr_idx];
	void* virt;
	char name[30];

	snprintf(name, sizeof(name), "%d.RBDR[%zd]", qset->vf_id, rbdr_idx);

	/* Buffer size has to be in multiples of 128 bytes */
	ODP_ASSERT(0 == (buf_size % 128));

	/* Allocate memory for RBDR descriptors */
	virt = nicvf_mem_alloc(nic, &rbdr->mem_desc,
			       desc_cnt * sizeof(struct rbdr_entry_t),
			       NICVF_RCV_BUF_ALIGN_BYTES, name);
	if (!virt) {
		ERR("Unable to allocate memory for rcv buffer ring\n");
		goto err;
	}

	rbdr->desc = virt;
	rbdr->desc_cnt = desc_cnt;
	rbdr->buf_size = buf_size;
	rbdr->enable = true;

	return 0;
err:
	return -ENOMEM;
}

static void nicvf_qset_rbdr_free_desc(struct nicvf *nic, size_t rbdr_idx)
{
	struct rbdr *rbdr = &(nic->qdesc.rbdr[rbdr_idx]);
	struct rbdr_entry_t *desc = rbdr->desc;
	uint64_t desc_cnt_mask = rbdr->desc_cnt - 1;
	uint64_t head, tail;
	uint64_t phys;

	if (!rbdr->desc)
		return;

	head = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_HEAD) >> 3;
	tail = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_TAIL) >> 3;
	/* Free SKBs */
	while (head != tail) {
		phys = desc[head].full_addr;
		if (phys != 0)
			nicvf_buffer_free(nic, phys);
		head++;
		head &= desc_cnt_mask;
	}

}

static void nicvf_qset_rbdr_free(struct nicvf *nic, size_t rbdr_idx)
{
	struct rbdr *rbdr = &(nic->qdesc.rbdr[rbdr_idx]);

	rbdr->enable = false;
	if (!rbdr->desc)
		return;

	nicvf_qset_rbdr_free_desc(nic, rbdr_idx);

	/* Free RBDR ring */
	nicvf_mem_free(nic, &rbdr->mem_desc);
}

#ifdef NIC_QUEUE_STATS
static inline void OPTIMIZATION_RECV nicvf_qset_rbdr_stats_update(
	struct rbdr_stats_t *rbdr_stats, uint64_t epoh_curr,
	uint64_t lbuf_cnt, uint64_t free_cnt_real)
{
	if (unlikely(epoh_curr != rbdr_stats->epoh_last)) {
		rbdr_stats->lbuf_sum = 0;
		rbdr_stats->lbuf_max = 0;
		rbdr_stats->lbuf_min = UINT64_MAX;
		rbdr_stats->prech_sum = 0;
		rbdr_stats->prech_cnt = 0;
		rbdr_stats->free_max = 0;
		rbdr_stats->free_min = UINT64_MAX;
		rbdr_stats->free_sum = 0;
		rbdr_stats->probes_cnt = 0;
		rbdr_stats->epoh_last = epoh_curr;
	}

	rbdr_stats->lbuf_sum += lbuf_cnt;
	rbdr_stats->lbuf_max = max(rbdr_stats->lbuf_max, lbuf_cnt);
	rbdr_stats->lbuf_min = min(rbdr_stats->lbuf_min, lbuf_cnt);
	rbdr_stats->free_max = max(rbdr_stats->free_max, free_cnt_real);
	rbdr_stats->free_min = min(rbdr_stats->free_min, free_cnt_real);
	rbdr_stats->free_sum += free_cnt_real;
	(rbdr_stats->probes_cnt)++;
}
#endif

/* Refill receive buffer descriptors with new buffers */
static size_t OPTIMIZATION_RECV nicvf_qset_rbdr_refill(
	struct nicvf * __restrict__ nic, size_t rbdr_idx, uint64_t free_cnt)
{
	struct rbdr *rbdr = &(nic->qdesc.rbdr[rbdr_idx]);
	struct rbdr_entry_t * __restrict__ desc = rbdr->desc;
	struct pool_entry_s *pool = nicvf_get_pool(nic);
#ifdef NIC_QUEUE_STATS
	struct rbdr_stats_t * __restrict__ rbdr_stats =
		&nic->qdesc.rbdr[rbdr_idx].stats[odp_thread_id()];
#endif
	uint64_t desc_cnt_mask = rbdr->desc_cnt - 1;
	uint64_t lbuf_cnt;
	uint64_t gbuf_cnt;
	uint64_t alloc_cnt;
	uint32_t head_prev;
	uint32_t head_next;
	size_t j;
	int ret;

#if (DEBUG >= 1)
	ODP_ASSERT(rbdr->enable); /* RBDR must be enabled */
#endif

	/* get number of buffers that the current thread have in local cache
	 * the point is do not use global cache at all until we cannot refill
	 * RBDR the other way */
	odp_buffer_pool_free_bufs((odp_pool_t)pool, &gbuf_cnt, &lbuf_cnt);

	/* from time to time we might need to add packets to local
	 * cache since in havy loaded env packet proccesing time might
	 * be long (time betwen packet is received and returned to
	 * cache)
	 * free_cnt variable is the external estimate about buffers which we
	 * should be able to refill */
	if (unlikely((lbuf_cnt < free_cnt) && (gbuf_cnt > 16))) {
		size_t precharge_add = buffer_rawalloc_cache_precharge(pool);
#ifdef NIC_QUEUE_STATS
		rbdr_stats->prech_sum += precharge_add;
		(rbdr_stats->prech_cnt)++;
#endif
		lbuf_cnt += precharge_add;
	}

#ifdef NIC_QUEUE_STATS
	/* check the free space in RBDR, from HW - slow :( */
	uint64_t status = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0);
	uint64_t free_cnt_real = desc_cnt_mask - (status & RBDR_RBDRE_COUNT_MASK);
	assert(free_cnt_real >= free_cnt); /* lets make sure that our estimations are correct */
	nicvf_qset_rbdr_stats_update(rbdr_stats, nic->epoh_curr,
				     lbuf_cnt, free_cnt_real);
#endif

	/* calculate how many buffers we may fill */
	alloc_cnt = min(lbuf_cnt, free_cnt);
	/* if we cannot make refill, exit with 0 as we did not refill rbdr */
	if (0 == alloc_cnt)
		return 0;

/* step 1 - atomic move of head - reservation of space */
	do {
		head_prev = __atomic_load_n(&rbdr->head, __ATOMIC_ACQUIRE);
		head_next = head_prev + alloc_cnt;
	} while (unlikely(!__atomic_compare_exchange_n(
		      &rbdr->head, &head_prev, head_next,
		      false /*strong */, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)));

/* Step 2 - allocate of the buffers - fill the space */
	j = head_prev & desc_cnt_mask;
	if (unlikely((j + alloc_cnt) & (~desc_cnt_mask))) {
		/* refill overlaps */
		size_t first_alloc_cnt = rbdr->desc_cnt - j;
		ret = nicvf_buffers_alloc(nic, first_alloc_cnt,
					  (struct odp_buffer_hdr_t **)(&desc[j]),
					  true);
		/* we allocate from cache this call cannot fail as we already moved the head */
		ODP_ASSERT(0 == ret); /* call cannot fail */
		ret = nicvf_buffers_alloc(nic, alloc_cnt - first_alloc_cnt,
					  (struct odp_buffer_hdr_t **)(&desc[0]),
					  true);
		ODP_ASSERT(0 == ret); /* call cannot fail */
	} else {
		ret = nicvf_buffers_alloc(nic, alloc_cnt,
					  (struct odp_buffer_hdr_t **)(&desc[j]),
					  true);
		/* we allocate from cache this call cannot fail as we already moved the head */
		ODP_ASSERT(0 == ret); /* call cannot fail */
	}

/* step 3 - atomic move of producer tail - finalization */
	/* If there are other enqueues in progress that preceeded us,
	 * we need to wait for them to complete */
	while (unlikely(__atomic_load_n(&rbdr->tail, __ATOMIC_ACQUIRE) != head_prev))
		odp_cpu_pause();

	/* Notify HW - make sure all memory stores are done before ringing doorbell */
	wmb();
	nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_DOOR, alloc_cnt);
	DBGV1("Refilled RBDR %zu with %"PRIu64" entr\n", rbdr_idx, alloc_cnt);

	/* Finaly we may anounce the world that both descriptors and HW is set
	 * up and we finished our work (now it is their turn) */
	__atomic_store_n(&rbdr->tail, head_next, __ATOMIC_RELEASE);

	return alloc_cnt;
}

/* Precharge RBDR with buffers */
static int nicvf_qset_rbdr_precharge(struct nicvf *nic, size_t rbdr_idx)
{
	struct rbdr *rbdr = &(nic->qdesc.rbdr[rbdr_idx]);
	struct rbdr_entry_t *desc = rbdr->desc;
	uint64_t alloc_cnt;

#if (DEBUG >= 1)
	ODP_ASSERT(rbdr->enable);
#endif

	/* we assume that RBDR is empty */
	alloc_cnt = rbdr->desc_cnt - 1;

	if (nicvf_buffers_alloc(
		nic, alloc_cnt, (struct odp_buffer_hdr_t **)(&desc[0]), false)) {
			ERR("Canot allocate buffers\n");
			return -1;
	}

	/* Notify HW - make sure all memory stores are done before ringing doorbell */
	wmb();
	nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_DOOR, alloc_cnt);
	DBGV1("Refilled RBDR %zu with %"PRIu64" entr\n", rbdr_idx, alloc_cnt);

	return 0;
}

static int nicvf_qset_rbdr_reset(struct nicvf *nic, size_t rbdr_idx)
{
	uint64_t status;

	/* read the current status */
	status = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0);
	status = (status & RBDR_FIFO_STATE_MASK) >> RBDR_FIFO_STATE_SHIFT;
	/* reset the RBDR */
	nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_CFG,
			     NICVF_RBDR_RESET);
	/* Pool for RESET state only in case we where in FAIL state (HW bug) */
	if (nicvf_rbdr_poll_reg(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0,
				RBDR_FIFO_STATE_SHIFT, 0x02,
				(RBDR_FIFO_STATE_ACTIVE == status) ?
					RBDR_FIFO_STATE_INACTIVE :
					RBDR_FIFO_STATE_RESET)) {
		ERR("Error while polling on RBDR STATUS0 = reset\n");
		return -1;
	}

	nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_CFG, 0x00);
	if (nicvf_rbdr_poll_reg(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0,
				RBDR_FIFO_STATE_SHIFT, 0x02,
				RBDR_FIFO_STATE_INACTIVE)) {
		ERR("Error while polling on RBDR STATUS0 = inactive\n");
		return -1;
	}

	return 0;
}


static int nicvf_qset_rbdr_reclaim(struct nicvf *nic, size_t rbdr_idx)
{
	uint64_t status;
	int timeout = 10;

	/* If RBDR FIFO is in 'FAIL' state then do a reset first
	* before relaiming. */
	status = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0);
	status = (status & RBDR_FIFO_STATE_MASK) >> RBDR_FIFO_STATE_SHIFT;
	if (RBDR_FIFO_STATE_FAIL == status) {
	       nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_CFG,
				    NICVF_RBDR_RESET);
	}

	/* Disable RBDR */
	nicvf_rbdr_reg_write(nic, rbdr_idx, NIC_QSET_RBDR_0_1_CFG, 0);
	if (nicvf_rbdr_poll_reg(nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0,
				RBDR_FIFO_STATE_SHIFT, 0x02,
				RBDR_FIFO_STATE_INACTIVE)) {
		ERR("Error while polling on RBDR STATUS0 register after disable\n");
		return -1;
	}

	while (1) {
		status = nicvf_rbdr_reg_read(
			nic, rbdr_idx, NIC_QSET_RBDR_0_1_PREFETCH_STATUS);
		if ((status & 0xFFFFFFFF) == ((status >> 32) & 0xFFFFFFFF)) {
			break;
		}
		nanosleep(&(struct timespec) {0, 1000000}, NULL);
		timeout--;
		if (!timeout) {
			ERR("Failed polling on prefetch status\n");
			return -1;
		}
	}

	/* free buffers memory under descriptors */
	nicvf_qset_rbdr_free_desc(nic, rbdr_idx);

	(void)nicvf_qset_rbdr_reset(nic, rbdr_idx);

	return 0;
}

static int nicvf_qset_rbdr_config(struct nicvf *nic, size_t rbdr_idx, bool enable)
{
	struct rbdr *rbdr = &(nic->qdesc.rbdr[rbdr_idx]);
	struct rbdr_cfg rbdr_cfg;
	uint64_t head, tail;

	if (enable)
		nicvf_qset_rbdr_reset(nic, rbdr_idx);

	if (nicvf_qset_rbdr_reclaim(nic, rbdr_idx)) {
		return -1;
	}
	if (!enable) {
		return 0;
	}

	/* Set descriptor base address */
	nicvf_rbdr_reg_write(
		nic, rbdr_idx, NIC_QSET_RBDR_0_1_BASE, (uint64_t)(rbdr->mem_desc.phys));

	/* Enable RBDR  & set queue size */
	/* Buffer size should be in multiples of 128 bytes */
	rbdr_cfg = (struct rbdr_cfg) {
		.ena = 1,
		.reset = 0,
		.ldwb = 0,
		.qsize = ctz(rbdr->desc_cnt >> RBDR_SIZE_SHIFT),
		.avg_con = 0,
		.lines = rbdr->buf_size / 128,
	};
	nicvf_rbdr_reg_write(
		nic, rbdr_idx, NIC_QSET_RBDR_0_1_CFG, rbdr_cfg.value);

	__asm__ __volatile__ ("dsb ish" : : : "memory");
	/* Verify proper RBDR reset */
	head = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_HEAD) >> 3;
	tail = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_TAIL) >> 3;

	NFO("Configuring RBDR rbdr_idx=%zu head=%"PRIu64" tail=%"PRIu64"\n",
	    rbdr_idx, head, tail);

	if ((head | tail) != 0) {
		ERR("Error intializing RBDR ring rbdr_idx=%zu head=%"PRIu64" tail=%"PRIu64"\n",
		    rbdr_idx, head, tail);
		return -1;
	}

	/* prefill RBDR */
	if (nicvf_qset_rbdr_precharge(nic, rbdr_idx)) {
		ERR("Error while filling RBDR\n");
		return -1;
	}

	/* initize tail register shadow for lockfree refill function */
	rbdr->tail = nicvf_rbdr_reg_read(nic, rbdr_idx, NIC_QSET_RBDR_0_1_TAIL) >> 3;
	rbdr->tail &= rbdr->desc_cnt - 1;
	rbdr->head = rbdr->tail;

	return 0;
}

/* *****************************************************************************
 * Send queue function
 * *****************************************************************************/

static int nicvf_qset_sq_alloc(struct nicvf *nic, size_t qidx, size_t desc_cnt)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct snd_queue *sq = &(nic->qdesc.sq[qidx]);
	void* virt;
	char name[20];

	snprintf(name, sizeof(name), "%d.SQ[%zd]", qset->vf_id, qidx);

	virt = nicvf_mem_alloc(nic, &sq->mem_desc,
			       desc_cnt * sizeof(union sq_entry_t),
			       NICVF_SQ_BASE_ALIGN_BYTES, name);
	if (!virt) {
		ERR("Unable to allocate memory for send queue\n");
		return -ENOMEM;
	}

	sq->desc = virt;
	sq->desc_cnt = desc_cnt;

	snprintf(name, sizeof(name), "%d.SQ[%zd].bufs_used", qset->vf_id, qidx);

	sq->bufs_used = nic_dma_alloc(
		desc_cnt * sizeof(struct packet_hdr_t *), odp_sys_page_size(), name);

	sq->prod.head.val = 0;
	sq->prod.tail.val = 0;
	sq->cons.head.val = 0;
	sq->cons.tail.val = 0;
	sq->recycle_time = odp_cpu_cycles();
	sq->pool_poluted = 0;

	return 0;
}

static void nicvf_qset_sq_free(struct nicvf *nic, size_t qidx)
{
	struct snd_queue *sq = &(nic->qdesc.sq[qidx]);

	sq->enable = false;
	if (!sq->desc)
		return;

	nicvf_mem_free(nic, &sq->mem_desc);
	nic_dma_free(sq->bufs_used);
}

static OPTIMIZATION_XMIT size_t nicvf_qset_sq_recycle_desc(
	struct nicvf *nic, size_t qidx);

static int nicvf_qset_sq_reclaim(struct nicvf *nic, size_t qidx)
{
	/* Do recycling before disable */
	nicvf_qset_sq_recycle_desc(nic, qidx);
	/* Disable send queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_CFG, 0);
	/* Check if SQ is stopped */
	if (nicvf_qidx_poll_reg(nic, qidx, NIC_QSET_SQ_0_7_STATUS, 21, 1, 0x01)) {
		return -1;
	}
	/* Reset send queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_CFG, NICVF_SQ_RESET);

	return 0;
}

/* TBD
 * - Set TL3 index
 */
static int nicvf_qset_sq_config(struct nicvf *nic, size_t qidx, bool enable)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct snd_queue *sq = &(nic->qdesc.sq[qidx]);
	struct sq_cfg sq_cfg;
	uint64_t head, tail;
	size_t qirem = qidx % MAX_QUEUES_PER_QSET;
	uint8_t vf_id = qset->vf_id;

	sq->enable = enable;
	if (!enable) {
		return nicvf_qset_sq_reclaim(nic, qidx);
	}

	/* Reset send queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_CFG, NICVF_SQ_RESET);

	head = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_SQ_0_7_HEAD) >> 4;
	tail = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_SQ_0_7_TAIL) >> 4;
	NFO("Configuring SQ qidx=%zu using vnic_id %"PRIu8" head=%"PRIu64" tail=%"PRIu64"\n",
	    qidx, vf_id, head, tail);

	sq->cq_qs = vf_id;
	sq->cq_idx = qirem; /* 1 to 1 assigment in the same QSET */

	sq->prod.head.val = 0;
	sq->prod.tail.val = 0;
	sq->cons.head.val = 0;
	sq->cons.tail.val = 0;
	sq->recycle_time = odp_cpu_cycles();
	sq->pool_poluted = 0;

	/* Send a mailbox msg to PF to config SQ */
	if (nicvf_mbox_sq_config(nic, qidx)) {
		ERR("Error on nicvf_mbox_sq_config\n");
		return -1;
	}

	/* Set queue base address */
	nicvf_qidx_reg_write(
		nic, qidx, NIC_QSET_SQ_0_7_BASE, (uint64_t)(sq->mem_desc.phys));

	/* Enable send queue  & set queue size */
	sq_cfg = (struct sq_cfg) {
		.ena = 1,
		.reset = 0,
		.ldwb = 0,
		.qsize = ctz(sq->desc_cnt >> SND_QSIZE_SHIFT),
		.tstmp_bgx_intf = 0,
	};
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_CFG, sq_cfg.value);

	/* Ring doorbell so that H/W restarts processing SQEs */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_DOOR, 0);

	return 0;
}

#ifdef NIC_QUEUE_STATS
static inline void OPTIMIZATION_RECV nicvf_qset_sq_recycle_desc_stats(
	struct sq_stats_t * __restrict__ sq_stats, uint64_t epoh_curr,
	uint64_t to_free, uint64_t sq_count)

{
	if (unlikely(epoh_curr != sq_stats->epoh_last)) {
		sq_stats->xmit_pkts_sum = 0;
		sq_stats->sq_recl_max = 0;
		sq_stats->sq_recl_min = UINT64_MAX;
		sq_stats->sq_recl_sum = 0;
		sq_stats->sq_count_max = 0;
		sq_stats->sq_count_min = UINT64_MAX;
		sq_stats->sq_count_sum = 0;
		sq_stats->sq_handler_calls = 0;
		sq_stats->probes_cnt = 0;
		sq_stats->xmit_calls = 0;
		sq_stats->epoh_last = epoh_curr;
	}
	sq_stats->sq_recl_max = max(sq_stats->sq_recl_max, to_free);
	sq_stats->sq_recl_min = min(sq_stats->sq_recl_min, to_free);
	sq_stats->sq_recl_sum += to_free;
	sq_stats->sq_count_max = max(sq_stats->sq_count_max, sq_count);
	sq_stats->sq_count_min = min(sq_stats->sq_count_min, sq_count);
	sq_stats->sq_count_sum += sq_count;
	sq_stats->probes_cnt++;
}
#endif

static __attribute__((noinline, hot, optimize("O3", "inline-functions")))
void free_buffers(struct nicvf *nic, struct snd_queue *sq,
		  size_t len, struct odp_buffer_hdr_t* bufs[len])
{
	size_t i;
	size_t n = len - 1;

	if (likely(!sq->pool_poluted)) {
		buffer_free_bulk(nicvf_get_pool(nic), len, bufs);
	} else {
		if (unlikely(len == 0))
			return;

		i = 0;
		do {
			prefetch_read_stream(bufs[i+1]);
			buffer_free_bulk(bufs[i]->pool, 1, &bufs[i]);
		} while(++i < n);
		buffer_free_bulk(bufs[n]->pool, 1, &bufs[n]);
	}
}

static OPTIMIZATION_XMIT size_t nicvf_qset_sq_recycle_desc(
	struct nicvf *nic, size_t qidx)
{
	struct snd_queue * __restrict__ sq = &nic->qdesc.sq[qidx];
	struct odp_buffer_hdr_t ** const __restrict__ bufs_used = sq->bufs_used;
	union sq_entry_t * const __restrict__ desc_ptr = sq->desc;
	union scatt_idx cons_head;
	union scatt_idx cons_next;
	union scatt_idx to_free;
	uint32_t hw_head;
	const uint32_t qlen = sq->desc_cnt;
	const uint32_t qlen_mask = (sq->desc_cnt - 1);
#ifdef NIC_QUEUE_STATS
	struct sq_stats_t * __restrict__ sq_stats =
		&nic->qdesc.sq[qidx].stats[odp_thread_id()];
#endif

#ifdef NIC_QUEUE_STATS
	sq_stats->sq_handler_calls++;
#endif

/* step 1 - atomic move of head - reservation of reclaim process */
	do {
		cons_head.val = __atomic_load_n(&sq->cons.head.val, __ATOMIC_ACQUIRE);
		hw_head = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_SQ_0_7_HEAD) >> 4;

		to_free.desc = (hw_head - cons_head.desc) & qlen_mask;
		if (unlikely(to_free.desc == 0))
			return 0;

		cons_next.desc = cons_head.desc + to_free.desc;
		/* to calculate memseg next we need to look at last
		 * sq.descriptor and extract the asosiated memseg index */
		cons_next.memseg = desc_ptr[(hw_head - 1) & qlen_mask].gather.rsvd0 + 1;
		to_free.memseg = (cons_next.memseg - cons_head.memseg) & qlen_mask;
#ifndef NIC_SQ_NONATOMIC
	} while (unlikely(!__atomic_compare_exchange_n(
			&sq->cons.head.val, &cons_head.val, cons_next.val,
			false /* strong */, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)));
#else
	__atomic_store_n(&sq->cons.head, cons_next, __ATOMIC_RELEASE);
	} while (0);
#endif
	/* just for development time .. verify that first gather descriptor
	 * (cons_head.desc + 1) has the same memseg idx as expected while basing
	 * on cons_head atomics */
	ODP_ASSERT((uint32_t)(desc_ptr[(cons_head.desc + 1) & qlen_mask].gather.rsvd0) ==
		   (cons_head.memseg & qlen_mask));

/* Step 2 - reclaim the descriptors */
#ifdef NIC_QUEUE_STATS
	uint64_t sq_count = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_SQ_0_7_STATUS) & 0xFFFF;
	nicvf_qset_sq_recycle_desc_stats(sq_stats, nic->epoh_curr, to_free.desc, sq_count);
#endif

	/* free already send buffers unless special config flag is set */
	if (likely(!(nic->cfg_flags & NICVF_CFGFLAG_NO_RECL_TX_BUFF))) {

		/* Iterate from sq->head to head module q size */
		if (unlikely((cons_head.memseg + to_free.memseg) & (~qlen_mask))) {
			/* buff free overlaps over ring */
			uint32_t first_free_cnt = qlen - cons_head.memseg;

			free_buffers(nic, sq, first_free_cnt,
				     &bufs_used[cons_head.memseg]);
			free_buffers(nic, sq, to_free.memseg - first_free_cnt,
				     &bufs_used[0]);
		} else {
			free_buffers(nic, sq, to_free.memseg,
				     &bufs_used[cons_head.memseg]);
		}
	}

/* step 3 - atomic move of producer tail - finalization */
	/* If there are other reclaim in progress that preceeded us,
	 * we need to wait for them to complete */
#ifndef NIC_SQ_NONATOMIC
	while (unlikely(__atomic_load_n(&sq->cons.tail.val, __ATOMIC_ACQUIRE) != cons_head.val))
		odp_cpu_pause();
#endif
	__atomic_store_n(&sq->cons.tail.val, cons_next.val, __ATOMIC_RELEASE);

	return to_free.desc;
}

/* Append an buff to a SQ for packet transfer */
static size_t OPTIMIZATION_XMIT nicvf_qset_sq_fill_desc(
	struct nicvf *nic,
	struct snd_queue *sq, union scatt_idx head,
	struct packet_hdr_t * const *pkts, size_t pkt_cnt)
{
	struct pool_entry_s *pool = nicvf_get_pool(nic);
	union sq_entry_t sqe;
	struct packet_hdr_t * __restrict__ seg;
	struct packet_hdr_t * __restrict__ pkt;
	union sq_entry_t * const __restrict__ desc_ptr = sq->desc;
	struct odp_buffer_hdr_t ** const __restrict__ bufs_used = sq->bufs_used;
	size_t seg_cnt;
	size_t pkt_i, seg_i;
	const uint32_t qlen_mask = (sq->desc_cnt - 1);
	uint32_t desc_idx = head.desc & qlen_mask;
	uint32_t buff_idx = head.memseg & qlen_mask;
	enum nicvf_cfg_flags cfg_flags = nic->cfg_flags;

	for (pkt_i = 0; likely(pkt_i < pkt_cnt); pkt_i++) {

		pkt = pkts[pkt_i];
		seg_cnt = pkt->buf_hdr.seg_count;

		/* Add SQ header subdesc */
		sqe.buff[0] = 0; sqe.buff[1] = 0;
		sqe.hdr.subdesc_type = SQ_DESC_TYPE_HEADER;
		sqe.hdr.post_cqe = 0; /* Disable notification via CQE after processing SQE */
		sqe.hdr.subdesc_cnt = seg_cnt; /* No of subdescriptors following this one */
		sqe.hdr.tot_len = pkt->total_len;

		/* instruct the HW to calculate the chksums in case pkt is IP */
		if ((cfg_flags & NICVF_CFGFLAG_CHCKSUM_IPV4) &&
		     packet_hdr_has_ipv4(pkt)) {
			sqe.hdr.csum_l3 = 1;
			sqe.hdr.l3_offset = pkt->hw.l3_offset;
			sqe.hdr.l4_offset = pkt->hw.l4_offset;
			if ((cfg_flags & NICVF_CFGFLAG_CHCKSUM_UDP) &&
			     packet_hdr_has_udp(pkt)) {
				sqe.hdr.csum_l4 = SEND_L4_CSUM_UDP;
			} else if ((cfg_flags & NICVF_CFGFLAG_CHCKSUM_TCP) &&
				    packet_hdr_has_tcp(pkt)) {
				sqe.hdr.csum_l4 = SEND_L4_CSUM_TCP;
			}
		}

		desc_ptr[desc_idx] = sqe;
		desc_idx = (desc_idx + 1) & qlen_mask;

		/* fill the segment's scatered descriptors */
		seg = pkt;
		seg_i = 0;
		do {
			void *virt;
			uint64_t phys;

			if (unlikely(seg->buf_hdr.pool != pool)) {
				sq->pool_poluted = 1;
				pool = seg->buf_hdr.pool;
				wmb();
			}

			/* Fill the SQ gather entry */
			sqe.buff[0] = 0; sqe.buff[1] = 0;
			sqe.gather.subdesc_type = SQ_DESC_TYPE_GATHER;
			sqe.gather.ld_type = 1;
			sqe.gather.rsvd0 = buff_idx; /* store index to assosiated memseg */
			sqe.gather.size = seg->segment_len;

			/* Store segment address for latter reclaim in sq_handler() */
			bufs_used[buff_idx] = &seg->buf_hdr;
			buff_idx = (buff_idx + 1) & qlen_mask;

			/* TODO: PERF: we should cache phys addr in buffer to speed up the following calculations */
			virt = (uint8_t *)seg->buf_hdr.data + seg->segment_offset;

			if (NICVF_TYPE_UIO == nic->nicvf_type)
				phys = odp_shm_phys_addr(pool->pool_buffer_shm, virt);
			else
				phys = (uint64_t)virt;
			sqe.gather.addr = phys;
			desc_ptr[desc_idx] = sqe;
			desc_idx = (desc_idx + 1) & qlen_mask;

			seg_i++;
			seg = (struct packet_hdr_t *)(seg->buf_hdr.next_seg);

		} while (unlikely(seg != NULL));

		ODP_ASSERT(seg_i == seg_cnt); /* inconsistent seg count */
	}

	return (desc_idx - head.desc) & qlen_mask;
}


static size_t OPTIMIZATION_XMIT nicvf_qset_sq_xmit(
	struct nicvf *nic, size_t qidx, struct packet_hdr_t * const *pkts,
	size_t pkt_cnt, uint64_t *out_est_cnt)
{
	struct snd_queue * __restrict__ sq = &nic->qdesc.sq[qidx];
#ifdef NIC_QUEUE_STATS
	struct sq_stats_t * __restrict__ sq_stats =
		&nic->qdesc.sq[qidx].stats[odp_thread_id()];
#endif
	union scatt_idx prod_head;
	union scatt_idx prod_next;
	union scatt_idx free_cnt;
	size_t i;
	size_t subdesc_cnt;
	size_t subdesc_cnt_ret;
	const uint32_t qlen_mask = (sq->desc_cnt - 1);

#ifdef NIC_QUEUE_STATS
	sq_stats->xmit_pkts_sum += pkt_cnt;
	sq_stats->xmit_calls++;
#endif
	/* no sense to prefetch packets since they are probably aleady in cache */

	/* count the number of needed subdescriptors needed to xmit all of the packets */
	subdesc_cnt = 0;
	for (i = 0; i < pkt_cnt; i++)
		subdesc_cnt += pkts[i]->buf_hdr.seg_count; /* header + number of segments */

/* step 1 - atomic move of head - reservation of space */
	do {
		union scatt_idx cons_tail;

		prod_head.val = __atomic_load_n(&sq->prod.head.val, __ATOMIC_ACQUIRE);
		cons_tail.val = __atomic_load_n(&sq->cons.tail.val, __ATOMIC_ACQUIRE);
		free_cnt.desc = qlen_mask + cons_tail.desc - prod_head.desc;
		//free_cnt.memseg = qlen_mask + cons_tail.memseg - prod_head.memseg;
		if (unlikely(subdesc_cnt + pkt_cnt > free_cnt.desc)) {
			/* not need to check (subdesc_cnt > free_cnt.memseg) */
			*out_est_cnt = qlen_mask - free_cnt.desc;
			return 0; /* no space in SQ to store all pkt descriptors */
		}
		prod_next.desc = prod_head.desc + subdesc_cnt + pkt_cnt;
		prod_next.memseg = prod_head.memseg + subdesc_cnt;
#ifndef NIC_SQ_NONATOMIC
	} while (unlikely(!__atomic_compare_exchange_n(
			&sq->prod.head.val, &prod_head.val, prod_next.val,
			false /* strong */, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)));
#else
	__atomic_store_n(&sq->prod.head.val, prod_next.val, __ATOMIC_RELEASE);
	} while (0);
#endif
	*out_est_cnt = qlen_mask - free_cnt.desc;

/* Step 2 - fill the descriptors */
	subdesc_cnt_ret = nicvf_qset_sq_fill_desc(nic, sq, prod_head,
						  pkts, pkt_cnt);
	ODP_ASSERT(subdesc_cnt + pkt_cnt == subdesc_cnt_ret); /* nicvf_qset_sq_fill_desc() failed */

/* step 3 - atomic move of producer tail - finalization */
	/* If there are other enqueues in progress that preceeded us,
	 * we need to wait for them to complete */
#ifndef NIC_SQ_NONATOMIC
	while (unlikely(__atomic_load_n(&sq->prod.tail.val, __ATOMIC_ACQUIRE) != prod_head.val))
		odp_cpu_pause();
#endif

	/* make sure all memory stores are done before ringing doorbell then
	 * ring it (Inform HW to xmit new packet) */
	wmb();
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_SQ_0_7_DOOR, subdesc_cnt + pkt_cnt);

	/* Finaly we may anounce the world that both descriptors and HW is set
	 * up and we finished our work (now it is their turn) */
	__atomic_store_n(&sq->prod.tail.val, prod_next.val, __ATOMIC_RELEASE);

	return pkt_cnt;
}

size_t OPTIMIZATION_XMIT nicvf_xmit(
	struct nicvf *nic, size_t qidx, struct packet_hdr_t * const *pkt,
	size_t pkt_cnt)
{
	struct snd_queue * __restrict__ sq = &nic->qdesc.sq[qidx];
	size_t pkt_sent;
	uint64_t est_cnt;
	uint64_t recycle_time;
	uint64_t recycle_time_prev;

	if (unlikely(pkt_cnt == 0))
		return 0; /* nothing to send */

	/* first try to send packets and get the estimated number of packets inside SQ */
	pkt_sent = nicvf_qset_sq_xmit(nic, qidx, pkt, pkt_cnt, &est_cnt);

	/* is esimated number of packet in SQ is above threshold then there is a
	 * chance that some of them were already xmited by HW. Lest try to
	 * recycle some of those packets back to buffer pool (cache) */
	if (unlikely(est_cnt > SQ_HANDLE_THRESHOLD)) {
		recycle_time_prev = __atomic_load_n(&sq->recycle_time, __ATOMIC_ACQUIRE);
		recycle_time = odp_cpu_cycles();
		/* since recycle require access to HW registers do not try to do
		 * that more frequent than SQ_HANDLE_CYCLEGUARD.
		 * Additionaly if SQ_HANDLE_GUARD is meet, prevent race of
		 * handling recycle from different CPU by using atomic CAS
		 * operation (update of sq->recycle_time). If CAS failed it
		 * means that some other thread done the recycle in the same
		 * time and our current thread does not have to repeat this
		 * process */
		if ( ((recycle_time - recycle_time_prev) > SQ_HANDLE_CYCLEGUARD) &&
		     (__atomic_compare_exchange_n(
			&sq->recycle_time, &recycle_time_prev, recycle_time,
			false /* strong */, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) ) {
				/* handle the recycling is called here */
				(void)nicvf_qset_sq_recycle_desc(nic, qidx);
		}
	}

	return pkt_sent;
}

/* *****************************************************************************
 * Receive queue function
 * *****************************************************************************/

static int nicvf_qset_rq_reclaim(struct queue_set *qset)
{
	return nicvf_mbox_rq_sync(qset);
}

/* Updates the RQ hardware registers */
static int nicvf_qset_rq_config(struct nicvf *nic, size_t qidx, bool enable)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct rcv_queue *rq = &(nic->qdesc.rq[qidx]);
	struct rq_cfg rq_cfg;
	size_t qirem = qidx % MAX_QUEUES_PER_QSET;
	uint8_t vf_id = qset->vf_id;

	/* Disable receive queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_RQ_0_7_CFG, 0);

	rq->enable = enable;
	if (!enable) {
		return nicvf_qset_rq_reclaim(qset);
	}

	NFO("Configuring RQ qidx=%zu using vnic_id %"PRIu8"\n", qidx, vf_id);
	rq->cq_qs = vf_id;
	rq->cq_idx = qirem; /* 1 to 1 assigment in the same QSET */
	rq->start_rbdr_qs = vf_id;
	rq->start_qs_rbdr_idx = 0; /* all RQ use the same RBDR[0] */
	rq->cont_rbdr_qs = vf_id;
	rq->cont_qs_rbdr_idx = 0;
	/* all writes to data payload pointed by RBDR will be allocated into L2C */
        rq->caching = RQ_CACHE_ALLOC_FIRST;

	/* Send a mailbox msg to PF to config RQ */
	if (nicvf_mbox_rq_config(nic, qidx)) {
		ERR("Error on nicvf_mbox_rq_config\n");
		return -1;
	}

	if (nicvf_mbox_rq_bp_cfg(qset)) {
		ERR("Error on nicvf_mbox_rq_bp_cfg\n");
		return -1;
	}

	/* Send a mailbox msg to PF to config RQ drop */
	if (nicvf_mbox_drop_config(nic, qidx)) {
		ERR("Error on nicvf_mbox_drop_config\n");
		return -1;
	}

	/* Enable Receive queue */
	rq_cfg = (struct rq_cfg) {
		.ena = 1,
	};
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_RQ_0_7_CFG, rq_cfg.value);
	/* Set the value of RQ_GEN_CFG to: LEN_L3 | LEN_L4 | CSUM_L4,
	 * thus enable L4 checksum verification and L3/L4 lengh checks.
	 * */
	DBG("NIC_QSET_RQ_GEN_CFG = %"PRIx64"\n", nicvf_qidx_reg_read(nic, qidx, NIC_QSET_RQ_GEN_CFG));
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_RQ_GEN_CFG ,0x1a00000);

	return 0;
}

__attribute__ ((pure))
static inline size_t frag_num(size_t i)
{
#if defined(__BIG_ENDIAN_BITFIELD)
        return (i & ~3) + 3 - (i & 3);
#else
        return i;
#endif
}

static void nicvf_qset_rq_handler_pkterror(
	struct cqe_rx_t *cqe_rx, struct packet_hdr_t *pkt, uint8_t rbptr_offset)
{
	uint16_t *rb_sz;
	uint64_t *rb_ptr;
	uint64_t phys;
	size_t segsize;
	size_t frag;

	/* Note that his if acts as preprocessor because
	 * DEBUG is a constant */
	if (DEBUG >= 3) {
		ERR("RX_PKT pkt_len %"PRIu16" rb_cnt %d level=%d opcode=%x\n",
		    cqe_rx->w1.pkt_len, cqe_rx->w0.rb_cnt, cqe_rx->w0.err_level, cqe_rx->w0.err_opcode);

		rb_sz = &(cqe_rx->rb0_sz);
		rb_ptr = (uint64_t *)cqe_rx + rbptr_offset;
		for (frag = 0; frag < cqe_rx->w0.rb_cnt; frag++) {
			phys = rb_ptr[frag] - ((0 == frag) ?
				cqe_rx->w1.align_pad : 0);
			segsize = rb_sz[frag_num(frag)];

			ERR("RX_PKT fragment %zu data=%p size=%zu\n",
			      frag, (void*)phys, segsize);
		}
	}
	/* Data mismatch erorrs will be handled by upper layers*/
	switch (cqe_rx->w0.err_level) {
		case 0x01:
			pkt->hw.error_flags.l2_chksum = 1;
			break;
		case 0x02:
			pkt->hw.error_flags.ip_err = 1;
			break;
		case 0x03:
			pkt->hw.error_flags.tcp_err = 1;
			pkt->hw.error_flags.udp_err = 1;
			break;
		default:
			pkt->hw.error_flags.l1_err = 1;
			break;
	}
}

static size_t OPTIMIZATION_RECV nicvf_qset_rq_handler_fixaddr_prefetch(
	struct nicvf * const nic,
	struct cqe_rx_t * const cqe_rx,
	odp_shm_t pool_buffer_shm,
	const size_t offset)
{
	struct odp_buffer_hdr_t* buf;
	uint16_t *rb_sz;
	uint64_t *rb_ptr;
	uint64_t phys;
	void* virt;
	size_t segsize;
	const size_t seg_cnt = cqe_rx->w0.rb_cnt;

	ODP_ASSERT(cqe_rx->w1.cq_pkt_len == 0); /* RX_PKT direct packet handling in CQ not supported! */
	ODP_ASSERT(seg_cnt != 0); /* RX_PKT pkt without buffers */

	rb_sz = &(cqe_rx->rb0_sz);
	rb_ptr = (uint64_t *)cqe_rx + nic->rbptr_offset;

	/* for first segment ... */
	phys = rb_ptr[0] - cqe_rx->w1.align_pad;
	segsize = rb_sz[frag_num(0)];
	ODP_ASSERT(0 != segsize && 0 != phys);

	/* map from phys to virt */
	if (NICVF_TYPE_UIO == nic->nicvf_type) {
		virt = odp_shm_virt_addr(pool_buffer_shm, phys);
	} else {
		virt = (void*)phys;
	}

	buf = nicvf_buffer_from_ptr(virt, offset);
	prefetch_store_keep(buf); /* prefetch buf header */

	/* fix buf addr in cqe_rx */
	rb_ptr[0] = (uint64_t)buf;

	/* for following segments ... */
	if (unlikely(seg_cnt > 1)) {
		size_t seg_i = 1;
		do {
			phys = rb_ptr[seg_i];
			segsize = rb_sz[frag_num(seg_i)];
			ODP_ASSERT(0 != segsize && 0 != phys);

			/* map from phys to virt */
			if (NICVF_TYPE_UIO == nic->nicvf_type) {
				virt = odp_shm_virt_addr(pool_buffer_shm, phys);
			} else {
				virt = (void*)phys;
			}

			buf = nicvf_buffer_from_ptr(virt, offset);

			/* fix buf addr in cqe_rx */
			rb_ptr[seg_i] = (uint64_t)buf;
		} while (++seg_i < seg_cnt);
	}

	return seg_cnt;
}

static struct packet_hdr_t* OPTIMIZATION_RECV nicvf_qset_rq_handler_retpkt(
	struct cqe_rx_t * __restrict__ cqe_rx,
	const size_t headroom, uint8_t rbptr_offset)
{
	struct packet_hdr_t * __restrict__ head;
	struct packet_hdr_t * __restrict__ pkt;
	struct w0_struct_t cqe_rx_w0 = cqe_rx->w0;
	struct w1_struct_t cqe_rx_w1 = cqe_rx->w1;
	struct w2_struct_t cqe_rx_w2 = cqe_rx->w2;
	size_t seg_cnt;
	uint16_t *rb_sz;
	uint64_t *rb_ptr;

	/* helper variables for segment sizes and pointers as a table */
	rb_sz = &(cqe_rx->rb0_sz);
	rb_ptr = (uint64_t *)cqe_rx + rbptr_offset;

	/* look at nicvf_qset_rq_handler_fixaddr_prefetch to see how buffer
	 * header addresses where corrected */
	pkt = (struct packet_hdr_t*)(rb_ptr[0]);

	/* for first segment ... */
	pkt->segment_len = rb_sz[frag_num(0)];
	pkt->segment_offset = headroom + cqe_rx_w1.align_pad;
	pkt->buf_hdr.next_seg = NULL;

	struct pkt_hw_fields_t hw;
	hw.error_flags.all = 0;
#ifndef NIC_DISABLE_PACKET_PARSING
	hw.l2_offset = cqe_rx_w1.l2_ptr;
	hw.l3_offset = cqe_rx_w1.l3_ptr;
	hw.l4_offset = cqe_rx_w1.l4_ptr;

	hw.input_flags.l2_flags.l2_pressent = cqe_rx_w0.l2_present;
	hw.input_flags.l2_flags.l2_vlan_pressent = cqe_rx_w0.vlan_found;
	hw.input_flags.l3_type = cqe_rx_w0.l3_type;
	hw.input_flags.l4_type = cqe_rx_w0.l4_type;
#endif
	pkt->hw = hw;

#if (DEBUG >= 4)
	nicvf_dump_packet((int8_t *)pkt->buf_hdr.data + pkt->segment_offset,
			  pkt->segment_len);
#endif

	seg_cnt = cqe_rx_w0.rb_cnt;
	head = pkt;
	if (unlikely(seg_cnt > 1)) {
		/* for following segments ... */
		struct packet_hdr_t * __restrict__ prev = head;
		size_t seg_i = 1;
		uint16_t segsize;

		do {
			pkt = (struct packet_hdr_t*)(rb_ptr[seg_i]);
			segsize = rb_sz[frag_num(seg_i)];
#if (DEBUG >= 4)
			nicvf_dump_packet((int8_t *)pkt->buf_hdr.data + headroom, segsize);
#endif

			pkt->segment_len = segsize;
			pkt->segment_offset = headroom;
			pkt->buf_hdr.next_seg = NULL;
			prev->buf_hdr.next_seg = &pkt->buf_hdr;
			prev = pkt;
		} while (++seg_i < seg_cnt);
	}

	head->buf_hdr.seg_count = seg_cnt;
	head->buf_hdr.total_size = seg_cnt * head->buf_hdr.data_size;
	head->total_len = cqe_rx_w1.pkt_len;
	head->last = pkt;

	/* Check for errors and set error flags*/
	if (unlikely(cqe_rx_w0.err_level || cqe_rx_w0.err_opcode)) {
		nicvf_qset_rq_handler_pkterror(cqe_rx, head, rbptr_offset);
	}

	head->rss_alg = cqe_rx_w0.rss_alg;
	head->rss_tag = cqe_rx_w2.rss_tag;

	/* report that CQ was sucessfully handled and we can advance to next CQ */
	return head;
}

/* *****************************************************************************
 * Completion queue function
 * *****************************************************************************/

static int nicvf_qset_cq_alloc(struct nicvf *nic, size_t qidx, size_t desc_cnt)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct cmp_queue *cq = &(nic->qdesc.cq[qidx]);
	void* virt;
	char name[20];

	snprintf(name, sizeof(name), "%"PRIu8".CQ[%zd]", qset->vf_id, qidx);

	/* Allocate memory for RBDR descriptors */
	virt = nicvf_mem_alloc(nic, &cq->mem_desc,
			       desc_cnt * sizeof(union cq_entry_t),
			       NICVF_CQ_BASE_ALIGN_BYTES, name);
	if (!virt) {
		ERR("Unable to allocate memory for competition ring\n");
		return -ENOMEM;
	}
	cq->desc = virt;
	cq->desc_cnt = desc_cnt;
	cq->prod_tail = 0;
	cq->cons.head.val = 0;
	cq->cons.tail.val = 0;
	cq->rbdr_refill_mark = 0;

	return 0;
}

static void nicvf_qset_cq_free(struct nicvf *nic, size_t qidx)
{
	struct cmp_queue *cq = &(nic->qdesc.cq[qidx]);

	cq->enable = false;
	if (!cq->desc)
		return;

	nicvf_mem_free(nic, &cq->mem_desc);
}

static int nicvf_qset_cq_reclaim(struct nicvf *nic, size_t qidx)
{
	/* Disable timer threshold (doesn't get reset upon CQ reset */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG2, 0);
	/* Disable completion queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG, 0);
	/* TODO we should pool for disable somehow */
	/* Reset completion queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG, NICVF_CQ_RESET);
	/* TODO should we poll for for reset completion ? */

	return 0;
}

/* Updates the CQ hardware registers */
static int nicvf_qset_cq_config(struct nicvf *nic, size_t qidx, bool enable)
{
	struct cmp_queue *cq = &(nic->qdesc.cq[qidx]);
	struct cq_cfg cq_cfg;

	cq->enable = enable;
	if (!enable) {
		return nicvf_qset_cq_reclaim(nic, qidx);
	}

	/* TODO PRIO there is some inconsistency compared to other queues ... seems that now we reset twice ... make it more consistent with other queues */
	/* Reset completion queue */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG, NICVF_CQ_RESET);

	/* Set completion queue base address */
	NFO("Configuring CQ BASE as 0x%"PRIx64"\n",
	    (uint64_t)(cq->mem_desc.phys));
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_BASE,
			      (uint64_t)(cq->mem_desc.phys));

	/* Set CQ's head entry */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_HEAD, 0);

	uint64_t tail = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_CQ_0_7_TAIL) >> 9;
	uint64_t head = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_CQ_0_7_HEAD) >> 9;
	ODP_ASSERT(tail == 0);
	ODP_ASSERT(head == 0);

	cq->prod_tail = 0;
	cq->cons.head.val = 0;
	cq->cons.tail.val = 0;
	cq->rbdr_refill_mark = 0;

	/* Enable Completion queue */
	cq_cfg = (struct cq_cfg) {
		.ena = 1,
		.reset = 0,
		.caching = 1, /* Writes of CQE will be allocated into L2C */
		.qsize = ctz(cq->desc_cnt >> CMP_QSIZE_SHIFT),
		.avg_con = 0,
	};

	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG, cq_cfg.value);

	/* Set threshold value for interrupt generation */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_THRESH, 0); /* no interrupt usage */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_CFG2, 0); /* no interrupt usage */

	return 0;
}

#ifdef NIC_QUEUE_STATS
static void OPTIMIZATION_RECV nicvf_qset_cq_handler_stats(
	struct cq_stats_t * __restrict__ cq_stats,
	uint64_t epoh_curr, uint64_t hw_count)
{
	if (unlikely(epoh_curr != cq_stats->epoh_last)) {
		cq_stats->cq_count_max = 0;
		cq_stats->cq_count_min = UINT64_MAX;
		cq_stats->cq_count_sum = 0;
		cq_stats->probes_cnt = 0;
		cq_stats->cq_handler_calls = 0;
		cq_stats->epoh_last = epoh_curr;
	}
	cq_stats->cq_count_max = max(cq_stats->cq_count_max, hw_count);
	cq_stats->cq_count_min = min(cq_stats->cq_count_min, hw_count);
	cq_stats->cq_count_sum += hw_count;
	(cq_stats->probes_cnt)++;
}
#endif

/* Process the CQ recently updated/given by HW */
size_t OPTIMIZATION_RECV nicvf_qset_cq_handler(
	struct nicvf *nic, size_t qidx,
	struct packet_hdr_t* pkt_table[], uint32_t budget,
	union scatt_idx *last_idx)
{
	struct cmp_queue * const __restrict__ cq = &(nic->qdesc.cq[qidx]);
	union cq_entry_t * const __restrict__ desc = cq->desc;
	union cq_entry_t * __restrict__ cq_entry;
	struct cqe_rx_t * __restrict__ cqe_rx;
#ifdef NIC_QUEUE_STATS
	struct cq_stats_t * __restrict__ cq_stats =
		&nic->qdesc.cq[qidx].stats[odp_thread_id()];
#endif
	struct pool_entry_s * const pool = nicvf_get_pool(nic);
	union scatt_idx cons_head;
	union scatt_idx cons_next;
	union scatt_idx cons_tail;
	uint32_t prod_tail;
	uint32_t prod_tail_prev;
	uint32_t hw_tail;
	uint32_t cqe_head;
	const uint32_t cqe_mask = cq->desc_cnt - 1;
	uint32_t to_process;
	uint32_t i;
	uint32_t seg_cnt;

#ifdef NIC_QUEUE_STATS
	cq_stats->cq_handler_calls++;
#endif

/* step 1 - atomic move of head - reservation (atomic move cons.head) of CQE to be handled */
	do {
		cons_head.val = __atomic_load_n(&cq->cons.head.val, __ATOMIC_ACQUIRE);

		do {
			/* only portion of CQE will be handled (budget),
			 * because of that there is no sense to read the HW TAIL
			 * register each time, let use shadow-copy of last read
			 * value and calculate the antries count on that */
			prod_tail = __atomic_load_n(&cq->prod_tail, __ATOMIC_ACQUIRE);
			to_process = (prod_tail - cons_head.desc) & cqe_mask;

/* step 1.1 - atomic update of prod.tail shadow-copy of NIC_QSET_CQ_0_7_TAIL */
			/* if the entries count is less than current budget than
			 * it means that we need to update the shadow-copy */
			if (likely(to_process > budget))
				break; /* do not update SW shadow tail */

			prod_tail_prev = prod_tail;
			hw_tail = nicvf_qidx_reg_read(nic, qidx, NIC_QSET_CQ_0_7_TAIL) >> 9;
			/* tail from HW is given as modulo queue size, while SW
			 * tail and head are keep monotonic, therefore we need
			 * to calculate how many elements where added to queue
			 * from time we last checked the HW tail and increment
			 * SW tail shadow by the same amount */
			prod_tail += (hw_tail - prod_tail_prev) & cqe_mask;
			/* recalculate to_process again */
			to_process = (prod_tail - cons_head.desc) & cqe_mask;

/* step 1.2 when reading HW also update statistics */
#ifdef NIC_QUEUE_STATS
			uint64_t hw_count = nicvf_qidx_reg_read(
				nic, qidx, NIC_QSET_CQ_0_7_STATUS) & CQ_CQE_COUNT_MASK;
			nicvf_qset_cq_handler_stats(cq_stats, nic->epoh_curr, hw_count);
#endif

			/* atomicly update the shadow prod_tail */
		} while (unlikely(!__atomic_compare_exchange_n(
				&cq->prod_tail, &prod_tail_prev, prod_tail,
				false /* strong */, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)));
/* end of step 1.1 */

		/* prefetch CQE to L1C, they is HW assisted precharge to L2C */
		prefetch_read_stream(&(desc[cons_head.desc & cqe_mask]));

		/* in case of 0 CQE to process do not try to CAS the cons.head */
		if (0 == to_process) {
			*last_idx = cons_head;
			return 0;
		}

		/* limit to given budget */
		to_process = min(to_process, budget);
		cons_next.desc = cons_head.desc + to_process;
		cons_next.memseg = 0; /* not known yet, look at update of cq->cons.tail */
	} while (unlikely(!__atomic_compare_exchange_n(
			&cq->cons.head.val, &cons_head.val, cons_next.val,
			false /* strong */, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)));
/* end of step 1 */

/* step 2 - the actual handling of CQE's */

	/* recalculate packet buffers pointers from CQE's but do not touch memory of packets */
	odp_shm_t pool_buffer_shm = pool->pool_buffer_shm;
	const size_t offset = nicvf_buffer_from_ptr_offset(pool);
	cqe_head = cons_head.desc & cqe_mask;
	i = 0;
	seg_cnt = 0;
	do { /* to_process > 0 then so we can use do .. while */
		cq_entry = &(desc[cqe_head]);
		cqe_head = (cqe_head + 1) & cqe_mask;
		prefetch_read_stream(&(desc[cqe_head])); /* prefetch next CQE to L1C */

		/* in the past we checked if cq_entry->type.cqe_type == CQE_TYPE_RX
		 * and stored index to such elements with cqe_rx_valid[to_receive++] = (uint16_t)cqe_head
		 * recently we assume that all cqe are TYPE_RX and we do not
		 * support other types, check the git history for legacy code */
		ODP_ASSERT(cq_entry->type.cqe_type == CQE_TYPE_RX); /* CQE other than CQE_TYPE_RX */

		/* calculate buffer header address and prefetch to memory
		 * accumulate number of received segments */
		seg_cnt += nicvf_qset_rq_handler_fixaddr_prefetch(
			nic, &cq_entry->rx_hdr, pool_buffer_shm, offset);

	} while (++i < to_process);

	/* all buffers are now prefetched to L1, join buffers into packets */
	cqe_head = cons_head.desc & cqe_mask;
	const size_t headroom = pool->pkt_alloc.headroom;
	i = 0;
	do { /* to_process > 0 then so we can use do .. while */
		cqe_rx = &(desc[cqe_head].rx_hdr);
		cqe_head = (cqe_head + 1) & cqe_mask;
		pkt_table[i] = nicvf_qset_rq_handler_retpkt(cqe_rx, headroom, nic->rbptr_offset);
	} while (++i < to_process);

/* step 3 - atomic move of consumer tail - finalization */
	/* If there are other handling in progress that preceeded us,
	 * we need to wait for them to complete */
	for(;;) {
		cons_tail.val = __atomic_load_n(&cq->cons.tail.val, __ATOMIC_ACQUIRE);
		/* check only desc index since memseg index is used only for
		 * purpose of segment number tracking */
		if (likely(cons_tail.desc == cons_head.desc))
			break;
		odp_cpu_pause(); /* idle in case of wait cycle */
	}

	/* Ring doorbell to inform H/W to reuse processed CQEs */
	nicvf_qidx_reg_write(nic, qidx, NIC_QSET_CQ_0_7_DOOR, to_process);

	/* Finaly we may anounce the world that we finished our work (now it is their turn)
	 * Update the number of received segments in memseg index */
	cons_next.memseg = cons_tail.memseg + seg_cnt;
	__atomic_store_n(&cq->cons.tail.val, cons_next.val, __ATOMIC_RELEASE);

	/* exit code */
	*last_idx = cons_next;
	return to_process; /* work_done is the number of received packets */
}

size_t OPTIMIZATION_RECV nicvf_recv(
	struct nicvf *nic, size_t qidx, struct packet_hdr_t *pkt_table[],
	size_t budget, uint64_t *order)
{
	struct cmp_queue * __restrict__ cq = &(nic->qdesc.cq[qidx]);
	size_t recv_pkts;
	union scatt_idx last_idx;
	uint32_t rbdr_refill_mark, rbdr_refill_mark_next;
	uint32_t to_refill;
	uint32_t refill_cnt;

	/* get mark when most recent RBDR refill was done */
	rbdr_refill_mark = __atomic_load_n(&cq->rbdr_refill_mark, __ATOMIC_ACQUIRE);

	/* receive packets and get current mark of CQ (cq_tail) */
	recv_pkts = nicvf_qset_cq_handler(nic, qidx, pkt_table, budget, &last_idx);
	/* FIXME: Account for multi-segment packets */
	*order = last_idx.desc - recv_pkts;

	/* now calculate if it is the right time to refill RBDR
	 * with cq_tail and rbdr_refill_mark we can estimate when we should try to
	 * refill the RBDR using only the local-cache from buffer allocator
	 * (without touching global pool). The whole thing is based on fact that
	 * processed buffers are temporarly stored in local-cache after being
	 * processed and freed, and this is the fastest source of buffers used
	 * for RBDR refill */
	to_refill = abs_diff(last_idx.memseg, rbdr_refill_mark);
	if (unlikely((recv_pkts > 0) &&
		     (to_refill > RQ_HANDLE_THRESHOLD))) {

		/* we assume that we will be able to refill whole RBDR from
		 * local cache. Therefore we set the next mark to current +
		 * to_refill and modify it by CAS. In case local cache didn't
		 * had enough free buffers and we refilled only a part of RBDR
		 * we fix the mark in second CAS (this should not happen often) */
		rbdr_refill_mark_next = rbdr_refill_mark + to_refill;
		if (__atomic_compare_exchange_n(
			&cq->rbdr_refill_mark, &rbdr_refill_mark, rbdr_refill_mark_next,
			false /* strong */, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {

				size_t rbdr_idx = (qidx / MAX_QUEUES_PER_QSET) * MAX_RBDR_PER_QSET;
				/* refill RBDR and get the exact number of filled bufers */
				refill_cnt = nicvf_qset_rbdr_refill(nic, rbdr_idx, to_refill);
				/* check if we had to correct the rbdr_refill_mark */
				if (unlikely(to_refill != refill_cnt)) {

					/* since we didnt refilled RBDR as much
					 * as expected, we have to correct the
					 * rbdr_refill_mark a bit back */
					do {
						rbdr_refill_mark = __atomic_load_n(&cq->rbdr_refill_mark, __ATOMIC_ACQUIRE);
						rbdr_refill_mark_next = rbdr_refill_mark - (to_refill - refill_cnt);
					} while (!__atomic_compare_exchange_n(
							&cq->rbdr_refill_mark, &rbdr_refill_mark, rbdr_refill_mark_next,
							false /* strong */, __ATOMIC_RELEASE, __ATOMIC_RELAXED));
				}
		}
	}

	return recv_pkts;
}

/* *****************************************************************************
 * Whole queue set functiions
 * *****************************************************************************/

int nicvf_qset_rxq_enable(struct nicvf *nic)
{
	struct queue_set *qset;
	size_t qidx;
	int ret;

	ret = pthread_spin_lock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */

	/* allocate free queue */
	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {
		if (!nicvf_rxq_active(nic, qidx))
			break;
	}
	if (qidx == MAX_QUEUES_PER_NIC)
		goto err_alloc;

	qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];

	if (nicvf_qset_cq_config(nic, qidx, true)) {
		ERR("Error while configuring %zu CMP\n", qidx);
		goto err_cq;
	}

	if (nicvf_qset_rq_config(nic, qidx, true)) {
		ERR("Error while configuring %zu RCV\n", qidx);
		goto err_rq;
	}

	nicvf_rxq_switch(nic, qidx, true);

	if (nicvf_mbox_config_cpi(qset->nic)) {
		ERR("Cannot configure CPI\n");
		goto err_cpi;
	}

#ifdef VNIC_RSS_SUPPORT
	/* Configure receive side scaling */
	if (nicvf_rss_init(qset->nic)) {
		ERR("Cannot configure RSS\n");
		goto err_rss;
	}
#endif

#ifdef NIC_QUEUE_STATS
	size_t i;

	nic->epoh_curr = 0;
	memset(&nic->qdesc.cq[qidx].stats, 0, sizeof(struct cq_stats_t) * ODP_THREAD_COUNT_MAX);
	memset(&nic->qdesc.rbdr[0].stats, 0, sizeof(struct rbdr_stats_t) * ODP_THREAD_COUNT_MAX);
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		nic->qdesc.cq[qidx].stats[i].cq_count_min = UINT64_MAX;
		nic->qdesc.rbdr[0].stats[i].free_min = UINT64_MAX;
		nic->qdesc.rbdr[0].stats[i].lbuf_min = UINT64_MAX;
	}

	/* initialize hw_stats snapshot so we did not get garbadge at first stat diff */
	nicvf_stathw_get(qset, &qset->last_hw_stats);
#endif
	nicvf_mbox_config_done(qset);

	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return qidx;

err_rss:
	nicvf_rxq_switch(nic, qidx, false);
	if (nicvf_mbox_config_cpi(qset->nic)) {
		ERR("Error while bailout: cpi_config()\n");
	}
err_cpi:
	if (nicvf_qset_rq_config(nic, qidx, false)) {
		ERR("Error while bailout: rq_config(disable)\n");
	}
err_rq:
	if (nicvf_qset_cq_config(nic, qidx, false)) {
		ERR("Error while bailout: cq_config(disable)\n");
	}
err_cq:
err_alloc:
	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return -1;
}

int nicvf_qset_txq_enable(struct nicvf *nic)
{
	struct queue_set *qset;
	size_t qidx;
	int ret;

	ret = pthread_spin_lock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */

	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {
		if (!nicvf_txq_active(nic, qidx))
			break;
	}
	if (qidx == MAX_QUEUES_PER_NIC)
		goto err_alloc;

	qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];

	if (nicvf_qset_sq_config(nic, qidx, true)) {
		ERR("Error while configuring %zu SND\n", qidx);
		goto err_sq;
	}

	nicvf_txq_switch(nic, qidx, true);

#ifdef NIC_QUEUE_STATS
	size_t i;

	nic->epoh_curr = 0;
	memset(&nic->qdesc.sq[qidx].stats, 0, sizeof(struct sq_stats_t) * ODP_THREAD_COUNT_MAX);
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		nic->qdesc.sq[qidx].stats[i].sq_recl_min = UINT64_MAX;
		nic->qdesc.sq[qidx].stats[i].sq_count_min = UINT64_MAX;
	}

	/* initialize hw_stats snapshot so we did not get garbadge at first stat diff */
	nicvf_stathw_get(qset, &qset->last_hw_stats);
#endif
	nicvf_mbox_config_done(qset);

	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return qidx;

err_sq:
err_alloc:
	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return -1;
}

int nicvf_qset_rxq_disable(struct nicvf *nic, size_t qidx)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	bool err = false;
	int ret;

	ret = pthread_spin_lock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */

	if (!nicvf_rxq_active(nic, qidx)) {
		ERR("Queue was not active\n");
		goto err_earl;
	}

	if (nicvf_qset_rq_config(nic, qidx, false)) {
		ERR("Error while configuring %zu RCV\n", qidx);
		err = true;
	}

	if (nicvf_qset_cq_config(nic, qidx, false)) {
		ERR("Error while configuring %zu CMP\n", qidx);
		err = true;
	}

	nicvf_rxq_switch(nic, qidx, false);

	/* TODO reclaim not consumed RX packets */

	if (nicvf_mbox_config_cpi(qset->nic)) {
		ERR("Cannot configure CPI\n");
		err = true;
	}

#ifdef VNIC_RSS_SUPPORT
	if (nicvf_rss_init(qset->nic)) {
		ERR("Cannot configure RSS\n");
		err = true;
	}
#endif

	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return (err) ? -1 : 0;

err_earl:
	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return -1;
}

int nicvf_qset_txq_disable(struct nicvf *nic, size_t qidx)
{
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	bool err = false;
	int ret;

	ret = pthread_spin_lock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */

	if (!nicvf_txq_active(nic, qidx)) {
		ERR("Queue was not active\n");
		goto err_earl;
	}

	if (nicvf_qset_sq_config(nic, qidx, false)) {
		ERR("Error while configuring %zu SND\n", qidx);
		err = true;
	}

	nicvf_txq_switch(nic, qidx, false);

	if (nicvf_mbox_config_cpi(qset->nic)) {
		ERR("Cannot configure CPI\n");
		err = true;
	}

#ifdef VNIC_RSS_SUPPORT
	if (nicvf_rss_init(qset->nic)) {
		ERR("Cannot configure RSS\n");
		err = true;
	}
#endif

	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return (err) ? -1 : 0;

err_earl:
	ret = pthread_spin_unlock(&nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return -1;
}

int nicvf_qset_triplet_disableall(struct queue_set *qset)
{
	bool err = false;
	size_t qidx, rbdr_idx, qset_idx;
	int ret;

	ret = pthread_spin_lock(&qset->nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */

	qset_idx = qset->qset_idx;

	/* allocate free queue triplet */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {

		if (nicvf_rxq_active(qset->nic, qidx)) {

			if (nicvf_qset_rq_config(qset->nic, qidx, false)) {
				ERR("Error while configuring %zu RCV\n", qidx);
				err = true;
			}


			if (nicvf_qset_cq_config(qset->nic, qidx, false)) {
				ERR("Error while configuring %zu CMP\n", qidx);
				err = true;
			}

			nicvf_rxq_switch(qset->nic, qidx, false);
		}

		if (nicvf_txq_active(qset->nic, qidx)) {

			if (nicvf_qset_sq_config(qset->nic, qidx, false)) {
				ERR("Error while configuring %zu SND\n", qidx);
				err = true;
			}

			nicvf_txq_switch(qset->nic, qidx, false);
		}
	}

	for (rbdr_idx = qset_idx * MAX_RBDR_PER_QSET;
	     rbdr_idx < (qset_idx + 1) * MAX_RBDR_PER_QSET;
	     rbdr_idx++) {
		if (nicvf_qset_rbdr_config(qset->nic, rbdr_idx, false)) {
			ERR("Error while configuring %zu RBDR\n", rbdr_idx);
			err = true;
		}
	}

	if (nicvf_mbox_config_cpi(qset->nic)) {
		ERR("Cannot configure CPI\n");
		err = true;
	}

#ifdef VNIC_RSS_SUPPORT
	/* Configure receive side scaling */
	if (nicvf_rss_init(qset->nic)) {
		ERR("Cannot configure RSS\n");
		err = true;
	}
#endif

	ret = pthread_spin_unlock(&qset->nic->qdesc.spin);
	ODP_ASSERT(0 == ret); /* call must not fail */
	return (err) ? -1 : 0;
}

int nicvf_qset_rxqtxq_disableall(struct nicvf *nic)
{
	size_t i;
	struct queue_set *qset;

	for (i = 0; i < nic->qset_cnt; i++) {

		qset = &nic->qset[i];

		if (qset->enable) {
			(void)nicvf_qset_triplet_disableall(qset);
		}
	}

	return 0;
}

/* Function allocates and initializes structures that shadows the QS resources
 * Here we are not touching HW registers */
static int nicvf_qset_alloc(struct queue_set *qset)
{
	struct pool_entry_s *pool = nicvf_get_pool(qset->nic);
	size_t rb_size;
	size_t qidx, rbdr_idx, qset_idx;

	qset_idx = qset->qset_idx;
	rb_size = buffer_segment_size(pool);
	ODP_ASSERT(0 == rb_size % 128); /* receive buffer size must be multiply of 128B */

	/* Alloc receive buffer descriptor ring */
	for (rbdr_idx = qset_idx * MAX_RBDR_PER_QSET;
	     rbdr_idx < (qset_idx + 1) * MAX_RBDR_PER_QSET;
	     rbdr_idx++) {
		if (nicvf_qset_rbdr_alloc(qset->nic, rbdr_idx, RCV_BUF_COUNT, rb_size)) {
			ERR("Error while allocating RBDR %zu\n", rbdr_idx);
			return -ENOMEM;
		}
	}

	/* Alloc send queue */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {
		if (nicvf_qset_sq_alloc(qset->nic, qidx, SND_QUEUE_LEN)) {
			ERR("Error while allocating SQ %zu\n", qidx);
			return -ENOMEM;
		}
	}

	/* Alloc completion queue */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {
		if (nicvf_qset_cq_alloc(qset->nic, qidx, CMP_QUEUE_LEN)) {
			ERR("Error while allocating CQ %zu\n", qidx);
			return -ENOMEM;
		}
	}

	return 0;
}

static void nicvf_qset_free(struct queue_set *qset)
{
	size_t qidx, rbdr_idx, qset_idx;

	qset_idx = qset->qset_idx;

	/* Free receive buffer descriptor ring */
	for (rbdr_idx = qset_idx * MAX_RBDR_PER_QSET;
	     rbdr_idx < (qset_idx + 1) * MAX_RBDR_PER_QSET;
	     rbdr_idx++) {
		nicvf_qset_rbdr_free(qset->nic, rbdr_idx);
	}

	/* Free send queue */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {
		nicvf_qset_sq_free(qset->nic, qidx);
	}

	/* Free completion queue */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {
		nicvf_qset_cq_free(qset->nic, qidx);
	}
}

void nicvf_qset_preinit(struct queue_set *qset)
{
	pthread_cond_init(&qset->mbx_cond, NULL);
	pthread_mutex_init(&qset->mbx_mutex, NULL);
	memset(&qset->mbx_msg, 0, sizeof(qset->mbx_msg));
}

/* Initialize queues and HW */
int nicvf_qset_init(struct queue_set *qset)
{
	int ret;

	ret = pthread_spin_init(&qset->nic->qdesc.spin, 0);
	ODP_ASSERT(0 == ret); /* call must not fail */

	if (!qset->enable ||
	    (NULL == qset->qset_reg_base)) {
		ERR("Qset must be initialized first by UIO or VFIO\n");
		return -1;
	}

	/* Allocate QS shadow structures */
	if (nicvf_qset_alloc(qset)) {
		ERR("Failed to alloc SQ shadow structures\n");
		goto err;
	}

	/* Enable Qset */
	if (nicvf_mbox_qset_config(qset)) {
		ERR("Failed to set QS in PF\n");
		goto err;
	}

	/* At start no queues are enabled but we use single RBDR for all queue
	 * triplets from the same qset, this also need to be done before any
	 * triplet will start use of RBDR */
	if (nicvf_qset_rbdr_config(qset->nic, MAX_RBDR_PER_QSET * qset->qset_idx, true)) {
		ERR("Error while configuring 0 RBDR\n");
		goto err;
	}

	return 0;

err:
	nicvf_qset_free(qset);
	return -1;
}

int nicvf_qset_close(struct queue_set *qset)
{
	bool err = false;

	qset->enable = false;

	/* Deinitialize HW queues */
	if (nicvf_qset_triplet_disableall(qset)) {
		ERR("Failed to disable VF's QS\n");
		err = true;
	}

	/* Disable HW Qset, to stop receiving packets */
	if (nicvf_mbox_qset_config(qset)) {
		ERR("Failed to set QS in PF\n");
		err = true;
	}

	/* Disable RBDR for all queue triplets */
	if (nicvf_qset_rbdr_config(qset->nic, MAX_RBDR_PER_QSET * qset->qset_idx, false)) {
		ERR("Error while configuring 0 RBDR\n");
		err = true;
	}

	/* Free resources */
	nicvf_qset_free(qset);

	return (err) ? -1 : 0;
}

void nicvf_intr_handler_qserr(struct queue_set *qset)
{
	size_t qidx, rbdr_idx;
	size_t qset_idx = qset->qset_idx;
	uint64_t status;

	/* Check if it is CQ err */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {

		if (nicvf_rxq_active(qset->nic, qidx)) {

			status = nicvf_qidx_reg_read(
				qset->nic, qidx, NIC_QSET_CQ_0_7_STATUS);
			NFO("CQ stat %zu %"PRIx64"\n", qidx, status);
			if (!(status & CQ_ERR_MASK)) {
				continue;
			}

			if (status & CQ_WR_FULL) {
				ERR("CQ %zu error FULL\n", qidx);
			} else if (status & CQ_WR_DISABLE) {
				ERR("CQ %zu error DISABLE\n", qidx);
			} else if (status & CQ_WR_FAULT) {
				ERR("CQ %zu error FAULT\n", qidx);
			}

			/* TODO Properly handle CQ reset or
			panic() and establish early DROP policy */
			goto close_abort;
		}
	}

	/* Check if it is SQ err */
	for (qidx = qset_idx * MAX_QUEUES_PER_QSET;
	     qidx < (qset_idx + 1) * MAX_QUEUES_PER_QSET;
	     qidx++) {

		if (nicvf_txq_active(qset->nic, qidx)) {

			status = nicvf_qidx_reg_read(
				qset->nic, qidx, NIC_QSET_SQ_0_7_STATUS);
			NFO("SQ stat %zu %"PRIx64"\n", qidx, status);
			if (!(status & SQ_ERR_MASK)) {
				continue;
			}

			if (status & SQ_ERR_STOPPED) {
				ERR("SQ %zu error STOPPED\n", qidx);
			} else if (status & SQ_ERR_SEND) {
				ERR("SQ %zu error DISABLE\n", qidx);
			} else if (status & SQ_ERR_DPE) {
				ERR("SQ %zu error FAULT\n", qidx);
			}
			/* TODO Properly handle SQ reset or return error */
			goto close_abort;
		}
	}

	/* Check if it is RBDR err */
	for (rbdr_idx = qset_idx * MAX_RBDR_PER_QSET;
	     rbdr_idx < (qset_idx + 1) * MAX_RBDR_PER_QSET;
	     rbdr_idx++) {

		status = nicvf_rbdr_reg_read(
			qset->nic, rbdr_idx, NIC_QSET_RBDR_0_1_STATUS0);
		status = (status & RBDR_FIFO_STATE_MASK) >> RBDR_FIFO_STATE_SHIFT;
		NFO("RBDR stat %zu %"PRIx64"\n", rbdr_idx, status);
		if (RBDR_FIFO_STATE_ACTIVE != status) {
			char const *desc[] = {
				"INACTIVE",
				"ACTIVE",
				"RESET",
				"FAIL"
			};
			uint64_t head = nicvf_rbdr_reg_read(
				qset->nic, rbdr_idx, NIC_QSET_RBDR_0_1_HEAD) >> 3;
			uint64_t tail = nicvf_rbdr_reg_read(
				qset->nic, rbdr_idx, NIC_QSET_RBDR_0_1_TAIL) >> 3;

			ERR("RBDR %zu state %s head=%"PRIu64" tail=%"PRIu64"\n",
			    rbdr_idx, desc[status], head, tail);
			/* TODO Properly handle RBDR reset or return error */
			goto close_abort;
		}
	}

	return;

close_abort:
	nicvf_dump_regs(qset->nic);
	abort();
}

