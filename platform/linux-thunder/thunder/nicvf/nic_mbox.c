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

#include <asm-generic/errno-base.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_reg.h"
#include "thunder/nicvf/nic_mbox.h"

#if (DEBUG >= 3)
#define DEF_MBOX_MSG_STR(msg) [msg] = #msg
static const char *msg_names[256] =  {
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_INVALID),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_READY),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_ACK),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_NACK),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_QS_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RQ_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_SQ_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RQ_DROP_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_SET_MAC),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_SET_MAX_FRS),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_CPI_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RSS_SIZE),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RSS_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RSS_CFG_CONT),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RQ_BP_CFG),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_RQ_SW_SYNC),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_BGX_STATS),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_BGX_LINK_CHANGE),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_ALLOC_SQS),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_LOOPBACK),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_CFG_DONE),
	DEF_MBOX_MSG_STR(NIC_MBOX_MSG_SHUTDOWN),
};
#endif

/* this function is called from housekeeping thread (handles IRQ) */
int nicvf_mbox_read_response(struct queue_set *qset)
{
	uint64_t *mbx_ptr;
	uint64_t mbx_addr;
	size_t i;
	int ret;
	uint8_t msg;

	pthread_mutex_lock(&qset->mbx_mutex);

	mbx_addr = NIC_VF_PF_MAILBOX_0_1;
	mbx_ptr = (uint64_t*)(&qset->mbx_msg);
	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		*mbx_ptr = nicvf_vf_reg_read(qset, mbx_addr);
		mbx_ptr++;
		mbx_addr += sizeof(uint64_t);
	}

	msg = qset->mbx_msg.msg.msg;
	switch (msg) {
	case NIC_MBOX_MSG_READY:
	case NIC_MBOX_MSG_ACK:
	case NIC_MBOX_MSG_NACK:
	case NIC_MBOX_MSG_RSS_SIZE | NIC_MBOX_MSG_RES_BIT:
#ifdef VNIC_MULTI_QSET_SUPPORT
	case NIC_MBOX_MSG_ALLOC_SQS | NIC_MBOX_MSG_RES_BIT:
#endif
	case NIC_MBOX_MSG_BGX_LINK_CHANGE:
		DBGV3("VF Mbox msg received msg_id=0x%x %s\n",
		      msg, msg_names[msg & (~NIC_MBOX_MSG_RES_BIT)]);
		/* overwrite the message buffer so we won't receive it again */
		nicvf_vf_reg_write(qset, NIC_VF_PF_MAILBOX_0_1, NIC_MBOX_MSG_INVALID);

		if (msg != NIC_MBOX_MSG_BGX_LINK_CHANGE) {
			/* for all messages beside "Link Change" signalize the
			 * waiting thread that msg was received */
			pthread_cond_signal(&qset->mbx_cond);
		} else {
			qset->nic->link_status = qset->mbx_msg.link_status;
			wmb();
			NFO("Link status %"PRIx8"\n", qset->mbx_msg.link_status.link_up);
		}
		ret = 0;
		break;

	default:
		/* in other cases it means message was invalid or not received */
		DBG("Unknown Mbox msg received msg_id=0x%x\n",
		    msg & (~NIC_MBOX_MSG_RES_BIT));
		ret = -1;
		break;
	}

	pthread_mutex_unlock(&qset->mbx_mutex);
	return ret;
}

#define MBX_TIMEOUT 1000000000 /* 1sec - since PF may have debugs enabled (slow down) */

/* this function is called from initializer thread
 * this function sleeps the initializer thread until response message will be
 * received by housekeeping thread (IRQ will trigger hausekeeping thread) */
static int nicvf_mbox_recv_response(
	struct queue_set *qset, union nic_mbx *res)
{
	struct timespec ts;
	int ret;

	pthread_mutex_lock(&qset->mbx_mutex);

	res->msg.msg = NIC_MBOX_MSG_INVALID; /* Invalidate any previous response code */
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += MBX_TIMEOUT;
	if (ts.tv_nsec > 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec += 1;
	}
	ret = pthread_cond_timedwait(&qset->mbx_cond, &qset->mbx_mutex, &ts);
	assert(ret == ETIMEDOUT || ret == 0);
	if (ret == 0) {
		*res = qset->mbx_msg;
		memset(&qset->mbx_msg, 0, sizeof(qset->mbx_msg));
	}

	pthread_mutex_unlock(&qset->mbx_mutex);
	return ret;
}

static void nicvf_mbox_send_msg_to_pf_raw(
	struct queue_set* qset, union nic_mbx *mbx)
{
	uint64_t *mbx_ptr;
	uint64_t mbx_addr;
	int i;

	DBG("Sending msg to PF msg=0x%02x %s\n", mbx->msg.msg,
	     msg_names[mbx->msg.msg & (~NIC_MBOX_MSG_RES_BIT)]);

	mbx_addr = NIC_VF_PF_MAILBOX_0_1;
	mbx_ptr = (uint64_t *)mbx;

	for (i = 0; i < NIC_PF_VF_MAILBOX_SIZE; i++) {
		nicvf_vf_reg_write(qset, mbx_addr, *mbx_ptr);
		mbx_ptr++;
		mbx_addr += sizeof(uint64_t);
	}
}

static void nicvf_mbox_send_async_msg_to_pf(
	struct queue_set* qset, union nic_mbx *mbx)
{
	nicvf_mbox_send_msg_to_pf_raw(qset, mbx);
	/* Messages without ack are racy!*/
	nanosleep(&(struct timespec) {0, 10000000}, NULL);
}

static int nicvf_mbox_send_msg_to_pf(
	struct queue_set *qset, union nic_mbx *mbx, union nic_mbx *res)
{
	size_t try;
	int ret;

	/* because of BUG in PF<->VF mbox design, some message transactions from
	 * VF-> PF can be overwrited by asynchronius PF->VF messages. Therefore
	 * in case of missing response, we have to try again */
	for(try = 0; try < 3 ; try++) {
		nicvf_mbox_send_msg_to_pf_raw(qset, mbx);
		ret = nicvf_mbox_recv_response(qset, res);
		if (!ret)
			break; /* Success */
		DBG("Missing response! Retrying MBX transaction ... %zu\n", try+1);
	}
	if (ret)
		ERR("Missing response 3 times in row. PF not responding?\n");

	return ret;
}

int nicvf_mbox_ready_qset(struct queue_set *qset, union nic_mbx *res)
{
	union nic_mbx mbx = { .msg = {.msg  = NIC_MBOX_MSG_READY }};

	nicvf_mbox_send_msg_to_pf_raw(qset, &mbx);

	if (nicvf_mbox_recv_response(qset, res) ||
	    res->msg.msg != NIC_MBOX_MSG_READY) {
		ERR("PF didn't respond to READY msg\n");
		return -1;
	}

	qset->vf_id = res->nic_cfg.vf_id & 0x7F;

	return 0;
}

int nicvf_mbox_set_mac_addr(struct nicvf *nic, const uint8_t mac[6])
{
	union nic_mbx mbx = { .msg = { 0 } };
	union nic_mbx res = { .msg = { 0 } };
	size_t i;

	mbx.msg.msg = NIC_MBOX_MSG_SET_MAC;
	mbx.mac.vf_id = nic->qset[0].vf_id;
	for (i = 0; i < 6; i++)
		mbx.mac.mac_addr[i] = mac[i];

	if (nicvf_mbox_send_msg_to_pf(&nic->qset[0], &mbx, &res)) {
		ERR("PF didn't respond to RSS req\n");
		return -1;
	}
	if (res.msg.msg != NIC_MBOX_MSG_ACK) {
		ERR("PF respond with invalid msg = 0x%02x\n", res.msg.msg);
		return -1;
	}

	return 0;
}

/** Configure CPI
 *  @param qset - queue set of vf to being configured
 *  @param cpi_alg - CPI algorithm to configure
 *  @return 0 in case of success != 0 in case of failure
 */
int nicvf_mbox_config_cpi(struct nicvf *nic)
{
	union nic_mbx mbx = { .msg = { 0 } };
	union nic_mbx res = { .msg = { 0 } };
	bitmap_t bitmap = nic->qdesc.rxq_bitmap;
	size_t qcnt, qidx;
	uint8_t cpi_alg = nic->cpi_alg;

	qcnt = 0;
	for (qidx = 0; qidx < MAX_QUEUES_PER_NIC; qidx++) {
		if (bitmap_test_bit(bitmap, qidx)) {
			qcnt++;
		}
	}

	mbx.cpi_cfg.msg = NIC_MBOX_MSG_CPI_CFG;
	mbx.cpi_cfg.vf_id = nic->qset[0].vf_id;
	mbx.cpi_cfg.cpi_alg = cpi_alg;
	mbx.cpi_cfg.rq_cnt = qcnt;

	if (nicvf_mbox_send_msg_to_pf(&nic->qset[0], &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK) {
		ERR("Error while configuring CPI's\n");
		return -1;
	}

	return 0;
}

#ifdef VNIC_RSS_SUPPORT
int nicvf_mbox_get_rss_size(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};

	mbx.msg.msg = NIC_MBOX_MSG_RSS_SIZE;
	mbx.rss_size.vf_id = qset->vf_id;

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != (NIC_MBOX_MSG_RSS_SIZE | NIC_MBOX_MSG_RES_BIT))
		return -1;

	return res.rss_size.ind_tbl_size;
}

int nicvf_mbox_config_rss(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	struct nicvf_rss_info *rss = &qset->rss_info;
	size_t tot_len = rss->rss_size;
	size_t cur_len;
	size_t cur_idx = 0;
	size_t i;

	mbx.rss_cfg.vf_id = qset->vf_id;
	mbx.rss_cfg.hash_bits = rss->hash_bits;
	mbx.rss_cfg.tbl_len = 0;
	mbx.rss_cfg.tbl_offset = 0;
	while (cur_idx < tot_len) {

		cur_len = min(tot_len - cur_idx, (size_t)RSS_IND_TBL_LEN_PER_MBX_MSG);
		mbx.msg.msg = (cur_idx > 0) ?
			NIC_MBOX_MSG_RSS_CFG_CONT : NIC_MBOX_MSG_RSS_CFG;
		mbx.rss_cfg.tbl_offset = cur_idx;
		mbx.rss_cfg.tbl_len = cur_len;
		for (i = 0; i < cur_len; i++)
			mbx.rss_cfg.ind_tbl[i] = rss->ind_tbl[cur_idx++];

		if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
		    res.msg.msg != NIC_MBOX_MSG_ACK) {
			ERR("Error while sending RSS table to PF\n");
			return -1;
		}
	}

	return 0;
}
#endif

int nicvf_mbox_rq_config(struct nicvf *nic, int qidx)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct rcv_queue *rq = &(nic->qdesc.rq[qidx]);

	mbx.msg.msg = NIC_MBOX_MSG_RQ_CFG;
	mbx.rq.qs_num = qset->vf_id;
	mbx.rq.rq_num = qidx % MAX_QUEUES_PER_QSET;
	mbx.rq.cfg = (rq->caching << 26) | (rq->cq_qs << 19) |
		     (rq->cq_idx << 16) | (rq->cont_rbdr_qs << 9) |
		     (rq->cont_qs_rbdr_idx << 8) |
		     (rq->start_rbdr_qs << 1) | (rq->start_qs_rbdr_idx);

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

int nicvf_mbox_sq_config(struct nicvf *nic, int qidx)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct snd_queue *sq = &(nic->qdesc.sq[qidx]);

	mbx.msg.msg = NIC_MBOX_MSG_SQ_CFG;
	mbx.sq.qs_num = qset->vf_id;
	mbx.sq.sq_num = qidx % MAX_QUEUES_PER_QSET;
	mbx.sq.sqs_mode = (qidx >= MAX_QUEUES_PER_QSET);
	mbx.sq.cfg = (sq->cq_qs << 3) | sq->cq_idx;

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

int nicvf_mbox_qset_config(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	struct qs_cfg *qs_cfg;

	/* Send a mailbox msg to PF to config Qset */
	mbx.msg.msg = NIC_MBOX_MSG_QS_CFG;
	mbx.qs.num = qset->vf_id;
	// ignored in PF mbx.qs.sqs_count = sqs_cnt;

	mbx.qs.cfg = 0;
	qs_cfg = (struct qs_cfg *)&mbx.qs.cfg;
	if (qset->enable) {
		qs_cfg->ena = 1;
#ifdef __BIG_ENDIAN_BITFIELD
		qs_cfg->be = 1;
#endif
		qs_cfg->vnic = qset->vf_id;
	}
	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK) {
		ERR("Error while communicating with PF durring NIC QSet setup\n");
		return -1;
	}

	return 0;
}

int nicvf_mbox_drop_config(struct nicvf *nic, size_t qidx)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	struct queue_set *qset = &nic->qset[qidx / MAX_QUEUES_PER_QSET];
	struct drop_cfg *drop_cfg;

	/* Enable CQ drop to reserve sufficient CQEs for all tx packets */
	mbx.msg.msg = NIC_MBOX_MSG_RQ_DROP_CFG;
	mbx.rq.qs_num = qset->vf_id;
	mbx.rq.rq_num = qidx % MAX_QUEUES_PER_QSET;
	drop_cfg = (struct drop_cfg*)&(mbx.rq.cfg);
	drop_cfg->cq_red = 1;
	drop_cfg->cq_drop = RQ_CQ_DROP;
	drop_cfg->cq_pass = RQ_CQ_DROP;

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

int nicvf_mbox_update_hw_max_frs(struct nicvf *nic, uint16_t mtu)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};

	mbx.msg.msg = NIC_MBOX_MSG_SET_MAX_FRS;
	mbx.frs.max_frs = mtu;
	mbx.frs.vf_id = nic->qset[0].vf_id;

	if (nicvf_mbox_send_msg_to_pf(&nic->qset[0], &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

int nicvf_mbox_rq_sync(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};

	/* Make sure all packets in the pipeline are written back into mem */
	mbx.msg.msg = NIC_MBOX_MSG_RQ_SW_SYNC;
	mbx.rq.cfg = 0;

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

int nicvf_mbox_rq_bp_cfg(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};

	mbx.msg.msg = NIC_MBOX_MSG_RQ_BP_CFG;
	mbx.rq.qs_num = qset->vf_id;
	mbx.rq.rq_num = qset->qset_idx;
	mbx.rq.cfg = (1ULL << 63) | (1ULL << 62) | (0xff << 16) | (0xff << 8) | (qset->vf_id << 0);
	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK)
		return -1;
	return 0;
}

#ifdef VNIC_MULTI_QSET_SUPPORT
int nicvf_mbox_qset_allocate_sqs(struct nicvf *nic)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};
	size_t i;

	assert((nic->qset_cnt > 1) &&
	       (nic->qset_cnt < MAX_SQS_PER_VF));

	NFO("Requesting %zu SQS\n", nic->qset_cnt - 1);

	mbx.sqs_alloc.msg = NIC_MBOX_MSG_ALLOC_SQS;
	mbx.sqs_alloc.spec = 1;
	mbx.sqs_alloc.qs_count = nic->qset_cnt - 1;
	for (i = 0; i < nic->qset_cnt - 1; i++) {
		mbx.sqs_alloc.svf[i] = nic->qset[i + 1].vf_id;
		NFO("SQS %"PRIu8" added to request\n", mbx.sqs_alloc.svf[i]);
	}

	if (nicvf_mbox_send_msg_to_pf(&nic->qset[0], &mbx, &res) ||
	    res.msg.msg != (NIC_MBOX_MSG_ALLOC_SQS | NIC_MBOX_MSG_RES_BIT)) {
		ERR("Invalid or missing response for alloc SQS\n");
		return -1;
	}

	NFO("SQS alloc response received qs_count=%"PRIu8"\n",
	    res.sqs_alloc.qs_count);

	if (res.sqs_alloc.qs_count != nic->qset_cnt - 1) {
		ERR("Nbr of SQS in response is different from requested\n");
		return -1;
	}
	for (i = 0; i < res.sqs_alloc.qs_count; i++) {
		if (res.sqs_alloc.svf[i] != nic->qset[i + 1].vf_id) {
			ERR("One of SQS is different than requested %"PRIu8"!=%"PRIu8"\n",
			    res.sqs_alloc.svf[i], nic->qset[i + 1].vf_id);
			return -1;
		}
	}

	return 0;
}
#endif

/* mark PF that all VFs are going down */
int nicvf_mbox_vf_shutdown(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg = { 0 }};
	union nic_mbx res = { .msg = { 0 }};

	mbx.msg.msg = NIC_MBOX_MSG_SHUTDOWN;

	if (nicvf_mbox_send_msg_to_pf(qset, &mbx, &res) ||
	    res.msg.msg != NIC_MBOX_MSG_ACK) {
		ERR("Error while communicating with PF durring NIC QSet teardown\n");
		return -1;
	}

	return 0;
}

void nicvf_mbox_config_done(struct queue_set *qset)
{
	union nic_mbx mbx = { .msg.msg = NIC_MBOX_MSG_CFG_DONE, };
	nicvf_mbox_send_async_msg_to_pf(qset, &mbx);
}

