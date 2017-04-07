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

#ifndef __THUNDERX_NIC_MBOX__
#define __THUNDERX_NIC_MBOX__

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/q_struct.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* --- Taken from Cavium ThunderX NIC driver, file nic_regs.h */

/* PF <--> VF Mailbox communication
 * Two 64bit registers are shared between PF and VF for each VF
 * Writing into second register means end of message.
 */

/* PF <--> VF mailbox communication */
#define	NIC_PF_VF_MAILBOX_SIZE		2
#define	NIC_MBOX_MSG_TIMEOUT		2000	/* ms */

/* Mailbox message types */
#define	NIC_MBOX_MSG_INVALID		0x00	/* Invalid message */
#define	NIC_MBOX_MSG_READY		0x01	/* Is PF ready to rcv msgs */
#define	NIC_MBOX_MSG_ACK		0x02	/* ACK the message received */
#define	NIC_MBOX_MSG_NACK		0x03	/* NACK the message received */
#define	NIC_MBOX_MSG_QS_CFG		0x04	/* Configure Qset */
#define	NIC_MBOX_MSG_RQ_CFG		0x05	/* Configure receive queue */
#define	NIC_MBOX_MSG_SQ_CFG		0x06	/* Configure Send queue */
#define	NIC_MBOX_MSG_RQ_DROP_CFG	0x07	/* Configure receive queue */
#define	NIC_MBOX_MSG_SET_MAC		0x08	/* Add MAC ID to DMAC filter */
#define	NIC_MBOX_MSG_SET_MAX_FRS	0x09	/* Set max frame size */
#define	NIC_MBOX_MSG_CPI_CFG		0x0A	/* Config CPI, RSSI */
#define	NIC_MBOX_MSG_RSS_SIZE		0x0B	/* Get RSS indir_tbl size */
#define	NIC_MBOX_MSG_RSS_CFG		0x0C	/* Config RSS table */
#define	NIC_MBOX_MSG_RSS_CFG_CONT	0x0D	/* RSS config continuation */
#define	NIC_MBOX_MSG_RQ_BP_CFG		0x0E	/* RQ backpressure config */
#define	NIC_MBOX_MSG_RQ_SW_SYNC		0x0F	/* Flush inflight pkts to RQ */
#define	NIC_MBOX_MSG_BGX_STATS		0x10	/* Get stats from BGX */
#define	NIC_MBOX_MSG_BGX_LINK_CHANGE	0x11	/* BGX:LMAC link status */
#define	NIC_MBOX_MSG_ALLOC_SQS		0x12	/* Allocate secondary Qset */
#define	NIC_MBOX_MSG_LOOPBACK		0x16	/* Set interface in loopback */
#define	NIC_MBOX_MSG_RESET_STAT_COUNTER 0x17	/* Reset statistics counters */
#define	NIC_MBOX_MSG_CFG_DONE		0xF0	/* VF configuration done */
#define	NIC_MBOX_MSG_SHUTDOWN		0xF1	/* VF is being shutdown */
#define	NIC_MBOX_MSG_MAX		0x100	/* Maximum number of messages */

/* Get vNIC VF configuration */
struct nic_cfg_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint8_t    node_id;
	bool	   tns_mode:1;
	bool	   sqs_mode:1;
	bool	   loopback_supported:1;
	uint8_t    mac_addr[ETH_ALEN];
};

/* Qset configuration */
struct qs_cfg_msg {
	uint8_t    msg;
	uint8_t    num;
	uint8_t    sqs_count;
	uint64_t   cfg;
};

/* Receive queue configuration */
struct rq_cfg_msg {
	uint8_t    msg;
	uint8_t    qs_num;
	uint8_t    rq_num;
	uint64_t   cfg;
};

/* Send queue configuration */
struct sq_cfg_msg {
	uint8_t    msg;
	uint8_t    qs_num;
	uint8_t    sq_num;
	bool       sqs_mode;
	uint64_t   cfg;
};

/* Set VF's MAC address */
struct set_mac_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint8_t    mac_addr[ETH_ALEN];
};

/* Set Maximum frame size */
struct set_frs_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint16_t   max_frs;
};

/* Set CPI algorithm type */
struct cpi_cfg_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint8_t    rq_cnt;
	uint8_t    cpi_alg;
};

/* Get RSS table size */
struct rss_sz_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint16_t   ind_tbl_size;
};

/* Set RSS configuration */
struct rss_cfg_msg {
	uint8_t    msg;
	uint8_t    vf_id;
	uint8_t    hash_bits;
	uint8_t    tbl_len;
	uint8_t    tbl_offset;
#define RSS_IND_TBL_LEN_PER_MBX_MSG	8
	uint8_t    ind_tbl[RSS_IND_TBL_LEN_PER_MBX_MSG];
};

struct bgx_stats_msg {
	uint8_t   msg;
	uint8_t   vf_id;
	uint8_t   rx;
	uint8_t   idx;
	uint8_t   stats;
};

/* Physical interface link status */
struct bgx_link_status {
	uint8_t    msg;
	uint8_t    link_up;
	uint8_t    duplex;
	uint32_t   speed;
};

#ifdef VNIC_MULTI_QSET_SUPPORT
#define MAX_SQS_PER_VF 11
/* Allocate additional SQS to VF */
struct sqs_alloc {
	uint8_t    msg;
	uint8_t    spec;
	uint8_t    qs_count;
	uint8_t    svf[MAX_SQS_PER_VF];
};
#endif

/* Set interface in loopback mode */
struct set_loopback {
	uint8_t    msg;
	uint8_t    vf_id;
	bool	   enable;
};

/* Reset statistics counters */
struct reset_stat_cfg {
	uint8_t    msg;
	/* Bitmap to select NIC_PF_VNIC(vf_id)_RX_STAT(0..13) */
	uint16_t   rx_stat_mask;
	/* Bitmap to select NIC_PF_VNIC(vf_id)_TX_STAT(0..4) */
	uint8_t    tx_stat_mask;
	/* Bitmap to select NIC_PF_QS(0..127)_RQ(0..7)_STAT(0..1)
	 * bit14, bit15 NIC_PF_QS(vf_id)_RQ7_STAT(0..1)
	 * bit12, bit13 NIC_PF_QS(vf_id)_RQ6_STAT(0..1)
	 * ..
	 * bit2, bit3 NIC_PF_QS(vf_id)_RQ1_STAT(0..1)
	 * bit0, bit1 NIC_PF_QS(vf_id)_RQ0_STAT(0..1)
	 */
	uint16_t   rq_stat_mask;
	/* Bitmap to select NIC_PF_QS(0..127)_SQ(0..7)_STAT(0..1)
	 * bit14, bit15 NIC_PF_QS(vf_id)_SQ7_STAT(0..1)
	 * bit12, bit13 NIC_PF_QS(vf_id)_SQ6_STAT(0..1)
	 * ..
	 * bit2, bit3 NIC_PF_QS(vf_id)_SQ1_STAT(0..1)
	 * bit0, bit1 NIC_PF_QS(vf_id)_SQ0_STAT(0..1)
	 */
	uint16_t   sq_stat_mask;
};

/* 128 bit shared memory between PF and each VF */
union nic_mbx {
	struct { uint8_t msg; }	msg;
	struct nic_cfg_msg	nic_cfg;
	struct qs_cfg_msg	qs;
	struct rq_cfg_msg	rq;
	struct sq_cfg_msg	sq;
	struct set_mac_msg	mac;
	struct set_frs_msg	frs;
	struct cpi_cfg_msg	cpi_cfg;
	struct rss_sz_msg	rss_size;
	struct rss_cfg_msg	rss_cfg;
	struct bgx_stats_msg    bgx_stats;
	struct bgx_link_status  link_status;
#ifdef VNIC_MULTI_QSET_SUPPORT
	struct sqs_alloc        sqs_alloc;
#endif
	struct set_loopback	lbk;
	struct reset_stat_cfg	reset_stat;
};

int nicvf_mbox_ready_qset(struct queue_set *qset, union nic_mbx *res);
int nicvf_mbox_set_mac_addr(struct nicvf *nic, const uint8_t mac[6]);
int nicvf_mbox_config_cpi(struct nicvf *nic);
#ifdef VNIC_RSS_SUPPORT
int nicvf_mbox_get_rss_size(struct queue_set *qset);
int nicvf_mbox_config_rss(struct queue_set *qset);
#endif
int nicvf_mbox_rq_config(struct nicvf *nic, int qidx);
int nicvf_mbox_sq_config(struct nicvf *nic, int qidx);
int nicvf_mbox_qset_config(struct queue_set *qset);
int nicvf_mbox_drop_config(struct nicvf *nic, size_t qidx);
int nicvf_mbox_update_hw_max_frs(struct nicvf *nic, uint16_t mtu);
int nicvf_mbox_rq_sync(struct queue_set *qset);
int nicvf_mbox_rq_bp_cfg(struct queue_set *qset);
#ifdef VNIC_MULTI_QSET_SUPPORT
int nicvf_mbox_qset_allocate_sqs(struct nicvf *nic);
#endif
int nicvf_mbox_vf_shutdown(struct queue_set *qset);
void nicvf_mbox_config_done(struct queue_set *qset);

/* this function should not be called by any other thread than housekeeping */
int nicvf_mbox_read_response(struct queue_set *qset);

_Static_assert(sizeof(union nic_mbx) <= 16,"sizeof(nic_mbx) <= 16");


#endif /* __THUNDERX_NIC_MBOX__ */
