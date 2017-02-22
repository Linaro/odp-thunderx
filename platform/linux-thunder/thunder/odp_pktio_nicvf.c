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

#include <string.h>

#include <odp_debug_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/pool.h>
#include <odp/api/packet.h>
#include <odp_posix_extensions.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_internal.h>
#include <odp_pool_internal.h>


#include <thunder/nicvf/nic_uio.h>
#include <thunder/nicvf/nic_vfio.h>
#include <thunder/nicvf/nic_vfmain.h>
#include <thunder/nicvf/nic_common.h>

#include "thunder/odp_pktio_nicvf.h"

/**
 * Local objects
 */
static const uint8_t default_mac[6] = { 0x02, 0x01, 0x01, 0x01, 0x01, 0x01 };

/**
 * Private functions forward declarations
 */
static int nicvf_pktio_recv_lockless(pktio_entry_t *pktio_entry, int index,
				     odp_packet_t pkt_table[], int num);

static int nicvf_pktio_send_lockless(pktio_entry_t *pktio_entry,
			   int index,
			   const odp_packet_t pkt_table[],
			   int num);

static int nicvf_pktio_recv_dummy(pktio_entry_t *pktio_entry ODP_UNUSED,
				  int index ODP_UNUSED,
				  odp_packet_t pkt_table[] ODP_UNUSED,
				  int num ODP_UNUSED);

static int nicvf_pktio_send_dummy(pktio_entry_t *pktio_entry ODP_UNUSED,
				  int index ODP_UNUSED,
				  const odp_packet_t pkt_table[] ODP_UNUSED,
				  int num ODP_UNUSED);

void odp_pktio_dump_regs(const char *name);

/**
 * Private functions
 */
static int nicvf_pktio_if_name_scan(const char* name, enum nicvf_type *type,
				    size_t *cnt, unsigned id[])
{
	ssize_t len;
	size_t pos, qs_cnt;
	int cons;

	len = strlen(name);
	if(!strncmp(name, "vfio:", 5)) {
		pos = 5;
		len -= 5;
		*type = NICVF_TYPE_VFIO;
	} else if(!strncmp(name, "uio:", 4)) {
		pos = 4;
		len -= 4;
		*type = NICVF_TYPE_UIO;
	} else {
		ODP_ERR("Invalid device name %s\n", name);
		return -1;
	}

	qs_cnt = 0;
	while ((len > 0) && (qs_cnt < MAX_QSETS_PER_NIC)) {

		if (1 != sscanf(&name[pos], "%u%n", &id[qs_cnt], &cons)) {
			ODP_ERR("Invalid device vfio group for SQS %s\n", name);
			return -1;
		}

		pos += cons;
		len -= cons;
		qs_cnt++;

		if ((name[pos] == '\0') || (name[pos] == '-'))
			break;
		if (name[pos] == '.') {
			pos += 1;
			len -= 1;
		}
	}
	*cnt = qs_cnt;

	return 0;
}

/**
 * Callback public interface functions
 */

static int nicvf_pktio_init_global(void)
{
	return 0; /* nothing to do */
}

static int nicvf_pktio_init_local(void)
{
	return 0; /* nothing to do */
}

static int nicvf_pktio_term(void)
{
	return 0; /* nothing to do */
}

static int nicvf_pktio_open(odp_pktio_t ODP_UNUSED id,
			    pktio_entry_t *pktio_entry,
			    const char *netdev, odp_pool_t pool)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	struct odp_shm_info_t shm_info;

	/* zero all structure fields, including internal nicvf */
	memset(pkt_nicvf, 0, sizeof(pkt_nicvf_t));

	/* scan the netdev name and detect following:
	 * - used backplane (UIO/VFIO)
	 * - number of QSET's
	 * - id of QSET's
	 */
	if (nicvf_pktio_if_name_scan(netdev, &pkt_nicvf->type,
				     &pkt_nicvf->qs_cnt, pkt_nicvf->qs_id)) {
		/* interface name not recognized, probably not ThunderX specific */
		return -1;
	}
#ifndef VNIC_MULTI_QSET_SUPPORT
	if (pkt_nicvf->qs_cnt > 0) {
		ODP_ERR("ThunderX NIC is not configured for multi QSET support\n");
		return -1;
	}
#endif

	pkt_nicvf->pool = (struct pool_entry_s *)pool;

	/* initialize ThunderX interface, depending on detected backplane */
	switch (pkt_nicvf->type) {
	case NICVF_TYPE_UIO:
		if (nic_uio_init(&pkt_nicvf->nicvf, pkt_nicvf->qs_cnt, pkt_nicvf->qs_id)) {
			ODP_ERR("UIO init failed");
			return -1;
		}
		break;

	case NICVF_TYPE_VFIO:
		if (nic_vfio_init(&pkt_nicvf->nicvf, pkt_nicvf->qs_cnt, pkt_nicvf->qs_id)) {
			ODP_ERR("VFIO init failed");
			return -1;
		}
		break;

	default:
		ODP_ASSERT(!"Invalid NIC mode");
		break;
	}

	uint16_t dev_id = nicvf_dev_id(&pkt_nicvf->nicvf);

	switch(dev_id) {
	case PCI_DEVICE_ID_THUNDER_PASS1_NIC_VF:
		pkt_nicvf->nicvf.rbptr_offset = NICVF_CQE_RBPTR_WORD;
		break;
	case PCI_DEVICE_ID_THUNDER_PASS2_NIC_VF:
	case PCI_DEVICE_ID_CN81XX_NIC_VF:
		pkt_nicvf->nicvf.rbptr_offset = NICVF_CQE_RX2_RBPTR_WORD;
		break;
	default:
		ODP_ABORT("Invalid NIC dev id: %"PRIx16"\n", dev_id);
		break;
	}

	if (odp_shm_info(((struct pool_entry_s *)pool)->pool_buffer_shm, &shm_info)) {
		ODP_ERR("Error on odp_shm_info\n");
		goto err2;
	}
	pkt_nicvf->pool_info.uva = shm_info.addr;
	pkt_nicvf->pool_info.size = shm_info.size;
	if (nic_dma_map(&pkt_nicvf->nicvf, pkt_nicvf->pool_info.uva, pkt_nicvf->pool_info.size,
			&(pkt_nicvf->pool_info.iova))) {
		ODP_ERR("Error on nic_dma_map\n");
		goto err2;
	}

	if (nicvf_open(&pkt_nicvf->nicvf, default_mac, false)) {
		ERR("Error while nicvf_open\n");
		goto err3;
	}

	return 0;
err3:
	(void)nic_dma_unmap(&pkt_nicvf->nicvf, pkt_nicvf->pool_info.uva, pkt_nicvf->pool_info.size,
			    pkt_nicvf->pool_info.iova);
err2:
	switch (pkt_nicvf->type) {
	case NICVF_TYPE_UIO:
		nic_uio_close(&pkt_nicvf->nicvf);
		break;
	case NICVF_TYPE_VFIO:
		nic_vfio_close(&pkt_nicvf->nicvf);
		break;
	default:
		ODP_ASSERT(!"dead code\n");
		break;
	}

	return -1;
}

static int nicvf_pktio_close(pktio_entry_t *pktio_entry)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	if (nicvf_close(&pkt_nicvf->nicvf)) {
		ODP_ERR("Error on nicvf_close()\n");
	}
	if (nic_dma_unmap(&pkt_nicvf->nicvf, pkt_nicvf->pool_info.uva,
			  pkt_nicvf->pool_info.size, pkt_nicvf->pool_info.iova)) {
		ODP_ERR("Error while unmapping buffer pool memory\n");
	}
	if (NICVF_TYPE_UIO == pkt_nicvf->type) {
		nic_uio_close(&pkt_nicvf->nicvf);
	} else {
		nic_vfio_close(&pkt_nicvf->nicvf);
	}
	return 0;
}

static int nicvf_pktio_start(pktio_entry_t *pktio_entry)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	size_t rxq_cnt = pkt_nicvf->rxq_cnt;
	size_t txq_cnt = pkt_nicvf->txq_cnt;
	size_t ridx = 0, tidx = 0, idx;
	int qidx;

	for (ridx = 0; ridx < rxq_cnt; ridx++) {
		qidx = nicvf_qset_rxq_enable(&pkt_nicvf->nicvf);
		if (qidx < 0) {
			ODP_ERR("Error while opening NIC RX queue qidx %d\n", ridx);
			goto err;
		}
	}

	for (tidx = 0; tidx < txq_cnt; tidx++) {
		qidx = nicvf_qset_txq_enable(&pkt_nicvf->nicvf);
		if (qidx < 0) {
			ODP_ERR("Error while opening NIC TX queue qidx %d\n", tidx);
			goto err;
		}
	}

	/* switch the callback and allow further call to HW rcv/send function */
	/* TODO this is not valid, since nicvf_pktio table is shared betwen all
	 * instances of ThunderX pktio's. We modify the callback for all of them
	 */
	nicvf_pktio_ops.recv = nicvf_pktio_recv_lockless;
	nicvf_pktio_ops.send = nicvf_pktio_send_lockless;

	return 0;

err:
	for (idx = 0; idx < ridx; idx++) {
		(void)nicvf_qset_rxq_disable(&pkt_nicvf->nicvf, idx);
	}
	for (idx = 0; idx < tidx; idx++) {
		(void)nicvf_qset_txq_disable(&pkt_nicvf->nicvf, idx);
	}
	return -1;
}

static int nicvf_pktio_stop(pktio_entry_t *pktio_entry)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	/* switch the callback and prevent further call to HW rcv/send function */
	/* TODO this is not valid, since nicvf_pktio table is shared betwen all
	 * instances of ThunderX pktio's. We modify the callback for all of them
	 */
	nicvf_pktio_ops.recv = nicvf_pktio_recv_dummy;
	nicvf_pktio_ops.send = nicvf_pktio_send_dummy;

	if (nicvf_qset_rxqtxq_disableall(&pkt_nicvf->nicvf)) {
		ODP_ERR("Error while closing NIC queues");
		return -1;
	}

	return 0;
}

static int nicvf_pktio_stats(pktio_entry_t *pktio_entry,
			     odp_pktio_stats_t *stats)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	struct nicvf *nic = &pkt_nicvf->nicvf;
	struct hw_stats_t hw;

	nicvf_stathw_get(&nic->qset[0], &hw);

	stats->in_octets = hw.rx_bytes_ok;
	stats->in_ucast_pkts = hw.rx_ucast_frames_ok;
	stats->in_discards = hw.rx_drop_overrun + hw.rx_drop_red +
				hw.rx_drop_bcast + hw.rx_drop_mcast +
				hw.rx_drop_l3_mcast + hw.rx_drop_l3_bcast;
	stats->in_errors = hw.rx_l2_errors + hw.rx_fcs_errors;
	stats->in_unknown_protos = 0;
	stats->out_octets = hw.tx_bytes_ok;
	stats->out_ucast_pkts = hw.tx_ucast_frames_ok;
	stats->out_discards = hw.tx_drops;
	stats->out_errors = 0;

	return 0;
}

static int nicvf_pktio_stats_reset(pktio_entry_t *pktio_entry)
{
	/* TODO PKTIO: implement pktio callback */
	(void) pktio_entry;
	return -1;
}

static uint32_t nicvf_pktio_mtu_get(pktio_entry_t *pktio_entry)
{
	struct nicvf *nicvf = &pktio_entry->s.pkt_nicvf.nicvf;
	return nicvf_mtu(nicvf);
}

static int nicvf_pktio_promisc_mode_set(pktio_entry_t *pktio_entry,
					odp_bool_t enable)
{
	/* TODO PKTIO: implement pktio callback */
	(void) pktio_entry;
	(void) enable;
	return 0;
}

static int nicvf_pktio_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	/* TODO PKTIO: implement pktio callback */
	(void) pktio_entry;
	return 0;
}

static int nicvf_pktio_mac_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	struct nicvf *nicvf = &pktio_entry->s.pkt_nicvf.nicvf;

	if (nicvf_mac_get(nicvf, mac_addr, ODPH_ETHADDR_LEN))
		return 0;
	return ETH_ALEN;
}

static int nicvf_pktio_link_status(pktio_entry_t *pktio_entry)
{
	struct nicvf *nic = &pktio_entry->s.pkt_nicvf.nicvf;
	return nic->link_status.link_up;
}

static int nicvf_pktio_capability(pktio_entry_t *pktio_entry,
				  odp_pktio_capability_t *capa)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues = pkt_nicvf->qs_cnt * MAX_QUEUES_PER_QSET;
	capa->max_output_queues = pkt_nicvf->qs_cnt * MAX_QUEUES_PER_QSET;

	/* TODO Timestamp for all packets is possible
	 * For TX we need to support second CQ descriptor type
	 * For RX the timestamp will be added before packet data
	 * For both the PTP clock setup is needed */
	capa->config.pktin.bit.ts_all = 0;
	/* PTP is just specific packet type, we support timestamp for any packet type */
	capa->config.pktin.bit.ts_ptp = 0;
	/* we do not support droping of packets with invalid ipv4 checksum
	 * TODO it is possible ot do in SW, see nicvf_qset_rq_handler_pkterror
	 * (postponed until new driver will be in place) */
	capa->config.pktin.bit.ipv4_chksum = 1;
	/* neither for UDP */
	capa->config.pktin.bit.udp_chksum = 1;
	/* nor TCP */
	capa->config.pktin.bit.tcp_chksum = 1;
	/* not SCTP */
	capa->config.pktin.bit.sctp_chksum = 0;
	/* not supported */
	capa->config.pktin.bit.drop_ipv4_err = 0;
	/* not supported */
	capa->config.pktin.bit.drop_ipv6_err = 0;
	/* not supported */
	capa->config.pktin.bit.drop_udp_err = 0;
	/* not supported */
	capa->config.pktin.bit.drop_tcp_err = 0;
	/* not supported */
	capa->config.pktin.bit.drop_sctp_err = 0;

	/* support for ipv4 check sum, see nicvf_qset_sq_fill_desc() */
	capa->config.pktout.bit.ipv4_chksum = 1;
	/* also UDP */
	capa->config.pktout.bit.udp_chksum = 1;
	/* and TCP */
	capa->config.pktout.bit.tcp_chksum = 1;
	/* no SCTP check sum */
	capa->config.pktout.bit.sctp_chksum = 0;
	/* specific for ThunderX (used in pktget)
	 * support for fast packet generation where buffers/packets are reused
	 * without free/reclaim operation after TX */
	capa->config.pktout.bit.tx_no_recl_buff = 1;

	/* TODO PKTIO: loopback support */
	capa->config.enable_loop = 0;
	capa->loop_supported = 0;

	return 0;
}

static int nicvf_pktio_config(pktio_entry_t *pktio_entry,
			      const odp_pktio_config_t *config)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	/* parse and store config flags for latter use in nicvf_pktio_open() */
	pkt_nicvf->nicvf.cfg_flags =0;
	if (config->pktout.bit.ipv4_chksum)
		pkt_nicvf->nicvf.cfg_flags |= NICVF_CFGFLAG_CHCKSUM_IPV4;
	if (config->pktout.bit.udp_chksum)
		pkt_nicvf->nicvf.cfg_flags |= NICVF_CFGFLAG_CHCKSUM_UDP;
	if (config->pktout.bit.tcp_chksum)
		pkt_nicvf->nicvf.cfg_flags |= NICVF_CFGFLAG_CHCKSUM_TCP;
	if (config->pktout.bit.tx_no_recl_buff)
		pkt_nicvf->nicvf.cfg_flags |= NICVF_CFGFLAG_NO_RECL_TX_BUFF;

	return 0;
}

static int nicvf_pktio_input_queues_config(pktio_entry_t *pktio_entry,
					   const odp_pktin_queue_param_t *p)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	pkt_nicvf->rxq_cnt = p->num_queues;
	NFO("%d RX queues configured\n", pkt_nicvf->rxq_cnt);
	return 0;
}

static int nicvf_pktio_output_queues_config(pktio_entry_t *pktio_entry,
					    const odp_pktout_queue_param_t *p)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	pkt_nicvf->txq_cnt = p->num_queues;
	NFO("%d TX queues configured\n", pkt_nicvf->txq_cnt);
	return 0;
}

static int nicvf_pktio_recv_lockless(pktio_entry_t *pktio_entry, int index,
				     odp_packet_t pkt_table[], int num)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	struct packet_hdr_t **_pkt_table = (struct packet_hdr_t **)pkt_table;
	size_t i, pkts;
	uint64_t order;

	pkts = nicvf_recv(&pkt_nicvf->nicvf, index,
			  _pkt_table, num, &order);

	for (i = 0; i < pkts; ++i) {
		_pkt_table[i]->input = pktio_entry->s.handle;
		_pkt_table[i]->buf_hdr.order = order++;
		_pkt_table[i]->buf_hdr.origin_qe = NULL;
	}

	return (int)pkts;
}

static int nicvf_pktio_send_lockless(pktio_entry_t *pktio_entry,
			   int index,
			   const odp_packet_t pkt_table[],
			   int num)
{
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;

	return nicvf_xmit(&pkt_nicvf->nicvf, index,
			  (struct packet_hdr_t * const*)pkt_table, num);
}

static int nicvf_pktio_recv_dummy(pktio_entry_t *pktio_entry ODP_UNUSED,
				  int index ODP_UNUSED,
				  odp_packet_t pkt_table[] ODP_UNUSED,
				  int num ODP_UNUSED)
{
	return 0;
}

static int nicvf_pktio_send_dummy(pktio_entry_t *pktio_entry ODP_UNUSED,
				  int index ODP_UNUSED,
				  const odp_packet_t pkt_table[] ODP_UNUSED,
				  int num ODP_UNUSED)
{
	return 0;
}

/* TODO CLEANUP: implement common pktio stats getter and use it
 *               or remove stats dump */
void odp_pktio_stats_dump(odp_pktio_t id)
{
#ifdef NIC_QUEUE_STATS
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	if (pktio_entry == NULL)
		return;

	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	nicvf_print_queue_stats(&pkt_nicvf->nicvf);
#else
	(void)id;
#endif
}

void odp_pktio_dump_regs(const char *name)
{
	odp_pktio_t id = odp_pktio_lookup(name);
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	if (pktio_entry == NULL)
		return;
	pkt_nicvf_t *pkt_nicvf = &pktio_entry->s.pkt_nicvf;
	nicvf_dump_regs(&pkt_nicvf->nicvf);
}

/**
 * Global callback table for interface functions
 */
pktio_if_ops_t nicvf_pktio_ops = {
	/* TODO PKTIO: add missing pktio callbacks */
	.name = "thunderx-nicvf",
	.init_global = nicvf_pktio_init_global,
	.init_local = nicvf_pktio_init_local,
	.term = nicvf_pktio_term,
	.open = nicvf_pktio_open,
	.close = nicvf_pktio_close,
	.start = nicvf_pktio_start,
	.stop = nicvf_pktio_stop,
	.stats = nicvf_pktio_stats,
	.stats_reset = nicvf_pktio_stats_reset,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.recv = NULL, /* dynamicly modified */
	.send = NULL, /* dynamicly modified */
	.mtu_get = nicvf_pktio_mtu_get,
	.promisc_mode_set = nicvf_pktio_promisc_mode_set,
	.promisc_mode_get = nicvf_pktio_promisc_mode_get,
	.mac_get = nicvf_pktio_mac_get,
	.link_status = nicvf_pktio_link_status,
	.capability = nicvf_pktio_capability,
	.config = nicvf_pktio_config,
	.input_queues_config = nicvf_pktio_input_queues_config,
	.output_queues_config = nicvf_pktio_output_queues_config,
};
