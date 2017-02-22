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
#include <string.h>
#include <assert.h>

#include "thunder/nicvf/nic.h"
#include "thunder/nicvf/nic_reg.h"
#include "thunder/nicvf/nic_vfio.h"
#include "thunder/nicvf/nic_mbox.h"

#include "thunder/nicvf/nic_vfmain.h"


/* Clear interrupt */
static void nicvf_qset_clear_intr(struct queue_set *qset, int int_type)
{
	uint64_t reg_val = 0;

	switch (int_type) {
	case NICVF_INTR_PKT_DROP:
		reg_val = (1ULL << NICVF_INTR_PKT_DROP_SHIFT);
	break;
	case NICVF_INTR_TCP_TIMER:
		reg_val = (1ULL << NICVF_INTR_TCP_TIMER_SHIFT);
	break;
	case NICVF_INTR_MBOX:
		reg_val = (1ULL << NICVF_INTR_MBOX_SHIFT);
	break;
	case NICVF_INTR_QS_ERR:
		reg_val = (1ULL << NICVF_INTR_QS_ERR_SHIFT);
	break;
	case NICVF_INTR_ALL:
		reg_val = NICVF_INTR_ALL_MASK;
	break;
	default:
		ERR("Failed to clear interrupt: unknown type\n");
	break;
	}

	/* there is one register per each 8 queues in QSet */
	nicvf_vf_reg_write(qset, NIC_VF_INT, reg_val);
}

static void nicvf_handle_mbx_intr(struct queue_set *qset)
{
	(void)nicvf_mbox_read_response(qset);
}

/* Warning. This function is not reentrant.
 * Caller of this functionmust provide proper serialization. */
static void nicvf_poll_misc(struct queue_set *qset)
{
	uint64_t intr;

	/* we use interrupt register to check which NIC part need handling */
	intr = nicvf_vf_reg_read(qset, NIC_VF_INT);
	if (intr & NICVF_INTR_MBOX_MASK) {
		DBGV1("IRQ: Mbox\n");
		nicvf_qset_clear_intr(qset, NICVF_INTR_MBOX);
		nicvf_handle_mbx_intr(qset);
	}

	if (intr & NICVF_INTR_QS_ERR_MASK) {
		DBGV1("IRQ: QS_ERR\n");
		nicvf_qset_clear_intr(qset, NICVF_INTR_QS_ERR);
		nicvf_intr_handler_qserr(qset);
	}
}

static void* nicvf_housekeeping_thread(void* param)
{
	struct nicvf *nic = (struct nicvf*)param;
	struct queue_set *qset;
	size_t i;

	nic->housekeeping_run = true;
	wmb();
	while (nic->housekeeping_work) {
		usleep(50000); /* 50ms */

		for (i = 0; i < nic->qset_cnt; i++) {
			qset = &nic->qset[i];
			/* housekeeping is something different than enable flag
			 * we need to housekeep even if qset is dissabled */
			if (qset->housekeeping)
				nicvf_poll_misc(qset);
		}
	}

	return NULL;
}

int nicvf_close(struct nicvf *nic)
{
	size_t i;
	struct queue_set *qset;

	for (i = 0; i < nic->qset_cnt; i++) {

		qset = &nic->qset[i];

		if (qset->enable) {

			if (nicvf_qset_close(qset)) {
				ERR("Error while closing NIC queue qset\n");
				/* just ignore it and try to continue */
			}

			if (nicvf_mbox_vf_shutdown(qset)) {
				ERR("Error while comunicating to PF that VF is going down\n");
				/* just ignore it and try to continue */
			}

			/* one from many things is stop handling mbox for that qset */
			qset->housekeeping = false;
		}
	}

	nic->housekeeping_work = false;
	if (pthread_join(nic->thread_housekeeping, NULL)) {
		ERR("Cannot join housekeeping thread\n");
		/* just ignore and try to continue */
	}

	return 0;
}

int nicvf_open(struct nicvf *nic, const uint8_t mac[ETH_ALEN], bool set_mac)
{
	struct queue_set *qset;
	union nic_mbx res = { .msg = { 0 } };
	size_t i, qset_cnt;
	bool disabled = false;

	/* initialize qset structs */
	qset_cnt = 0;

	for (i = 0; i < MAX_QSETS_PER_NIC; i++) {

		qset = &nic->qset[i];

		if (qset->enable) {

			qset->qset_idx = i;
			qset->nic = nic;

			/* Reset all HW blocks (only reset by registers) */
			if (nicvf_qset_reset(qset)) {
				ERR("Cannot reset HW!\n");
				return -1;
			}

			/* disable and confirm all interrupts which may preserved from last
			 * userspace session */
			nicvf_vf_reg_write(qset, NIC_VF_ENA_W1C, NICVF_INTR_ALL_MASK);
			nicvf_vf_reg_write(qset, NIC_VF_INT, NICVF_INTR_ALL_MASK);

			/* housekeeping is something different than enable flag
			 * for instance we need handle mbox before we mark qset
			 * as enabled */
			qset->housekeeping = true;

			/* initialize essential qset fields */
			nicvf_qset_preinit(qset);

			assert(false == disabled && "qset table must be without gaps\n");
			qset_cnt++;
		} else {
			/* clear memory for BUG checking */
			memset(qset, 0, sizeof(*qset));
			disabled = true;
		}
	}
	nic->qset_cnt = qset_cnt;

	/* start housekeeping thread, we need it for mbox handling */
	nic->housekeeping_work = true;
	nic->housekeeping_run = false;
	if (pthread_create(&nic->thread_housekeeping, NULL,
			   nicvf_housekeeping_thread, nic)) {
		ERR("Cannot create housekeeping thread\n");
		/* TODO some bailout needed here !! */
		return -1;
	}
	/* wait for housekeeping thread start */
	while(!nic->housekeeping_run);

	/* Check if VF is able to communicate with PF */
	/* first QSet is master for whole NIC */
	assert(nic->qset[0].enable);
	if (nicvf_mbox_ready_qset(&nic->qset[0], &res)) {
		ERR("Cannot make READY of Qset-0\n");
		return -1;
	}

	nic->tns_mode = res.nic_cfg.tns_mode & 0x7F;
	nic->node = res.nic_cfg.node_id;
	if (res.nic_cfg.sqs_mode != 0) {
			ERR("Device %u is not a primary VF.\n", nicvf_dev_num(nic, 0));
			return -1;

	}
	memcpy(nic->mac_addr, &res.nic_cfg.mac_addr, ETH_ALEN);

	/* for additional QSets just mark them as ready */
	for (i = 1; i < nic->qset_cnt; i++) {
		if (nicvf_mbox_ready_qset(&nic->qset[i], &res)) {
			ERR("Cannot make READY of Qset-%zu\n", i);
			return -1;
		}
		if (res.nic_cfg.sqs_mode != 1) {
			ERR("Device %u is not a secondary VF.\n", nicvf_dev_num(nic, i));
			return -1;
		}
	}

#ifdef VNIC_MULTI_QSET_SUPPORT
	if (qset_cnt > 1) {
		if (nicvf_mbox_qset_allocate_sqs(nic)) {
			ERR("nicvf_mbox_qset_allocate_sqs() failed");
			return -1;
			/* TODO some bailout needed here !! */
		}
	}
#endif

	/* required because kernel does not respond for mbx */
	usleep(100000);

	if (set_mac) {
		if (nicvf_mac_set(nic, mac)) {
			ERR("Cannot set initial mac addr\n");
			return -1;
			/* TODO some bailout needed here !! */
		}
	}

	nic->mtu = NIC_HW_MAX_FRS;
	if (nicvf_mbox_update_hw_max_frs(nic, nic->mtu)) {
	       ERR("Canot configure MTU\n");
	       return -1;
		/* TODO some bailout needed here !! */
	}

	/* Initialize internal structures such as buffer descriptors */
	for (i = 0; i < nic->qset_cnt; i++) {
		if (nicvf_qset_init(&nic->qset[i])) {
			ERR("Canot initialize QSETs\n");
			/* TODO some bailout needed here !! */
			return -1;
		}
	}

	/* Make sure queue initialization is written */
	wmb();
	DBG("VNIC Open success!\n");

	return 0;
}

uint16_t nicvf_mtu(struct nicvf *nic)
{
	return nic->mtu;
}

int nicvf_mac_set(struct nicvf *nic, const uint8_t mac[ETH_ALEN])
{
	/* Send message to PF to setup the MAC */
	if (nicvf_mbox_set_mac_addr(nic, mac)) {
		ERR("Cannot set mac addr\n");
		return -1;
	}

	memcpy(&nic->mac_addr, mac, ETH_ALEN);
	return 0;
}

int nicvf_mac_get(struct nicvf *nic, uint8_t mac[ETH_ALEN], size_t len)
{
	if (len < ETH_ALEN) {
		return -1;
	}
	memcpy(mac, &nic->mac_addr, ETH_ALEN);
	return 0;
}

