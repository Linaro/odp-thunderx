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

#ifndef THUNDER_ODP_PACKET_NICVF_H
#define THUNDER_ODP_PACKET_NICVF_H

#include <thunder/nicvf/nic.h>

/** Packet IO using ThunderX NICVF interface */
typedef struct {
	struct nicvf nicvf;		/**< ThunderX NIC structure */
	struct pool_entry_s *pool;	/**< Memory poll assosiated with NIC */
	enum nicvf_type type;		/**< NICVF type (uio, vfio) used only for reference during pktio_if_search */
	struct buffer_pool_info {
		void* uva;		/**< Address of buffer pool */
		uint64_t iova;		/**< IO virtual address assosiated with buffer pool */
		size_t size;		/**< Size of memory assosiated with buffer pool */
	} pool_info;			/**< Temporal info about buffer pool needed for later free operation */
	size_t qs_cnt;
	unsigned qs_id[MAX_QSETS_PER_NIC];
	uint8_t txq_cnt;
	uint8_t rxq_cnt;
} pkt_nicvf_t;

#endif
