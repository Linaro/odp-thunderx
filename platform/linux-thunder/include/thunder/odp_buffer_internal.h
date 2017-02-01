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

/**
 * @file
 *
 * ODP buffer descriptor - implementation internal
 */

#ifndef THUNDER_ODP_BUFFER_INTERNAL_H_
#define THUNDER_ODP_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/buffer.h>
#include <odp/api/std_types.h>
#include <odp/api/atomic.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/byteorder.h>

/* this can help catch bugs in buffer allocation code
   or give additional possibilites for future
   developlent but dramaticly decrease the performance
   by 50% due to cache missies during alloc() */
//#define ODP_BUFFER_REFCNT

ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

ODP_STATIC_ASSERT((ODP_CONFIG_PACKET_SEG_LEN_MIN % ODP_CACHE_LINE_SIZE) == 0,
		  "ODP Segment size must be a multiple of cache line size");

ODP_STATIC_ASSERT((ODP_CONFIG_PACKET_BUF_LEN_MAX %
		   ODP_CONFIG_PACKET_SEG_LEN_MIN) == 0,
		  "Packet max size must be a multiple of segment size");

ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_BUF_LEN_MAX < 65536,
		  "Packet max size must be less than 65536");
/* Common buffer header
 *
 * Buffer is the basic entity in ODP. There are try types of buffers:
 * - packet buffer
 * - timer
 * - raw buffer
 * In case of packet buffers, the buffer header prepends the buffer data area.
 * Buffer keeps information about its size but not about the actual length of
 * data that are stored there. Those information are keept in packet_hdr_t */
struct odp_buffer_hdr_t {
/* Temporary integration with generic scheduler
 * TODO OTHER: investigate integration effort for our scheduler
 */
	void			*data;
	union {
	struct {
		uint64_t    fl_zeroized:1;
		uint64_t    fl_hdrdata:1;
		uint64_t    fl_sustain:1;
		uint64_t    fl_reserved:5;
		uint64_t    type:7;
		uint64_t    seg_count:7;
		uint64_t    data_size:14;
		uint64_t    total_size:14;
		uint64_t    udata_size:14;
	};
	union {
		uint8_t all;
		struct {
			uint8_t zeroized:1;
			uint8_t hdrdata:1;
			uint8_t sustain:1;
			uint8_t reserved:5;
		};
	} flags;
	};
	struct odp_buffer_hdr_t     *next_seg;
	struct pool_entry_s    *pool;
	void			*udata;
#ifdef ODP_BUFFER_REFCNT
	odp_atomic_u16_t         ref_count;
#endif
	struct odp_buffer_hdr_t           *next;
	struct odp_buffer_hdr_t           *link;
	uint64_t                 order;
	queue_entry_t           *origin_qe;
	union {
		queue_entry_t   *target_qe;
		uint64_t         sync[SCHEDULE_ORDERED_LOCKS_PER_QUEUE];
	};
} __attribute__((packed));

/* TODO CLEANUP: fix conflicting names */
#if 1
struct odp_buffer_hdr_t* buffer_alloc(struct pool_entry_s *pool, size_t size);
void buffer_free(struct pool_entry_s *pool, struct odp_buffer_hdr_t *buf);
//void *buffer_map(struct odp_buffer_hdr_t *buf, uint32_t offset, uint32_t *seglen,
//		 uint32_t limit);
int buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);
#endif

#ifdef __cplusplus
}
#endif

#endif
