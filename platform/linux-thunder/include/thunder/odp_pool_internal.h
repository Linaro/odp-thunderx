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
 * ODP buffer pool - internal header
 */

#ifndef THUNDER_ODP_POOL_INTERNAL_H_
#define THUNDER_ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/atomic.h>
#include <odp/api/thread.h>
#include <odp_atomic_internal.h>
#include <thunder/odph_ring.h>
#include <string.h>

#define ODP_CONFIG_POOL_CACHE_BUFFER_SIZE (ODP_CONFIG_POOL_CACHE_SIZE * 3)

/* Extra error checks */
/* #define POOL_ERROR_CHECK */

/* TODO CLEANUP: fix conflicting names */
#if 1
/* Local cache for buffer alloc/free acceleration */
struct buffer_cache_t {
	/* The local cache */
	struct odp_buffer_hdr_t	*local_bufs[ODP_CONFIG_POOL_CACHE_BUFFER_SIZE];
	/* Local buffer free count */
	uint32_t		bufcount;
} ODP_ALIGNED_CACHE;
#endif

/* Information needed for packet allocation
 * (used only if pool is used as packet allocator) */
struct pkt_alloc_t {
	size_t                  headroom;	/* Room in front of buffer */
	size_t                  tailroom;	/* Room after the buffer */
};

struct pool_entry_s {
	odph_ring_t             *global_bufs;
	odp_shm_t               pool_struct_shm;
	odp_shm_t               pool_buffer_shm;
	odp_pool_param_t	params;
	struct pkt_alloc_t	pkt_alloc;
	size_t                  pool_size;
	size_t                  hdr_size; /* size of buffer header */
	size_t                  udata_size; /* size of buffer udata section */
	size_t                  data_size; /* size of buffer data section */
	size_t			seg_size; /* total size of single segment buffer */
	size_t			buf_align; /* aligment used by pool */
	struct pool_entry_s	*next; /* next pool entry on list of all created pool's */
	union {
		uint32_t all;
		struct {
			uint32_t has_name:1;
			uint32_t unsegmented:1;
			uint32_t zeroized:1;
			uint32_t predefined:1;
		};
	} flags;

	uint32_t                quiesced;
	void                   *pool_base_addr;
	void                   *buffers_base_addr;
#if ODP_CONFIG_POOL_STATS
	odp_atomic_u32_t        bufcount;
	odp_atomic_u64_t        bufallocs;
	odp_atomic_u64_t        buffrees;
	odp_atomic_u64_t        bufempty;
	odp_atomic_u64_t        high_wm_count;
	odp_atomic_u64_t        low_wm_count;
#endif

/* TODO CLEANUP: fix conflicting names */
#if 1
	/* this is very big */
	struct buffer_cache_t    local_cache[ODP_CONFIG_MAX_THREADS] ODP_ALIGNED_CACHE;
#endif

	char                    name[ODP_POOL_NAME_LEN];
};

//struct odp_buffer_hdr_t* buffer_alloc(struct pool_entry_s *pool, size_t size);
void buffer_free(struct pool_entry_s *pool, struct odp_buffer_hdr_t *buf);
size_t buffer_segment_size(struct pool_entry_s *pool);
size_t buffer_segment_headroom(struct pool_entry_s *pool);
size_t buffer_segment_tailroom(struct pool_entry_s *pool);

size_t buffer_rawalloc_cache_precharge(struct pool_entry_s *pool);
int buffer_rawalloc_bulk(struct pool_entry_s *pool, size_t n,
		      struct odp_buffer_hdr_t* bufs[n],
		      uintptr_t addoffset);
int buffer_rawalloc_cache_bulk(struct pool_entry_s *pool, size_t n,
			    struct odp_buffer_hdr_t* bufs[n],
			    size_t addoffset);
int buffer_free_bulk(struct pool_entry_s *pool, size_t n,
		     struct odp_buffer_hdr_t* bufs[n]);

void odp_buffer_pool_free_bufs(odp_pool_t pool, uint64_t * __restrict glob,
			       uint64_t * __restrict loc);

#ifdef __cplusplus
}
#endif

#endif
