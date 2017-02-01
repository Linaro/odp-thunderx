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
#include <stdlib.h>
#include <pthread.h>

#include <odp/api/std_types.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp/api/align.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp/api/thread.h>
#include <odp/api/spinlock.h>
#include <odp/api/system_info.h>
#include <odp_internal.h>
#include <odp_buffer_internal.h>
#include <odp_shm_internal.h>
#include <odp_pool_internal.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <odp_atomic_internal.h>

#if defined(ODP_CONFIG_SECURE_POOLS) && (ODP_CONFIG_SECURE_POOLS == 1)
#define buffer_is_secure(buf) (buf->flags.zeroized)
#define pool_is_secure(pool) (pool->flags.zeroized)
#else
#define buffer_is_secure(buf) 0
#define pool_is_secure(pool) 0
#endif

#define TAG_ALIGN ((size_t)16)

#define odp_cs(ptr, old, new) \
	_odp_atomic_ptr_cmp_xchg_strong(&ptr, (void **)&old, (void *)new, \
					_ODP_MEMMODEL_SC, \
					_ODP_MEMMODEL_SC)

/* Helper functions for pointer tagging to avoid ABA race conditions */
#define odp_tag(ptr) \
	(((size_t)ptr) & (TAG_ALIGN - 1))

#define odp_detag(ptr) \
	((void *)(((size_t)ptr) & -TAG_ALIGN))

#define odp_retag(ptr, tag) \
	((void *)(((size_t)ptr) | odp_tag(tag)))

union buffer_any_t {
	struct odp_buffer_hdr_t buf;
	odp_timeout_hdr_t time;
	struct packet_hdr_t packet;
};

static odp_spinlock_t pool_spin; /* global pool list spin */
static struct pool_entry_s *pool_list; /* global list of all created pool's */

void odp_buffer_pool_free_bufs(
	odp_pool_t pool, uint64_t * __restrict glob, uint64_t * __restrict loc)
{
	struct buffer_cache_t *cache = &((struct pool_entry_s *)pool)->local_cache[odp_thread_id()];
	if (glob)
		*glob = odph_ring_count(((struct pool_entry_s *)pool)->global_bufs);
	if (loc)
		*loc = cache->bufcount;
}


/* Init buffer common headers and add to pool buffers freelist
 * Keep in mind that buffers are sliced with assumption about correct buffer
 * size depending on type */
static void slice_buffers(struct pool_entry_s* __restrict__ pool)
{
	struct odp_buffer_hdr_t *buf;
	odph_ring_t *global_bufs = pool->global_bufs;
	uint8_t *ptr = pool->buffers_base_addr;
	size_t i;

	for (i = 0; i < pool->params.buf.num; i++) {

		/* We assume that on ThunderX all memory for buffers is
		 * physically continuous, so we dont have to think about page
		 * boundaries (look at shared_memory.c) */
		buf = (struct odp_buffer_hdr_t*)ptr;

		buf->data = (uint8_t*)buf + pool->hdr_size;
		buf->data_size = pool->data_size;
		buf->udata = (uint8_t*)buf + pool->hdr_size + pool->data_size;
		buf->udata_size = pool->udata_size;
		buf->type = pool->params.type;
		buf->next_seg = NULL;
		buf->pool = pool;
#ifdef ODP_BUFFER_REFCNT
		odp_atomic_init_u16(&buf->ref_count, 0);
#endif
		/* following two will be updated by each buff allocation
		 * depending on segment count */
		buf->seg_count = 1;
		buf->total_size = pool->data_size;

		/* Push bufer onto pool's freelist */
		odph_ring_sp_enqueue_bulk(global_bufs, (void * const *)&buf, 1);
		ptr += pool->seg_size;
	}
}

/* WARNING using of this function is potentialy unsafe, since local caches are
 * not protected from concurrent access */
static void flush_buffer_cache(struct pool_entry_s *pool)
{
	size_t i;

	for (i = 0; i < ODP_CONFIG_MAX_THREADS; i++) {
		struct buffer_cache_t *cache =
			&pool->local_cache[i];

		odph_ring_mp_enqueue_bulk(pool->global_bufs,
			(void * const *)cache->local_bufs, cache->bufcount);
		cache->bufcount = 0;
	}
}

static void flush_all_caches(void)
{
	struct pool_entry_s *pool;

	odp_spinlock_lock(&pool_spin);
	pool = pool_list;
	while (pool) {
		flush_buffer_cache(pool);
		pool = pool->next;
	}
	odp_spinlock_unlock(&pool_spin);
}


size_t buffer_rawalloc_cache_precharge(struct pool_entry_s *pool)
{
	struct buffer_cache_t *cache =
		&pool->local_cache[odp_thread_id()];
	struct odp_buffer_hdr_t **cached_bufs = cache->local_bufs;
	size_t refill_cnt;
	int ret;

	if (odp_unlikely(cache->bufcount >= ODP_CONFIG_POOL_CACHE_SIZE))
		return 0;

	refill_cnt = ODP_CONFIG_POOL_FLUSH_SIZE - cache->bufcount;
	ret = odph_ring_mc_dequeue_bulk(pool->global_bufs,
			(void **)&cached_bufs[cache->bufcount], refill_cnt);
	if (odp_unlikely(ret < 0))
		return 0;

	cache->bufcount += refill_cnt;
	return refill_cnt;
}

int buffer_rawalloc_cache_bulk(struct pool_entry_s *pool, size_t n,
			    struct odp_buffer_hdr_t* bufs[n],
			    uintptr_t addoffset)
{
	struct buffer_cache_t *cache =
		&pool->local_cache[odp_thread_id()];
	struct odp_buffer_hdr_t **cached_bufs = cache->local_bufs;
	size_t i;

	if (odp_unlikely(n > cache->bufcount))
		return -1;

	/* take elements from the end of cache table */
	cached_bufs += cache->bufcount - n;
	for (i = 0; i < n; i++, bufs++, cached_bufs++) {
#ifdef ODP_BUFFER_REFCNT
		odp_atomic_add_u16(&((*cached_bufs)->ref_count), 1);
#endif
		*bufs = (struct odp_buffer_hdr_t*)((uintptr_t)*cached_bufs + addoffset);
	}
	cache->bufcount -= n;


	return 0;
}

int buffer_rawalloc_bulk(struct pool_entry_s *pool, size_t n,
		      struct odp_buffer_hdr_t* bufs[n],
		      uintptr_t addoffset)
{
	int ret;
	struct buffer_cache_t *cache =
		&pool->local_cache[odp_thread_id()];
	struct odp_buffer_hdr_t **cached_bufs = cache->local_bufs;
	size_t i;
	size_t refill_cnt;

	if (odp_unlikely(n > ODP_CONFIG_POOL_CACHE_SIZE))
		goto global_dequeue;

	if (odp_unlikely(cache->bufcount < n)) {
		refill_cnt = n + ODP_CONFIG_POOL_CACHE_SIZE - cache->bufcount;

		ret = odph_ring_mc_dequeue_bulk(pool->global_bufs,
				(void **)&cached_bufs[cache->bufcount], refill_cnt);
		if (odp_unlikely(ret < 0))
			goto global_dequeue;

		cache->bufcount += refill_cnt;
	}


	cached_bufs += cache->bufcount - n;
	for (i = 0; i < n; i++, bufs++, cached_bufs++) {
#ifdef ODP_BUFFER_REFCNT
		odp_atomic_add_u16(&((*cached_bufs)->ref_count), 1);
#endif
		*bufs = (struct odp_buffer_hdr_t*)((uintptr_t)*cached_bufs + addoffset);
	}

	cache->bufcount -= n;

	return 0;

global_dequeue:

	ret = odph_ring_mc_dequeue_bulk(pool->global_bufs, (void **)bufs, n);
	if (ret)
		return -1;
	for (i = 0; i < n; i++, bufs++) {
#ifdef ODP_BUFFER_REFCNT
		odp_atomic_add_u16(&((*bufs)->ref_count), 1);
#endif
		*bufs = (struct odp_buffer_hdr_t*)((uintptr_t)*bufs + addoffset);
	}

	return 0;
}


int buffer_free_bulk(struct pool_entry_s *pool, size_t n,
		     struct odp_buffer_hdr_t* bufs[n])
{
	int ret;
	struct buffer_cache_t *cache =
		&pool->local_cache[odp_thread_id()];
	struct odp_buffer_hdr_t **cached_bufs = cache->local_bufs;
	size_t i;
	size_t cache_len = ODP_CONFIG_POOL_CACHE_SIZE;
	size_t cache_flush_len = ODP_CONFIG_POOL_FLUSH_SIZE;

	/* This funtion strivers to keep cache utilization
	 * between cache_len and cach_flush_len (512<bufcount<768).
	 * Cache should not be kept empty because all packet allocations
	 * to RBDR are done only from local cache.
	 * Also, spilling to global pool must be done with bufcount > 256
	 * (global spill is slow due to costly CAS operation).
	 */

	if (cache->bufcount > cache_flush_len) {
		/* anything above must be spilled into global pool */
		ret = odph_ring_mp_enqueue_bulk(pool->global_bufs,
					(void **)&cached_bufs[cache_len],
					cache->bufcount - cache_len);
		if (odp_unlikely(ret < 0))
			return ret;
		cache->bufcount = cache_len;
	}


	if (odp_unlikely(n > cache_len)) {
		/* anything above must be spilled into global pool */
		ret = odph_ring_mp_enqueue_bulk(pool->global_bufs,
							(void **)bufs, n);
		return ret;
	}

	/* store in local cache */
	cached_bufs += cache->bufcount;
	for (i = 0; i < n; i++, bufs++, cached_bufs++) {
#ifdef ODP_BUFFER_REFCNT
		uint16_t ref_cnt = odp_atomic_fetch_sub_u16(&((*bufs)->ref_count), 1);
		ODP_ASSERT(ref_cnt == 1, "Alloc/free mismatch ?"); /* not supporting multireference for now */
#endif
		*cached_bufs = *bufs;
	}
	cache->bufcount += n;

	return 0;
}

struct odp_buffer_hdr_t* buffer_alloc(struct pool_entry_s *pool, size_t size)
{
	struct odp_buffer_hdr_t *buf = (struct odp_buffer_hdr_t *)ODP_BUFFER_INVALID;
	size_t totsize;
	size_t nsegs;
	size_t i;

	totsize = (size > 0) ?
		pool->pkt_alloc.headroom + size +
		pool->pkt_alloc.tailroom : 0;

	/* Reject oversized allocation requests */
	if ((pool->flags.unsegmented && totsize > pool->data_size) ||
	    (!pool->flags.unsegmented &&
	     totsize > ODP_CONFIG_PACKET_BUF_LEN_MAX))
		return (struct odp_buffer_hdr_t *)ODP_BUFFER_INVALID;

	/* By default, buffers inherit their pool's zeroization setting
	 * XXX: Is it needed here? */
	nsegs = ((0 == totsize) || (0 == pool->data_size)) ? (size_t)1 :
		( (totsize / pool->data_size) +
		  ((totsize % pool->data_size) > 0 ? (size_t)1 : 0));
	do {
		struct odp_buffer_hdr_t *bufs[nsegs]; /* use dynamic sized table on stack */

		if (buffer_rawalloc_bulk(pool, nsegs, bufs, 0))
			return (struct odp_buffer_hdr_t *)ODP_BUFFER_INVALID;

		/* chain the buffer segments into list */
		for (i = 0;  i < nsegs; i++) {
			bufs[i]->next_seg = (i < nsegs - 1) ? bufs[i + 1] : NULL;
		}

		/* initialize segmented buffer fields */
		bufs[0]->seg_count = nsegs;
		bufs[0]->total_size = nsegs * pool->data_size;

		/* return pointer to first segment */
		buf = bufs[0];
	} while (0);

	return buf;
}

int buffer_alloc_multi(odp_pool_t pool_hdl, size_t size,
		       odp_buffer_t buf[], int num)
{
	int count;

	for (count = 0; count < num; ++count) {
		buf[count] = (odp_buffer_t)buffer_alloc((struct pool_entry_s *)pool_hdl, size);
		if (buf[count] == ODP_BUFFER_INVALID)
			break;
	}

	return count;
}

void buffer_free(struct pool_entry_s *pool, struct odp_buffer_hdr_t *buf)
{
	size_t i;
	size_t nsegs = buf->seg_count;

	struct odp_buffer_hdr_t *buf_tbl[nsegs];

	buf_tbl[0] = buf;

	for (i = 1; i < nsegs; i++) {
		buf = buf->next_seg;
		buf_tbl[i] = buf;
		/* No need to de-chain buffers as they will be chained properly
		 * when allocated */
	}

	buffer_free_bulk(pool, nsegs, buf_tbl);
}

size_t buffer_segment_size(struct pool_entry_s *pool)
{
	return pool->data_size - pool->pkt_alloc.headroom - pool->pkt_alloc.tailroom;
}

size_t buffer_segment_headroom(struct pool_entry_s *pool)
{
	return pool->pkt_alloc.headroom;
}

size_t buffer_segment_tailroom(struct pool_entry_s *pool)
{
	return pool->pkt_alloc.tailroom;
}

/******************************************************************************
 * Public API functions
 ******************************************************************************/

int odp_pool_init_global(void)
{
	odp_spinlock_init(&pool_spin);
	return 0;
}

int odp_pool_term_global(void)
{
	flush_all_caches();
	return 0;
}

int odp_pool_init_local(void)
{
	return 0;
}

int odp_pool_term_local(void)
{
	return 0;
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pool_capability_t));

	capa->max_pools = ODP_CONFIG_POOLS;

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = 0;
	capa->buf.max_num   = 0;

	/* Packet pools */
	capa->pkt.max_pools        = ODP_CONFIG_POOLS;
	capa->pkt.max_len          = ODP_CONFIG_PACKET_MAX_SEGS *
				     ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_num	   = 0;
	capa->pkt.min_headroom     = ODP_CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = ODP_CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = ODP_CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = 0;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = 0;

	return 0;
}

static int lg(int n)
{
	return sizeof(int) * __CHAR_BIT__  - 1 - __builtin_clz(n);
}

/**
 * Buffer pool creation
 */
static odp_pool_t odp_pool_create_internal(const char *name,
	size_t headroom, size_t tailroom, size_t num,
	size_t align, size_t hdr_size, size_t udata_size,
	size_t data_size, odp_pool_param_t* params)
{
	/* allocate and initialize pool */
	size_t bufs_pow2;
	char s[ODP_SHM_NAME_LEN];
	struct pool_entry_s *pool;
	odp_shm_t pool_struct_shm;
	odp_shm_t shm;

	snprintf(s, sizeof(s)/sizeof(s[0]), "s_%s", name);

	pool_struct_shm = odp_shm_reserve(s, sizeof(*pool), ODP_CACHE_LINE_SIZE, 0);
	if (pool_struct_shm == ODP_SHM_INVALID) {
		ODP_ERR("Cannot allocate pool\n");
		return ODP_POOL_INVALID;
	}

	pool = odp_shm_addr(pool_struct_shm);
	pool->pool_struct_shm = pool_struct_shm;

	/* calculate total required pool size
	 * all fields tahen into acount are already rounded to required aligment */
	pool->seg_size = hdr_size + udata_size + data_size;
	pool->pool_size = ODP_PAGE_SIZE_ROUNDUP(num * pool->seg_size);

	pool->params = *params;
	pool->pkt_alloc.headroom = headroom;
	pool->pkt_alloc.tailroom = tailroom;
	/* In fact, udata may be bigger than uarea param but ODP unit tests assume it is equal. */
	pool->udata_size = params->pkt.uarea_size;
	pool->data_size = data_size;
	pool->hdr_size = hdr_size;
	pool->buf_align = align;
	if (name) {
		strncpy(pool->name, name,
			ODP_POOL_NAME_LEN - 1);
		pool->name[ODP_POOL_NAME_LEN - 1] = 0;
		pool->flags.has_name = 1;
	}

	/* allocate global buffer ring */
	snprintf(s, sizeof(s)/sizeof(s[0]), "ring@%p", pool);
	bufs_pow2 = 2 << lg(params->buf.num);
	pool->global_bufs = odph_ring_create(s, bufs_pow2, 0);
	if (pool->global_bufs == NULL) {
		ODP_ERR("Cannot allocate global buffer ring\n");
		odp_shm_free(pool_struct_shm);
		return ODP_POOL_INVALID;

	}

#if ODP_CONFIG_POOL_STATS
	/* Initialization will increment these to their target vals */
	odp_atomic_store_u32(&pool->bufcount, 0);

	/* Initialize pool statistics counters */
	odp_atomic_store_u64(&pool->bufallocs, 0);
	odp_atomic_store_u64(&pool->buffrees, 0);
	odp_atomic_store_u64(&pool->bufempty, 0);
	odp_atomic_store_u64(&pool->high_wm_count, 0);
	odp_atomic_store_u64(&pool->low_wm_count, 0);
#endif
	/* Reset other pool globals to initial state */
	pool->quiesced = 0;

	shm = odp_shm_reserve(pool->name,
			      pool->pool_size,
			      odp_sys_page_size(), 0);
	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("Error while allocating shared memory for pool\n");
		odp_shm_free(pool_struct_shm);
		return ODP_POOL_INVALID;
	}
	pool->pool_buffer_shm = shm;
	pool->pool_base_addr = odp_shm_addr(shm);

	/* buffers memory is placed after caches */
	pool->buffers_base_addr = (int8_t *)pool->pool_base_addr;

	/* Slice the shared memory area into buffers */
	slice_buffers(pool);

	/* add pool to the global list */
	odp_spinlock_lock(&pool_spin);
	pool->next = pool_list;
	pool_list = pool;
	odp_spinlock_unlock(&pool_spin);

	return (odp_pool_t)pool;
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}

odp_pool_t odp_pool_create(const char *name, odp_pool_param_t *params)
{
	size_t headroom = 0; /* only used in case of ODP_BUFFER_TYPE_PACKET */
	size_t tailroom = 0;
	size_t udata_size = 0;
	size_t num;
	size_t seg_len;
	size_t required_len;
	size_t required_segs;
	size_t data_size, hdr_size;
	size_t buf_align;

	if (params == NULL)
		return ODP_POOL_INVALID;

	/* Default size and align for timeouts */
	if (params->type == ODP_POOL_TIMEOUT) {
		params->buf.size  = 0; /* tmo.__res1 */
		params->buf.align = 0; /* tmo.__res2 */
	}

	buf_align = params->type == ODP_POOL_BUFFER ? params->buf.align : 0;

	/* Validate requested buffer alignment */
	if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    buf_align != ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align))
		return ODP_POOL_INVALID;

	/* Set correct alignment based on input request */
	if (buf_align == 0)
		buf_align = ODP_CACHE_LINE_SIZE;
	else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Calculate space needed for buffer blocks and metadata */
	switch (params->type) {
	case ODP_POOL_BUFFER:
		data_size = ODP_ALIGN_ROUNDUP(params->buf.size, buf_align);
		hdr_size = ODP_CACHE_LINE_SIZE_ROUNDUP(
				sizeof(struct odp_buffer_hdr_t));
		num = params->buf.num;
		break;

	case ODP_POOL_PACKET:
		headroom = ODP_CONFIG_PACKET_HEADROOM;
		tailroom = ODP_CONFIG_PACKET_TAILROOM;

		seg_len = odp_max(
		   odp_min((size_t)(params->pkt.seg_len), (size_t)ODP_CONFIG_PACKET_BUF_LEN_MAX),
		   (size_t)ODP_CONFIG_PACKET_SEG_LEN_MIN);

		required_len = params->pkt.len <= seg_len ? seg_len :
			ODP_ALIGN_ROUNDUP(params->pkt.len, seg_len);

		required_segs = required_len / seg_len;

		if (required_segs > ODP_BUFFER_MAX_SEG)
			return ODP_POOL_INVALID;

		num = required_segs * params->pkt.num;

		data_size = ODP_ALIGN_ROUNDUP(
			headroom + seg_len + tailroom,
			buf_align);

		hdr_size = ODP_CACHE_LINE_SIZE_ROUNDUP(
				sizeof(struct packet_hdr_t));

		udata_size = ODP_CACHE_LINE_SIZE_ROUNDUP(
			params->pkt.uarea_size);

		break;

	case ODP_POOL_TIMEOUT:
		hdr_size = ODP_CACHE_LINE_SIZE_ROUNDUP(
				sizeof(odp_timeout_hdr_t));
		data_size = 0;
		num = params->tmo.num;
		break;

	default:
		return ODP_POOL_INVALID;
	}

	return odp_pool_create_internal(name, headroom, tailroom, num,
					buf_align, hdr_size, udata_size,
					data_size, params);
}

odp_pool_t odp_pool_lookup(const char *name)
{
	struct pool_entry_s *pool;

	odp_spinlock_lock(&pool_spin);
	pool = pool_list;
	while (pool) {
		if (strcmp(name, pool->name) == 0) {
			/* found it */
			break;
		}
		pool = pool->next;
	}
	odp_spinlock_unlock(&pool_spin);

	return (pool) ? (odp_pool_t)pool : ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	struct pool_entry_s *pool = (struct pool_entry_s *)pool_hdl;

	if (pool == NULL || info == NULL)
		return -1;

	memset(info, 0, sizeof(*info));
	info->name = pool->name;
	info->params.buf.size  = pool->params.buf.size;
	info->params.buf.align = pool->params.buf.align;
	info->params.buf.num  = pool->params.buf.num;
	info->params.type  = pool->params.type;

	return 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	struct pool_entry_s *pool = (struct pool_entry_s *)pool_hdl;

	if (pool == NULL)
		return -1;

	odp_spinlock_lock(&pool_spin);

	/* Call fails if pool is predefined*/
	if (pool->flags.predefined) {
		ODP_ERR("Cannot free predefined pool's\n");
		odp_spinlock_unlock(&pool_spin);
		return -1;
	}

	/* Make sure local caches are empty
	 * \TODO OTHER: \FIXME this is unsafe!!! */
	flush_buffer_cache(pool);

	/* Call fails if pool has allocated buffers */
	if (odph_ring_count(pool->global_bufs) < pool->params.buf.num) {
		ODP_ERR("Not all buffers where returned to pool, therefore it"
			" cannot be freed\n");
		odp_spinlock_unlock(&pool_spin);
		return -1;
	}

	/* free global buffer ring */
	if (odph_ring_destroy(pool->global_bufs))
		ODP_ERR("Error while freeing global_ring\n");

	/* free shm for buffer memory */
	odp_shm_free(pool->pool_buffer_shm);
	pool->pool_buffer_shm = ODP_SHM_INVALID;

	/* Remove the pool from global list */
	if (pool == pool_list) {

		pool_list = pool->next;
	}
	else {
		struct pool_entry_s *pool_prev = pool_list;
		while (pool_prev && pool != pool_prev->next)
			pool_prev = pool_prev->next;
		if (pool_prev)
			pool_prev->next = pool->next;
	}

	odp_shm_t pool_struct_shm = pool->pool_struct_shm;
	memset(pool, 0, sizeof(*pool)); /* overwrite the pool struct memory */
	odp_shm_free(pool_struct_shm);

	odp_spinlock_unlock(&pool_spin);
	return 0;
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool)
{
	return (odp_buffer_t)buffer_alloc((struct pool_entry_s *)pool, ((struct pool_entry_s *)pool)->params.buf.size);
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	size_t buf_size = ((struct pool_entry_s *)pool_hdl)->params.buf.size;

	return buffer_alloc_multi(pool_hdl, buf_size, buf, num);
}

void odp_buffer_free(odp_buffer_t buf)
{
	buffer_free(((struct odp_buffer_hdr_t *)buf)->pool, (struct odp_buffer_hdr_t *)buf);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	while (num--)
		odp_buffer_free(buf[num]);
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	struct pool_entry_s *pool = (struct pool_entry_s *)pool_hdl;

	uint32_t bufcount  = odph_ring_count(pool->global_bufs);
#if ODP_CONFIG_POOL_STATS
	uint64_t bufallocs = odp_atomic_load_u64(&pool->bufallocs);
	uint64_t buffrees  = odp_atomic_load_u64(&pool->buffrees);
	uint64_t bufempty  = odp_atomic_load_u64(&pool->bufempty);
	uint64_t hiwmct    = odp_atomic_load_u64(&pool->high_wm_count);
	uint64_t lowmct    = odp_atomic_load_u64(&pool->low_wm_count);
#endif
	ODP_PRINT("Pool info\n");
	ODP_PRINT("---------\n");
	ODP_PRINT(" name            %s\n",
		pool->flags.has_name ? pool->name : "Unnamed Pool");
	ODP_PRINT(" pool type       %s\n",
		pool->params.type == ODP_POOL_BUFFER ? "buffer" :
	       (pool->params.type == ODP_POOL_PACKET ? "packet" :
	       (pool->params.type == ODP_POOL_TIMEOUT ? "timeout" :
		"unknown")));
	ODP_PRINT(" pool status     %s\n",
		pool->quiesced ? "quiesced" : "active");
	ODP_PRINT(" pool opts       %s, %s, %s\n",
		pool->flags.unsegmented ? "unsegmented" : "segmented",
		pool->flags.zeroized ? "zeroized" : "non-zeroized",
		pool->flags.predefined  ? "predefined" : "created");
	ODP_PRINT(" pool base       %p\n",  pool->pool_base_addr);
	ODP_PRINT(" pool size       %zu (%zu pages)\n",
		pool->pool_size, pool->pool_size / odp_sys_page_size());
	ODP_PRINT(" headroom        %u\n",  pool->pkt_alloc.headroom);
	ODP_PRINT(" tailroom        %u\n",  pool->pkt_alloc.tailroom);
	if (pool->params.type == ODP_POOL_BUFFER) {
		ODP_PRINT(" buf size        %zu\n", pool->params.buf.size);
		ODP_PRINT(" buf align       %u requested, %u used\n",
			pool->params.buf.align, pool->buf_align);
	} else if (pool->params.type == ODP_POOL_PACKET) {
		ODP_PRINT(" seg length      %u requested, %u used\n",
			pool->params.pkt.seg_len, pool->seg_size);
		ODP_PRINT(" pkt length      %u requested\n",
			pool->params.pkt.len);
	}
	ODP_PRINT(" num bufs        %u\n",  pool->params.buf.num);
	ODP_PRINT(" bufs available  %u\n", bufcount);
	ODP_PRINT(" bufs in use     %u\n",  pool->params.buf.num - bufcount);
#if ODP_CONFIG_POOL_STATS
	ODP_PRINT(" buf allocs      %lu\n", bufallocs);
	ODP_PRINT(" buf frees       %lu\n", buffrees);
	ODP_PRINT(" buf empty       %lu\n", bufempty);
	ODP_PRINT(" high wm value   %lu\n", ODP_CONFIG_POOL_FLUSH_SIZE);
	ODP_PRINT(" high wm count   %lu\n", hiwmct);
	ODP_PRINT(" low wm value    %lu\n", ODP_CONFIG_POOL_CACHE_SIZE);
	ODP_PRINT(" low wm count    %lu\n", lowmct);
#endif
}


odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return (odp_pool_t)((struct odp_buffer_hdr_t *)buf)->pool;
}

