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
#include <stdio.h>

#include <odp/api/packet.h>
#include <odp_internal.h>
#include <odp_packet_internal.h>
#include <odp_pool_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>


#define PACKET_HDR_INVALID ((struct packet_hdr_t *)ODP_PACKET_INVALID)

/* ********************************************************
 * Internal Use Routines
 * ********************************************************/

static struct packet_hdr_t* packet_alloc(struct pool_entry_s *pool, size_t len);
static void packet_free(struct pool_entry_s *pool, struct packet_hdr_t *pkt);
static void packet_init(struct packet_hdr_t *pkt_hdr);
static int packet_push_head(struct packet_hdr_t *pkt, size_t len);
static int packet_pull_head(struct packet_hdr_t *pkt, size_t len);
static int packet_push_last_segment(struct packet_hdr_t *pkt, size_t len);
static int packet_push_tail(struct packet_hdr_t *pkt, size_t len);
static int packet_pull_tail(struct packet_hdr_t *pkt, size_t len);
static int packet_extend_head(struct packet_hdr_t **pkt, size_t len);
static int packet_trunc_head(struct packet_hdr_t **pkt, size_t len);
static int packet_extend_tail(struct packet_hdr_t **pkt, size_t len);
static int packet_trunc_tail(struct packet_hdr_t **pkt, size_t len);

/**
 * Initialize packet buffer
 * This function is intended only for packet_hdr_t initialization. This function
 * cannot magicaly gues how many data is stored in buffers and therefore it sets
 * all segment length's to 0. Total size is also set to 0.
 * For manipulating the packet lenghth use other functions.
 */
void packet_init(struct packet_hdr_t *pkt)
{
       /*
	* Reset parser metadata.  Note that we clear via memset to make
	* this routine indepenent of any additional adds to packet metadata.
	*/
	const size_t start_offset = ODP_FIELD_SIZEOF(struct packet_hdr_t, buf_hdr);
	struct pool_entry_s *pool = pkt->buf_hdr.pool;
	struct packet_hdr_t *seg;
	uint8_t *start;
	size_t len;

	start = (uint8_t *)pkt + start_offset;
	len = sizeof(struct packet_hdr_t) - start_offset;
	memset(start, 0, len);

	/* Set metadata items that initialize to non-zero values */
	pkt->hw.l2_offset = ODP_PACKET_OFFSET_INVALID;
	pkt->hw.l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt->hw.l4_offset = ODP_PACKET_OFFSET_INVALID;

	/* Reset the lengths of segments, when initializing packet has 0 len by
	 * design, then length of data can be modified if needed */
	pkt->last = pkt; /* when packet does not hold any data then first segment is the last one */
	pkt->total_len = 0;
	seg = pkt;
	while (seg) {
		seg->segment_len = 0;
		seg->segment_offset = 0;
		seg = (struct packet_hdr_t*)(seg->buf_hdr.next_seg);
	}
       /*
	* Packet headroom is set from the pool's headroom
	* Packet tailroom is rounded up to fill the last
	* segment.
	*/
	pkt->segment_offset = pool->pkt_alloc.headroom;
}

static void *packet_map(struct packet_hdr_t *pkt,
			uint32_t offset, odp_packet_seg_t *seg_out,
			uint32_t *seglen_out)
{
	struct packet_hdr_t *seg;

	if (offset > pkt->total_len)
		return NULL;
	seg = pkt;
	while (seg && offset >= seg->segment_len) {
		offset -= seg->segment_len;
		seg = (struct packet_hdr_t*)(seg->buf_hdr.next_seg);
	}
	if (!seg)
		return NULL;

	if (seg_out)
		*seg_out = (odp_packet_seg_t)seg;
	if (seglen_out)
		*seglen_out = seg->segment_len - offset;

	/* take segment offset into calculation */
	offset += seg->segment_offset;

	return (uint8_t*)(seg->buf_hdr.data) + offset;
}

static inline uint32_t
packet_tailroom(struct packet_hdr_t *pkt)
{
	struct packet_hdr_t *seg = pkt->last;
	return seg->buf_hdr.data_size - seg->segment_offset - seg->segment_len;
}

static inline void *
packet_map_tailroom(struct packet_hdr_t *pkt, uint32_t *tailroom)
{
	struct packet_hdr_t *seg = pkt->last;
	if (tailroom)
		*tailroom = seg->buf_hdr.data_size - seg->segment_offset - seg->segment_len;
	return (uint8_t*)seg->buf_hdr.data + seg->segment_offset + seg->segment_len;
}

static int packet_push_head(struct packet_hdr_t *pkt, size_t len)
{
	/* we cannot push more than headroom */
	if (pkt->segment_offset < len)
		return -1;

	/* pushing the head means updating the first segment only */
	pkt->segment_offset -= len;
	pkt->segment_len += len;
	pkt->total_len += len;

	return 0;
}

static int packet_extend_head(struct packet_hdr_t **pkt, size_t len)
{
	struct packet_hdr_t *old_pkt = *pkt;
	struct packet_hdr_t *new_pkt;
	struct packet_hdr_t *seg;
	size_t extend_len;

	/* try to push old packet */
	if (0 == packet_push_head(old_pkt, len))
		return 0;

	/* extend old buffer if push failed */
	extend_len = len - old_pkt->segment_offset;
	new_pkt = (struct packet_hdr_t *)buffer_alloc(
			old_pkt->buf_hdr.pool, extend_len);
	if (PACKET_HDR_INVALID == new_pkt)
		return -1;

	/* update old segment */
	old_pkt->segment_len += old_pkt->segment_offset;
	old_pkt->segment_offset = 0;

	/* update new segments starting from the second */
	seg = new_pkt;
	while (seg->buf_hdr.next_seg) {

		seg = (struct packet_hdr_t*)seg->buf_hdr.next_seg;
		seg->segment_len = seg->buf_hdr.data_size;
		seg->segment_offset = 0;
		extend_len -= seg->buf_hdr.data_size;
	}

	/* link buffer chains together */
	seg->buf_hdr.next_seg = &old_pkt->buf_hdr;

	/* update first buffer header */
	new_pkt->buf_hdr.total_size += old_pkt->buf_hdr.total_size;
	new_pkt->buf_hdr.seg_count += old_pkt->buf_hdr.seg_count;

	/* update first segment */
	new_pkt->segment_len = extend_len;
	new_pkt->segment_offset = new_pkt->buf_hdr.data_size - extend_len;
	new_pkt->total_len = old_pkt->total_len + len;
	new_pkt->last = old_pkt->last;

	/* return new packet */
	*pkt = new_pkt;
	return 1;
}

static int packet_pull_head(struct packet_hdr_t *pkt, size_t len)
{
	/* we allow only for pushing in range of first segment */
	if (pkt->segment_len <= len)
		return -1;

	pkt->segment_offset += len;
	pkt->segment_len -= len;
	pkt->total_len -= len;

	return 0;
}

static int packet_trunc_head(struct packet_hdr_t **pkt, size_t len)
{
	struct packet_hdr_t *first_seg = *pkt;
	struct packet_hdr_t *last_seg, *seg;
	size_t total_len, seg_count;
	size_t trunc_len, trunc_nsegs;

	/* try to pull old packet */
	if (0 == packet_pull_head(first_seg, len))
		return 0;

	/* reject oversized request */
	if (len > (size_t)first_seg->total_len - 1)
		return -1;

	/* save some values */
	total_len = first_seg->total_len;
	last_seg = first_seg->last;
	seg_count = first_seg->buf_hdr.seg_count;

	/* count segments to truncate */
	trunc_len = len;
	trunc_nsegs = 0;
	seg = first_seg;
	do {
		trunc_len -= seg->segment_len;
		trunc_nsegs++;

	} while ((seg = (struct packet_hdr_t *)seg->buf_hdr.next_seg)
		&& (trunc_len >= seg->segment_len));

	/* realese truncated segments */
	first_seg->buf_hdr.seg_count = trunc_nsegs;
	buffer_free(first_seg->buf_hdr.pool,&first_seg->buf_hdr);

	/* update first buffer header */
	seg->buf_hdr.seg_count = (seg_count - trunc_nsegs);
	seg->buf_hdr.total_size = (seg_count - trunc_nsegs) * seg->buf_hdr.data_size;

	/* update first segment header */
	seg->segment_len -= trunc_len;
	seg->segment_offset += trunc_len;
	seg->total_len = total_len - len;
	seg->last = last_seg;

	/* return new packet */
	*pkt = seg;
	return 1;
}

static int packet_push_tail(struct packet_hdr_t *pkt, size_t len)
{
	if (len > packet_tailroom(pkt))
		return -1;

	pkt->last->segment_len += len;
	pkt->total_len += len;

	return 0;
}

static int packet_push_last_segment(struct packet_hdr_t *pkt, size_t len)
{
	struct packet_hdr_t *seg;
	size_t free_space;
	size_t minlen;
	size_t left;

	if (!len)
		return 0;

	/* Note, durring reception ThunderX NIC can give intermediate segments
	 * not fully loaded with data, therefore we cannot assume that packet
	 * has equaly filled segments (we need to iterrate) */
	seg = pkt->last; /* start from last segment that holds data */
	free_space = seg->buf_hdr.data_size - seg->segment_len - seg->segment_offset;
	while ((seg = (struct packet_hdr_t *)(seg->buf_hdr.next_seg)))
		free_space += seg->buf_hdr.data_size;
	if (free_space < len)
		return -1;
	seg = pkt->last; /* start from last segment that holds data */
	left = len;
	do {
		free_space = seg->buf_hdr.data_size - seg->segment_len - seg->segment_offset;
		minlen = odp_min(free_space, left); /* how much we can extend current segment? */
		seg->segment_len += minlen;
		left -= minlen;
	/* do we have to extend next segment, advance if needed */
	} while (left && (seg = (struct packet_hdr_t *)(seg->buf_hdr.next_seg)));
	ODP_ASSERT(0 == left); /* check if free_space of packet was corectly calculated */

	/* all segments updated now update packet fields */
	pkt->last = seg;
	pkt->total_len += len;

	return 0;
}

static int packet_extend_tail(struct packet_hdr_t **pkt, size_t len)
{
	struct packet_hdr_t *first_seg = *pkt;
	struct packet_hdr_t *seg, *extend_seg;
	size_t tailroom, extend_len;

	/* try to push old packet */
	if (0 == packet_push_last_segment(first_seg, len))
		return 0;

	/* extend old buffer if push failed */
	tailroom = packet_tailroom(first_seg);
	extend_len = len - tailroom;
	extend_seg = (struct packet_hdr_t *)buffer_alloc(
			first_seg->buf_hdr.pool, extend_len);
	if (PACKET_HDR_INVALID == extend_seg)
		return -1;

	/* update old last segment */
	first_seg->last->segment_len += tailroom;

	/* link buffer chains together */
	first_seg->last->buf_hdr.next_seg = &extend_seg->buf_hdr;

	/* update new segments */
	seg = extend_seg;
	while (seg->buf_hdr.next_seg) {

		seg->segment_len = seg->buf_hdr.data_size;
		extend_len -= seg->buf_hdr.data_size;
		seg = (struct packet_hdr_t*)seg->buf_hdr.next_seg;
	}
	seg->segment_len = extend_len;

	/* update the first buffer header */
	first_seg->buf_hdr.seg_count += extend_seg->buf_hdr.seg_count;
	first_seg->buf_hdr.total_size += extend_seg->buf_hdr.total_size;

	/* update first segment */
	first_seg->total_len += len;
	first_seg->last = seg;

	return 0;
}

static int packet_pull_tail(struct packet_hdr_t *pkt, size_t len)
{
	if (pkt->last->segment_len <= len)
		return -1;

	pkt->last->segment_len -= len;
	pkt->total_len -= len;

	return 0;
}

static int packet_trunc_tail(struct packet_hdr_t **pkt, size_t len)
{
	struct packet_hdr_t *first_seg = *pkt;
	struct packet_hdr_t *seg;
	size_t trunc_len, trunc_nsegs;

	/* try to pull old packet */
	if (0 == packet_pull_tail(first_seg, len))
		return 0;

	/* reject oversized request */
	if (len > (size_t)first_seg->total_len - 1)
		return -1;

	/* count segments to truncate */
	trunc_len = first_seg->total_len;
	trunc_nsegs = first_seg->buf_hdr.seg_count;
	seg = first_seg;
	do {
		trunc_len -= seg->segment_len;
		trunc_nsegs--;

	} while ((trunc_len > len) &&
		(seg = (struct packet_hdr_t *)seg->buf_hdr.next_seg));

	/* realese truncated segments */
	seg->buf_hdr.next_seg->seg_count = trunc_nsegs;
	buffer_free(seg->buf_hdr.pool, seg->buf_hdr.next_seg);

	/* update last segments */
	seg->segment_len -= (len - trunc_len);
	seg->buf_hdr.next_seg = 0;

	/* update the first buffer header */
	first_seg->buf_hdr.seg_count -= trunc_nsegs;
	first_seg->buf_hdr.total_size -= trunc_nsegs * first_seg->buf_hdr.data_size;

	/* update first segment */
	first_seg->total_len -= len;
	first_seg->last = seg;

	return 0;
}


static int packet_copy(odp_packet_t srcpkt, uint32_t srcoffset,
                       odp_packet_t dstpkt, uint32_t dstoffset,
                       uint32_t len)
{
	struct packet_hdr_t *srchdr = (struct packet_hdr_t *)(srcpkt);
	struct packet_hdr_t *dsthdr = (struct packet_hdr_t *)(dstpkt);
	void *srcmap;
	void *dstmap;
	uint32_t cpylen, minseg;
	uint32_t srcseglen = 0; /* GCC */
	uint32_t dstseglen = 0; /* GCC */

	/* Offsets with len cannot point to source pkt which is not filled with
	 * data. Also it cannot exceed the destination packet size (not the
	 * actual data which are stored since we may overwrite those) */
	if (srcoffset + len > srchdr->total_len ||
	    dstoffset + len > dsthdr->buf_hdr.total_size)
		return -1;
	/* Should never happen... check just in case */
	ODP_ASSERT (dstoffset + len <= dsthdr->total_len);

	while (len > 0) {
		srcmap = packet_map(srchdr, srcoffset, NULL, &srcseglen);
		dstmap = packet_map(dsthdr, dstoffset, NULL, &dstseglen);

		minseg = dstseglen > srcseglen ? srcseglen : dstseglen;
		cpylen = len > minseg ? minseg : len;
		memcpy(dstmap, srcmap, cpylen);

		srcoffset += cpylen;
		dstoffset += cpylen;
		len       -= cpylen;
	}

	return 0;
}

static struct packet_hdr_t* packet_alloc(struct pool_entry_s *pool, size_t len)
{
	struct packet_hdr_t *pkt;

	if (pool->params.type != ODP_POOL_PACKET)
		return PACKET_HDR_INVALID;

	pkt = (struct packet_hdr_t *)buffer_alloc(pool,
			len ? len : pool->params.buf.size);
	if (PACKET_HDR_INVALID == pkt)
		return PACKET_HDR_INVALID;
	packet_init(pkt);
	packet_push_last_segment(pkt, len);

	return pkt;
}

void packet_free(struct pool_entry_s *pool, struct packet_hdr_t *pkt)
{
	buffer_free(pool,&pkt->buf_hdr);
}

/* ********************************************************
 * Alloc and free
 * ********************************************************/

odp_packet_t odp_packet_alloc(odp_pool_t pool, uint32_t len)
{
	if (((struct pool_entry_s*)pool)->params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;

	return (odp_packet_t)packet_alloc((struct pool_entry_s*)pool, len);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int num)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);
	size_t pkt_size = len ? len : pool->params.buf.size;
	int count, i;

	if (pool->params.type != ODP_POOL_PACKET) {
		__odp_errno = EINVAL;
		return -1;
	}

	count = buffer_alloc_multi(pool_hdl, pkt_size,
				   (odp_buffer_t *)pkt, num);

	for (i = 0; i < count; ++i) {
		odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt[i]);
		packet_init(pkt_hdr);
		packet_push_last_segment(pkt_hdr, len);
	}

	return count;
}

void odp_packet_free(odp_packet_t pkt)
{
	packet_free(((struct packet_hdr_t*)pkt)->buf_hdr.pool, (struct packet_hdr_t*)pkt);
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	while (num--) {
		packet_free(((struct packet_hdr_t*)pkt[num])->buf_hdr.pool, (struct packet_hdr_t*)pkt[num]);
	}
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	struct pool_entry_s *pool = ((struct packet_hdr_t*)pkt)->buf_hdr.pool;
	uint32_t totsize = pool->pkt_alloc.headroom + len +
			   pool->pkt_alloc.tailroom;

	if (totsize > ((struct packet_hdr_t*)pkt)->buf_hdr.total_size)
		return -1;

	packet_init((struct packet_hdr_t*)pkt);
	packet_push_last_segment((struct packet_hdr_t*)pkt, len);
	return 0;
}

/* ********************************************************
 * Pointers and lengths
 * ********************************************************/

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

/* redundant API, removed in 1.0 */
void *odp_packet_head(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.data;
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.total_size;
}

/* redundant API, removed in 1.0 */
void *odp_packet_data(odp_packet_t pkt)
{
	return odp_packet_seg_data(pkt, (odp_packet_seg_t)pkt);
}

/* redundant API, removed in 1.0 */
uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return odp_packet_seg_data_len(pkt, (odp_packet_seg_t)pkt);
}

uint32_t odp_packet_len(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->total_len;
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->segment_offset;
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	return packet_tailroom(hdr);
}

void *odp_packet_tail(odp_packet_t pkt)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	return packet_map_tailroom(hdr, NULL);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	if (packet_push_head(hdr, len))
		return NULL;
	return packet_map(hdr, 0, NULL, NULL);
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	struct packet_hdr_t **hdr = (struct packet_hdr_t **)pkt;
	int ret;
	if ((ret = packet_extend_head(hdr, len)) < 0)
		return -1;
	if (data_ptr)
		*data_ptr = packet_map(*hdr, 0, NULL, seg_len);
	return ret;
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	if (packet_pull_head(hdr, len))
		return NULL;
	return packet_map(hdr, 0, NULL, NULL);
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len,
			  void **data_ptr, uint32_t *seg_len)
{
	struct packet_hdr_t **hdr = (struct packet_hdr_t **)pkt;
	int ret;
	if ((ret = packet_trunc_head(hdr, len)) < 0)
		return -1;
	if (data_ptr)
		*data_ptr = packet_map(*hdr, 0, NULL, seg_len);
	return ret;
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	uint32_t origin = hdr->total_len;

	if (packet_push_tail(hdr, len))
		return NULL;
	return len ? packet_map(hdr, origin, NULL, NULL)
		: packet_map_tailroom(hdr, NULL);
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	struct packet_hdr_t **hdr = (struct packet_hdr_t **)pkt;
	uint32_t origin = (*hdr)->total_len;

	if (packet_extend_tail(hdr, len))
		return -1;
	if (data_ptr)
		*data_ptr = len ? packet_map(*hdr, origin, NULL, seg_len)
			: packet_map_tailroom(*hdr, seg_len);
	return 0;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;
	if (packet_pull_tail(hdr, len))
		return NULL;
	return packet_map_tailroom(hdr, NULL);
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len,
			  void **tail_ptr, uint32_t *tailroom)
{
	struct packet_hdr_t **hdr = (struct packet_hdr_t **)pkt;
	if (packet_trunc_tail(hdr, len))
		return -1;
	if (tail_ptr)
		*tail_ptr = packet_map_tailroom(*hdr, tailroom);
	return 0;
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	return packet_map((struct packet_hdr_t *)pkt, offset, seg, len);
}

/* This function is a no-op */
void odp_packet_prefetch(odp_packet_t pkt ODP_UNUSED,
			 uint32_t offset ODP_UNUSED,
			 uint32_t len ODP_UNUSED)
{
	/* TODO API: implement new API */
}

/* ********************************************************
 * Meta-data
 * ********************************************************/

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return (odp_pool_t)((struct packet_hdr_t *)pkt)->buf_hdr.pool;
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return (odp_pktio_t)((struct packet_hdr_t *)pkt)->input;
}

int odp_packet_input_index(odp_packet_t pkt)
{
	return odp_pktio_index(odp_packet_input(pkt));
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->user_ctx.ptr;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	((struct packet_hdr_t *)pkt)->user_ctx.const_ptr = ctx;
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.udata;
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.udata_size;
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	return packet_ptr(odp_packet_hdr(pkt), len) + odp_packet_l2_offset(pkt);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);
	return packet_l2_offset(hdr);
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (offset >= ((struct packet_hdr_t *)pkt)->total_len)
		return -1;

	((struct packet_hdr_t *)pkt)->hw.l2_offset = offset;
	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);
	return packet_ptr(hdr, len) + packet_l3_offset(hdr);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return packet_l3_offset((struct packet_hdr_t*)pkt);
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (offset >= ((struct packet_hdr_t *)pkt)->total_len)
		return -1;

	((struct packet_hdr_t *)pkt)->hw.l3_offset = offset;
	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);
	return packet_ptr(hdr, len)
		+ packet_l4_offset(hdr);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return packet_l4_offset((struct packet_hdr_t*)pkt);
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (offset >= ((struct packet_hdr_t *)pkt)->total_len)
		return -1;

	((struct packet_hdr_t *)pkt)->hw.l4_offset = offset;
	return 0;
}

uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return packet_flow_hash((struct packet_hdr_t*)pkt);
}

void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	packet_flow_hash_set((struct packet_hdr_t*)pkt, flow_hash);
}

odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	struct packet_hdr_t *pkt_hdr = (struct packet_hdr_t *)pkt;
	return pkt_hdr->timestamp;
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	struct packet_hdr_t *pkt_hdr = (struct packet_hdr_t *)pkt;
	pkt_hdr->timestamp = timestamp;
	packet_hdr_has_ts_set(pkt_hdr, 1);
}

/* ********************************************************
 * Segment level
 * ********************************************************/

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.seg_count > 1;
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	return ((struct packet_hdr_t *)pkt)->buf_hdr.seg_count;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)(((struct packet_hdr_t *)pkt)->last);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED,
				     odp_packet_seg_t seg)
{
	odp_packet_seg_t next = (odp_packet_seg_t)(((struct packet_hdr_t *)seg)->buf_hdr.next_seg);
	return (NULL == next) ? ODP_PACKET_SEG_INVALID : next;
}

void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg)
{
	size_t headroom = 0;

	/* if the segment is first segment, than add headroom */
	if ((void *)pkt == (void *)seg)
		headroom = ((struct packet_hdr_t *)pkt)->segment_offset;

	return (uint8_t*)(((struct packet_hdr_t *)seg)->buf_hdr.data) + headroom;
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED,
				 odp_packet_seg_t seg)
{
	return ((struct packet_hdr_t *)seg)->segment_len;
}

/* ********************************************************
 * Manipulation
 * ********************************************************/

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	odp_packet_t newpkt;
	odp_packet_hdr_t *newpkt_hdr;
	uint32_t pktlen = pkt_hdr->total_len;

	if (offset > pkt_hdr->total_len)
		return -1;

	newpkt = odp_packet_alloc((odp_pool_t)pkt_hdr->buf_hdr.pool, pktlen + len);
	if (ODP_PACKET_INVALID == newpkt)
		return -1;
	newpkt_hdr = odp_packet_hdr(newpkt);

	if (packet_copy(pkt, 0, newpkt, 0, offset) ||
	    packet_copy(pkt, offset, newpkt, offset + len, pktlen - offset)) {
		odp_packet_free(newpkt);
		return -1;
	}

	newpkt_hdr->input = pkt_hdr->input;
	newpkt_hdr->user_ctx = pkt_hdr->user_ctx;
	if (newpkt_hdr->buf_hdr.udata != NULL &&
	    pkt_hdr->buf_hdr.udata != NULL) {
		size_t size = odp_min(
			(size_t)newpkt_hdr->buf_hdr.udata_size,
			(size_t)pkt_hdr->buf_hdr.udata_size);
		memcpy(newpkt_hdr->buf_hdr.udata,
		       pkt_hdr->buf_hdr.udata,
		       size);
	}

	copy_packet_parser_metadata(pkt_hdr, newpkt_hdr);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 0;
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr, uint32_t offset,
				 uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	odp_packet_t newpkt;
	odp_packet_hdr_t *newpkt_hdr;
	uint32_t pktlen = pkt_hdr->total_len;


	if (offset > pktlen || offset + len > pktlen)
		return -1;

	newpkt = odp_packet_alloc((odp_pool_t)((struct packet_hdr_t *)pkt)->buf_hdr.pool, pktlen - len);
	if (ODP_PACKET_INVALID == newpkt)
		return -1;
	newpkt_hdr = odp_packet_hdr(newpkt);

	if (packet_copy(pkt, 0, newpkt, 0, offset) ||
	    packet_copy(pkt, offset + len, newpkt, offset, pktlen - offset - len)) {
		odp_packet_free(newpkt);
		return -1;
	}

	newpkt_hdr->input = pkt_hdr->input;
	newpkt_hdr->user_ctx = pkt_hdr->user_ctx;
	if (newpkt_hdr->buf_hdr.udata != NULL &&
	    pkt_hdr->buf_hdr.udata != NULL) {
		size_t size = odp_min(
			(size_t)newpkt_hdr->buf_hdr.udata_size,
			(size_t)pkt_hdr->buf_hdr.udata_size);
		memcpy(newpkt_hdr->buf_hdr.udata,
		       pkt_hdr->buf_hdr.udata,
		       size);
	}
	copy_packet_parser_metadata(pkt_hdr, newpkt_hdr);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 0;
}

int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align)
{
	int rc;
	uint32_t shift;
	uint32_t seglen = 0;  /* GCC */
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	void *addr = packet_map(pkt_hdr, offset, NULL, &seglen);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > pkt_hdr->segment_len)
			return -1;
		shift  = len - seglen;
		uaddr -= shift;
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
		if (misalign)
			shift += align - misalign;
	}

	rc = odp_packet_extend_head(pkt, shift, NULL, NULL);
	if (rc < 0)
		return rc;

	(void)odp_packet_move_data(*pkt, 0, shift,
				   odp_packet_len(*pkt) - shift);

	(void)odp_packet_trunc_tail(pkt, shift, NULL, NULL);
	return 1;
}

int odp_packet_concat(odp_packet_t *dst, odp_packet_t src)
{
	uint32_t dst_len = odp_packet_len(*dst);
	uint32_t src_len = odp_packet_len(src);

	if (odp_packet_extend_tail(dst, src_len, NULL, NULL) >= 0) {
		(void)odp_packet_copy_from_pkt(*dst, dst_len,
					       src, 0, src_len);
		if (src != *dst)
			odp_packet_free(src);
		return 0;
	}

	return -1;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = odp_packet_len(*pkt);

	if (len >= pktlen || tail == NULL)
		return -1;

	*tail = odp_packet_copy_part(*pkt, len, pktlen - len,
				     odp_packet_pool(*pkt));

	if (*tail == ODP_PACKET_INVALID)
		return -1;

	return odp_packet_trunc_tail(pkt, pktlen - len, NULL, NULL);
}

/* ********************************************************
 * Copy
 * ********************************************************/

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	odp_packet_hdr_t *srchdr = odp_packet_hdr(pkt);
	uint32_t pktlen = srchdr->total_len;
	uint32_t meta_offset = ODP_FIELD_SIZEOF(odp_packet_hdr_t, buf_hdr);
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);

	if (newpkt != ODP_PACKET_INVALID) {
		odp_packet_hdr_t *newhdr = odp_packet_hdr(newpkt);
		uint8_t *newstart, *srcstart;

		/* Must copy metadata first, followed by packet data */
		newstart = (uint8_t *)newhdr + meta_offset;
		srcstart = (uint8_t *)srchdr + meta_offset;

		memcpy(newstart, srcstart,
		       sizeof(odp_packet_hdr_t) - meta_offset);

		if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0,
					     pktlen) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		}
	}

	/* update last segment */
	struct packet_hdr_t *last_seg = (struct packet_hdr_t *)newpkt;
	while (last_seg->buf_hdr.next_seg)
		last_seg = (struct packet_hdr_t *)last_seg->buf_hdr.next_seg;
	((struct packet_hdr_t *)newpkt)->last = last_seg;

	return newpkt;
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset >= pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pool, len);
	if (newpkt != ODP_PACKET_INVALID)
		odp_packet_copy_from_pkt(newpkt, 0, pkt, offset, len);

	return newpkt;
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	uint8_t *dstaddr = (uint8_t *)dst;

	if (offset + len > ((struct packet_hdr_t *)pkt)->total_len)
		return -1;

	while (len > 0) {
		mapaddr = packet_map((struct packet_hdr_t*)pkt, offset, NULL, &seglen);
		cpylen = len > seglen ? seglen : len;
		memcpy(dstaddr, mapaddr, cpylen);
		offset  += cpylen;
		dstaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			     uint32_t len, const void *src)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	const uint8_t *srcaddr = (const uint8_t *)src;

	if (offset + len > ((struct packet_hdr_t *)pkt)->total_len)
		return -1;

	while (len > 0) {
		mapaddr = packet_map((struct packet_hdr_t*)pkt, offset, NULL, &seglen);
		cpylen = len > seglen ? seglen : len;
		memcpy(mapaddr, srcaddr, cpylen);
		offset  += cpylen;
		srcaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len)
{
	odp_packet_hdr_t *dst_hdr = odp_packet_hdr(dst);
	odp_packet_hdr_t *src_hdr = odp_packet_hdr(src);
	void *dst_map;
	void *src_map;
	uint32_t cpylen, minseg;
	uint32_t dst_seglen = 0; /* GCC */
	uint32_t src_seglen = 0; /* GCC */
	int overlap;

	if (dst_offset + len > dst_hdr->total_len ||
	    src_offset + len > src_hdr->total_len)
		return -1;

	overlap = (dst_hdr == src_hdr &&
		   ((dst_offset <= src_offset &&
		     dst_offset + len >= src_offset) ||
		    (src_offset <= dst_offset &&
		     src_offset + len >= dst_offset)));

	if (overlap && src_offset < dst_offset) {
		odp_packet_t temp =
			odp_packet_copy_part(src, src_offset, len,
					     odp_packet_pool(src));
		if (temp == ODP_PACKET_INVALID)
			return -1;
		odp_packet_copy_from_pkt(dst, dst_offset, temp, 0, len);
		odp_packet_free(temp);
		return 0;
	}

	while (len > 0) {
		dst_map = packet_map(dst_hdr, dst_offset, NULL, &dst_seglen);
		src_map = packet_map(src_hdr, src_offset, NULL, &src_seglen);

		minseg = dst_seglen > src_seglen ? src_seglen : dst_seglen;
		cpylen = len > minseg ? minseg : len;

		if (overlap)
			memmove(dst_map, src_map, cpylen);
		else
			memcpy(dst_map, src_map, cpylen);

		dst_offset += cpylen;
		src_offset += cpylen;
		len        -= cpylen;
	}

	return 0;
}

int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

/* ********************************************************
 * Debugging
 * ********************************************************/

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len-1;
	struct packet_hdr_t *hdr = (struct packet_hdr_t *)pkt;

	len += snprintf(&str[len], n-len, "Packet ");
	len += buffer_snprint(&str[len], n-len, (odp_buffer_t) pkt);
	len += snprintf(&str[len], n-len,
			"  input_flags  0x%x\n", hdr->hw.input_flags.all);
	len += snprintf(&str[len], n-len,
			"  error_flags  0x%x\n", hdr->hw.error_flags.all);
	len += snprintf(&str[len], n-len,
			"  offsets.l2_offset    %u\n", packet_l2_offset(hdr));
	len += snprintf(&str[len], n-len,
			"  offsets.l3_offset    %u\n", packet_l3_offset(hdr));
	len += snprintf(&str[len], n-len,
			"  offsets.l4_offset    %u\n", packet_l4_offset(hdr));
	len += snprintf(&str[len], n-len,
			"  total_len    %u\n", hdr->total_len);
	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	return (pkt && ((struct packet_hdr_t *)pkt)->buf_hdr.type == ODP_EVENT_PACKET);
}
