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
 *
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***********************license end**************************************/

#include <assert.h>
#include <odp/api/shared_memory.h>
#include <odp_internal.h>
#include <odp_align_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/align.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <odp_debug_internal.h>
#include <odp/api/rwlock.h>
#include <thunder/odph_ring.h>

static TAILQ_HEAD(, odph_ring) odp_ring_list;

#if 1
/*
 * the enqueue of pointers on the ring.
 */
#define ENQUEUE_PTRS() do { \
	const uint32_t size = r->prod.size; \
	uint32_t idx = prod_head & mask; \
	if (odp_likely(idx + n < size)) { \
		for (i = 0; i < (n & ((~(unsigned)0x3))); i += 4, idx += 4) { \
			r->ring[idx] = obj_table[i]; \
			r->ring[idx+1] = obj_table[i+1]; \
			r->ring[idx+2] = obj_table[i+2]; \
			r->ring[idx+3] = obj_table[i+3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		r->ring[idx++] = obj_table[i++]; \
		case 2: \
		r->ring[idx++] = obj_table[i++]; \
		case 1: \
		r->ring[idx++] = obj_table[i++]; \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++)\
			r->ring[idx] = obj_table[i]; \
		for (idx = 0; i < n; i++, idx++) \
			r->ring[idx] = obj_table[i]; \
	} \
} while (0)

/*
 * the actual copy of pointers on the ring to obj_table.
 */
#define DEQUEUE_PTRS() do { \
	uint32_t idx = cons_head & mask; \
	const uint32_t size = r->cons.size; \
	if (odp_likely(idx + n < size)) { \
		for (i = 0; i < (n & (~(unsigned)0x3)); i += 4, idx += 4) {\
			obj_table[i] = r->ring[idx]; \
			obj_table[i+1] = r->ring[idx+1]; \
			obj_table[i+2] = r->ring[idx+2]; \
			obj_table[i+3] = r->ring[idx+3]; \
		} \
		switch (n & 0x3) { \
		case 3: \
		obj_table[i++] = r->ring[idx++]; \
		case 2: \
		obj_table[i++] = r->ring[idx++]; \
		case 1: \
		obj_table[i++] = r->ring[idx++]; \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++) \
			obj_table[i] = r->ring[idx]; \
		for (idx = 0; i < n; i++, idx++) \
			obj_table[i] = r->ring[idx]; \
	} \
} while (0)
#else
#define ENQUEUE_PTRS() do { \
	(void)i; \
	const uint32_t size = r->prod.size; \
	uint32_t idx = prod_head & mask; \
	if (odp_likely(idx + n < size)) { \
		memcpy(&r->ring[idx], obj_table, sizeof(void*) * n); \
	} else { \
		size_t cpy = size - idx; \
		memcpy(&r->ring[idx], obj_table, sizeof(void*) * cpy); \
		memcpy(r->ring, &obj_table[cpy], sizeof(void*) * (n - cpy)); \
	} \
} while (0)

/*
 * the actual copy of pointers on the ring to obj_table.
 */
#define DEQUEUE_PTRS() do { \
	(void)i; \
	uint32_t idx = cons_head & mask; \
	const uint32_t size = r->cons.size; \
	if (odp_likely(idx + n < size)) { \
		memcpy(obj_table, &r->ring[idx], sizeof(void*) * n); \
	} else { \
		size_t cpy = size - idx; \
		memcpy(obj_table, &r->ring[idx], sizeof(void*) * cpy); \
		memcpy(&obj_table[cpy], r->ring, sizeof(void*) * (n - cpy)); \
	} \
} while (0)
#endif

static odp_rwlock_t	qlock;	/* rings tailq lock */

/* init tailq_ring */
int odph_ring_tailq_init(void)
{
	TAILQ_INIT(&odp_ring_list);
	odp_rwlock_init(&qlock);
	return 0;
}

/* create the ring */
odph_ring_t* odph_ring_create(const char *name, unsigned count, unsigned flags)
{
	char ring_name[ODPH_RING_NAMESIZE];
	odph_ring_t *r = NULL;
	size_t ring_size;
	odp_shm_t shm;

	/* count must be a power of 2 */
	if (!ODP_VAL_IS_POWER_2(count) || (count > ODPH_RING_SZ_MASK)) {
		ODP_ERR("Requested size is invalid, must be power of 2, and  do not exceed the size limit %u\n",
			ODPH_RING_SZ_MASK);
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "%s", name);
	ring_size = count*sizeof(void *)+sizeof(odph_ring_t);

	odp_rwlock_write_lock(&qlock);
	/* reserve a memory zone for this ring.*/
	shm = odp_shm_reserve(ring_name, ring_size, ODP_CACHE_LINE_SIZE, 0);

	if (shm != ODP_SHM_INVALID) {
		/* init the ring structure */
		r = odp_shm_addr(shm);

		snprintf(r->name, sizeof(r->name), "%s", name);
		r->flags = flags;
		r->shm = shm;
		r->prod.watermark = count;
		r->prod.sp_enqueue = !!(flags & ODPH_RING_F_SP_ENQ);
		r->cons.sc_dequeue = !!(flags & ODPH_RING_F_SC_DEQ);
		r->prod.size = count;
		r->cons.size = count;
		r->prod.mask = count-1;
		r->cons.mask = count-1;
		r->prod.head = 0;
		r->cons.head = 0;
		r->prod.tail = 0;
		r->cons.tail = 0;

		TAILQ_INSERT_TAIL(&odp_ring_list, r, next);
	} else {
		ODP_ERR("Cannot reserve memory\n");
	}

	odp_rwlock_write_unlock(&qlock);
	return r;
}

/* Destroys the ring
 * @note It is not safe to destroy ring which are in use by other threads
 */
int odph_ring_destroy(odph_ring_t* r)
{
	odp_shm_t shm = r->shm;

	if (ODP_SHM_INVALID == shm)
		return -1;

	odp_rwlock_write_lock(&qlock);

	/* detach ring from list */
	TAILQ_REMOVE(&odp_ring_list, r, next);

	/* overwrite ring object memory and free it */
	memset(r, 0, sizeof(r->prod.size * sizeof(void*)) +
		     sizeof(odph_ring_t));
	if (odp_shm_free(shm)) {
		ODP_ERR("Critical error while freeing shm for ring\n");
		goto err;
	}

	odp_rwlock_write_unlock(&qlock);
	return 0;

err:
	odp_rwlock_write_unlock(&qlock);
	return -1;
}

/*
 * change the high water mark. If *count* is 0, water marking is
 * disabled
 */
int odph_ring_set_water_mark(odph_ring_t *r, unsigned count)
{
	if (count >= r->prod.size)
		return -EINVAL;

	/* if count is 0, disable the watermarking */
	if (count == 0)
		count = r->prod.size;

	r->prod.watermark = count;
	return 0;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int __odph_ring_mp_do_enqueue(odph_ring_t *r, void * const *obj_table,
			 unsigned n, enum odph_ring_queue_behavior behavior)
{
	size_t i;
	uint32_t prod_head, prod_next;
	uint32_t cons_tail, free_entries;
	uint32_t mask = r->prod.mask;
	uint32_t tmp;
	const unsigned max = n;
	int success;
	int ret;

	if (odp_unlikely(0 == n))
		return 0;

	/* move prod.head atomically */
	do {
		/* Reset n to the initial burst count */
		n = max;

		prod_head = __atomic_load_n(&r->prod.head, __ATOMIC_ACQUIRE);
		cons_tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * prod_head > cons_tail). So 'free_entries' is always between 0
		 * and size(ring)-1. */
		free_entries = (mask + cons_tail - prod_head);

		/* check that we have enough room in ring */
		if (odp_unlikely(n > free_entries)) {
			if (behavior == ODPH_RING_QUEUE_FIXED) {
				return -ENOBUFS;
			} else {
				/* No free entry available */
				if (odp_unlikely(free_entries == 0))
					return 0;

				n = free_entries;
			}
		}

		prod_next = prod_head + n;
		tmp = prod_head;
		success = __atomic_compare_exchange_n(&r->prod.head,
				&tmp,
				prod_next,
				false/*strong*/,
				__ATOMIC_ACQ_REL,
				__ATOMIC_RELAXED);
	} while (odp_unlikely(success == 0));

	/* write entries in ring */
	ENQUEUE_PTRS();

	/*
	 * If there are other enqueues in progress that preceeded us,
	 * we need to wait for them to complete
	 */
	while (__atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE) != prod_head)
		odp_cpu_pause();
	__atomic_store_n(&r->prod.tail, prod_next, __ATOMIC_RELEASE);

	/* if we exceed the watermark */
	if (odp_unlikely(((mask + 1) - free_entries + n) > r->prod.watermark)) {
		ret = (behavior == ODPH_RING_QUEUE_FIXED) ? -EDQUOT :
				(int)(n | ODPH_RING_QUOT_EXCEED);
	} else {
		ret = (behavior == ODPH_RING_QUEUE_FIXED) ? 0 : n;
	}

	return ret;
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
int __odph_ring_sp_do_enqueue(odph_ring_t *r, void * const *obj_table,
			     unsigned n, enum odph_ring_queue_behavior behavior)
{
	size_t i;
	uint32_t prod_head, cons_tail;
	uint32_t prod_next, free_entries;
	uint32_t mask = r->prod.mask;
	int ret;

	prod_head = __atomic_load_n(&r->prod.head, __ATOMIC_ACQUIRE);
	cons_tail = __atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE);
	/* The subtraction is done between two unsigned 32bits value
	 * (the result is always modulo 32 bits even if we have
	 * prod_head > cons_tail). So 'free_entries' is always between 0
	 * and size(ring)-1. */
	free_entries = mask + cons_tail - prod_head;

	/* check that we have enough room in ring */
	if (odp_unlikely(n > free_entries)) {
		if (behavior == ODPH_RING_QUEUE_FIXED) {
			return -ENOBUFS;
		} else {
			/* No free entry available */
			if (odp_unlikely(free_entries == 0))
				return 0;

			n = free_entries;
		}
	}

	prod_next = prod_head + n;
	__atomic_store_n(&r->prod.head, prod_next, __ATOMIC_SEQ_CST);

	/* write entries in ring */
	ENQUEUE_PTRS();

	/* Release our entries and the memory they refer to */
	__atomic_store_n(&r->prod.tail, prod_next, __ATOMIC_RELEASE);

	/* if we exceed the watermark */
	if (odp_unlikely(((mask + 1) - free_entries + n) > r->prod.watermark)) {
		ret = (behavior == ODPH_RING_QUEUE_FIXED) ? -EDQUOT :
			(int)(n | ODPH_RING_QUOT_EXCEED);
	} else {
		ret = (behavior == ODPH_RING_QUEUE_FIXED) ? 0 : n;
	}

	return ret;
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */

int __odph_ring_mc_do_dequeue(
	odph_ring_t *r, void **obj_table,
	unsigned n, enum odph_ring_queue_behavior behavior,
	uint32_t *head_ret)
{
	size_t i;
	uint32_t cons_head, prod_tail;
	uint32_t cons_next, entries;
	uint32_t mask = r->prod.mask;
	uint32_t tmp;
	const unsigned max = n;
	int success;

	if (odp_unlikely(0 == n))
		return 0;

	/* move cons.head atomically */
	do {
		/* Restore n as it may change every loop */
		n = max;

		cons_head = __atomic_load_n(&r->cons.head, __ATOMIC_ACQUIRE);
		prod_tail = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1. */
		entries = (prod_tail - cons_head);

		/* Set the actual entries for dequeue */
		if (n > entries) {
			if (behavior == ODPH_RING_QUEUE_FIXED) {
				return -ENOENT;
			} else {
				if (odp_unlikely(entries == 0)) {
					return 0;
				}

				n = entries;
			}
		}

		cons_next = cons_head + n;
		tmp = cons_head;
		success = __atomic_compare_exchange_n(&r->cons.head,
				&tmp,
				cons_next,
				false/*strong*/,
				__ATOMIC_ACQ_REL,
				__ATOMIC_RELAXED);
	} while (odp_unlikely(success == 0));

	/* copy in table */
	DEQUEUE_PTRS();

	/*
	 * If there are other dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	while (__atomic_load_n(&r->cons.tail, __ATOMIC_ACQUIRE) != cons_head)
		odp_cpu_pause();
	__atomic_store_n(&r->cons.tail, cons_next, __ATOMIC_RELEASE);
	if (head_ret)
		*head_ret = cons_head;

	return behavior == ODPH_RING_QUEUE_FIXED ? 0 : n;
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
int __odph_ring_sc_do_dequeue(odph_ring_t *r, void **obj_table,
			     unsigned n, enum odph_ring_queue_behavior behavior)
{
	uint32_t cons_head, prod_tail;
	uint32_t cons_next, entries;
	unsigned i;
	uint32_t mask = r->prod.mask;

	cons_head = __atomic_load_n(&r->cons.head, __ATOMIC_ACQUIRE);
	prod_tail = __atomic_load_n(&r->prod.tail, __ATOMIC_ACQUIRE);
	/* The subtraction is done between two unsigned 32bits value
	 * (the result is always modulo 32 bits even if we have
	 * cons_head > prod_tail). So 'entries' is always between 0
	 * and size(ring)-1. */
	entries = prod_tail - cons_head;

	if (n > entries) {
		if (behavior == ODPH_RING_QUEUE_FIXED) {
			return -ENOENT;
		} else {
			if (odp_unlikely(entries == 0))
				return 0;

			n = entries;
		}
	}

	cons_next = cons_head + n;
	__atomic_store_n(&r->cons.head, cons_next, __ATOMIC_SEQ_CST);

	/* copy in table */
	DEQUEUE_PTRS();

	__atomic_store_n(&r->cons.tail, cons_next, __ATOMIC_RELEASE);
	return behavior == ODPH_RING_QUEUE_FIXED ? 0 : n;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int odph_ring_mp_enqueue_bulk(odph_ring_t *r, void * const *obj_table,
				unsigned n)
{
	return __odph_ring_mp_do_enqueue(r, obj_table, n,
					 ODPH_RING_QUEUE_FIXED);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
int odph_ring_sp_enqueue_bulk(odph_ring_t *r, void * const *obj_table,
			     unsigned n)
{
	return __odph_ring_sp_do_enqueue(r, obj_table, n,
					 ODPH_RING_QUEUE_FIXED);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int odph_ring_mc_dequeue_bulk(odph_ring_t *r, void **obj_table, unsigned n)
{
	return __odph_ring_mc_do_dequeue(r, obj_table, n,
					 ODPH_RING_QUEUE_FIXED, NULL);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
int odph_ring_sc_dequeue_bulk(odph_ring_t *r, void **obj_table, unsigned n)
{
	return __odph_ring_sc_do_dequeue(r, obj_table, n,
					 ODPH_RING_QUEUE_FIXED);
}

/**
 * Test if a ring is full.
 */
int odph_ring_full(const odph_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (((cons_tail - prod_tail - 1) & r->prod.mask) == 0);
}

/**
 * Test if a ring is empty.
 */
int odph_ring_empty(const odph_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return !!(cons_tail == prod_tail);
}

/**
 * Return the number of entries in a ring.
 */
unsigned odph_ring_count(const odph_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (prod_tail - cons_tail) & r->prod.mask;
}

/**
 * Return the number of free entries in a ring.
 */
unsigned odph_ring_free_count(const odph_ring_t *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	return (cons_tail - prod_tail - 1) & r->prod.mask;
}

/* dump the status of the ring on the console */
void odph_ring_dump(const odph_ring_t *r)
{
	ODP_DBG("ring <%s>@%p\n", r->name, r);
	ODP_DBG("  flags=%x\n", r->flags);
	ODP_DBG("  size=%"PRIu32"\n", r->prod.size);
	ODP_DBG("  ct=%"PRIu32"\n", r->cons.tail);
	ODP_DBG("  ch=%"PRIu32"\n", r->cons.head);
	ODP_DBG("  pt=%"PRIu32"\n", r->prod.tail);
	ODP_DBG("  ph=%"PRIu32"\n", r->prod.head);
	ODP_DBG("  used=%u\n", odph_ring_count(r));
	ODP_DBG("  avail=%u\n", odph_ring_free_count(r));
	if (r->prod.watermark == r->prod.size)
		ODP_DBG("  watermark=0\n");
	else
		ODP_DBG("  watermark=%"PRIu32"\n", r->prod.watermark);
}

/* dump the status of all rings on the console */
void odph_ring_list_dump(void)
{
	const odph_ring_t *mp = NULL;

	odp_rwlock_read_lock(&qlock);

	TAILQ_FOREACH(mp, &odp_ring_list, next) {
		odph_ring_dump(mp);
	}

	odp_rwlock_read_unlock(&qlock);
}

/* search a ring from its name */
odph_ring_t *odph_ring_lookup(const char *name)
{
	odph_ring_t *r;

	odp_rwlock_read_lock(&qlock);
	TAILQ_FOREACH(r, &odp_ring_list, next) {
		if (strncmp(name, r->name, ODPH_RING_NAMESIZE) == 0)
			break;
	}
	odp_rwlock_read_unlock(&qlock);

	return r;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
int odph_ring_mp_enqueue_burst(odph_ring_t *r, void * const *obj_table,
			      unsigned n)
{
	return __odph_ring_mp_do_enqueue(r, obj_table, n,
					 ODPH_RING_QUEUE_VARIABLE);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
int odph_ring_sp_enqueue_burst(odph_ring_t *r, void * const *obj_table,
			      unsigned n)
{
	return __odph_ring_sp_do_enqueue(r, obj_table, n,
					ODPH_RING_QUEUE_VARIABLE);
}

/**
 * Enqueue several objects on a ring.
 */
int odph_ring_enqueue_burst(odph_ring_t *r, void * const *obj_table,
			   unsigned n)
{
	if (r->prod.sp_enqueue)
		return odph_ring_sp_enqueue_burst(r, obj_table, n);
	else
		return odph_ring_mp_enqueue_burst(r, obj_table, n);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
int odph_ring_mc_dequeue_burst(odph_ring_t *r, void **obj_table, unsigned n)
{
	return __odph_ring_mc_do_dequeue(r, obj_table, n,
					ODPH_RING_QUEUE_VARIABLE, NULL);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
int odph_ring_sc_dequeue_burst(odph_ring_t *r, void **obj_table, unsigned n)
{
	return __odph_ring_sc_do_dequeue(r, obj_table, n,
					 ODPH_RING_QUEUE_VARIABLE);
}

/**
 * Dequeue multiple objects from a ring up to a maximum number.
 */
int odph_ring_dequeue_burst(odph_ring_t *r, void **obj_table, unsigned n)
{
	if (r->cons.sc_dequeue)
		return odph_ring_sc_dequeue_burst(r, obj_table, n);
	else
		return odph_ring_mc_dequeue_burst(r, obj_table, n);
}
