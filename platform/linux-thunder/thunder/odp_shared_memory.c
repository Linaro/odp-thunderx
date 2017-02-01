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

#include <odp/api/shared_memory.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/align.h>
#include <odp/api/system_info.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_shm_internal.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <asm/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#ifdef ODP_SHM_DEBUG_EXTRA
#define ODP_DBG2 ODP_DBG
#else
#define ODP_DBG2(fmt, ...)
#endif

#define ODP_SHM_NUM_BLOCKS 512

/* TODO OTHER: Discover hugetlbfs dir automatically */
#define FILE_NAME "odp_hugepage"

#define	PAGEMAP_FNAME		"/proc/self/pagemap"

/** Mask value of type <tp> for the first <ln> bit set. */
#define	LEN2MASK(ln, tp)	\
	((tp)((uint64_t)-1 >> (sizeof(uint64_t) * CHAR_BIT - (ln))))

/*
 * the pfn (page frame number) are bits 0-54 (see pagemap.txt in linux
 * Documentation).
 */
#define	PAGEMAP_PFN_BITS	54
#define	PAGEMAP_PFN_MASK	LEN2MASK(PAGEMAP_PFN_BITS, uint64_t)

struct odp_shm_map {
	int		fd;
	uint32_t	flags;
	int		huge;
	uint32_t	page_num;
	void		*addr_orig;
	uint64_t	page_sz;
	uint64_t	map_size;
	uint64_t	free_size;
	uint64_t	free_offset;
	uint64_t	*phys_map;
	unsigned	refcnt;
};

typedef struct odp_shm_map odp_shm_map_t;

struct odp_shm_block {
	void		*addr;
	uint64_t	phys;
	uint64_t	alloc_size;
	uint64_t	size;
	uint64_t	align;
	odp_shm_map_t	*map;
	char		name[ODP_SHM_NAME_LEN];
};

typedef struct odp_shm_block odp_shm_block_t;

typedef struct {
	odp_shm_block_t	block[ODP_SHM_NUM_BLOCKS];
	odp_shm_map_t	map[ODP_SHM_NUM_BLOCKS];
	odp_spinlock_t	lock;

} odp_shm_table_t;


struct hp {
	union {
		uintptr_t va;
		void *ptr;
	};
	union {
		uintptr_t va;
		void *ptr;
	} new;
	uintptr_t pa;
	int fd;
};

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif


/* Global shared memory table */
static odp_shm_table_t *odp_shm_tbl;


static odp_shm_block_t *alloc_free_block(
				size_t size, size_t align, uint32_t flags)
{
/*
 * A map layout
 * |--------map_size--------------------------|
 *
 * |---free_offset--|---free_size-------------|
 *
 * |---aligned_free_off-|--aligned_free_size--|
 *
 * |---aligned_free_off-|-size-----|----------|
 *
 * |---free_offset--|-aligned_size-|----------|
 *
 * |---------new free_offset-------|----------|
 */

	unsigned i;
	odp_shm_map_t *best = NULL;
	odp_shm_block_t *block = NULL;
	size_t best_off = UINT_MAX;
	size_t best_size = (size_t)-1;
	//size_t aligned_size = ODP_ALIGN_ROUNDUP(size, align);

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		size_t aligned_free_off;
		size_t aligned_free_size;
		odp_shm_map_t *map = &odp_shm_tbl->map[i];

		/* Skip empty maps */
		if (map->addr_orig == NULL || map->free_size == 0)
			continue;

		ODP_ASSERT(map->free_size < map->map_size);
		ODP_ASSERT(map->free_offset > 0);

		aligned_free_off = ODP_ALIGN_ROUNDUP(map->free_offset, align);
		aligned_free_size = map->map_size - aligned_free_off;

		if (map->flags == flags && size <= aligned_free_size &&
					best_size > aligned_free_size) {
			best = map;
			best_size = aligned_free_size;
			best_off = aligned_free_off;
		}
	}


	/* Allocate a new block */
	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		if (odp_shm_tbl->block[i].addr == NULL) {
			/* Found free block */
			break;
		}
	}

	if (i > ODP_SHM_NUM_BLOCKS - 1) {
		/* Table full */
		ODP_DBG("odp_shm_reserve: no more blocks\n");
	} else {
		block = &odp_shm_tbl->block[i];
	}

	/* Find a free map if there is no match but there are free blocks */
	if (best == NULL && block != NULL) {
		for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++)
			if (odp_shm_tbl->map[i].addr_orig == NULL)
				break;
		if (i > ODP_SHM_NUM_BLOCKS - 1) {
			/* Table full */
			ODP_DBG("odp_shm_reserve: no more maps\n");
			/* No map for block.
			 * Return NULL as for mo mem
			 */
			block = NULL;
		} else {
			block->map = &odp_shm_tbl->map[i];
		}
	}

	/* Fill up a block for the existing map */
	if (best != NULL && block != NULL) {
		size_t aligned_size = best_off + size - best->free_offset;

		ODP_ASSERT(aligned_size <= best->free_size); /* Alloc too big ? */

		best->free_size -= aligned_size;
		best->free_offset += aligned_size;
		block->alloc_size = aligned_size;
		block->size = size;
		block->align = align;
		block->addr =
			(int8_t *)best->addr_orig + best_off;
		block->map = best;
		block->phys = block->map->phys_map[0] + best_off;
		ODP_DBG("Reusing map orig_va=%p va=%p map_size=%llu alloc_size=%llu free_size=%llu\n",
			best->addr_orig, block->addr, best->map_size, block->alloc_size, best->free_size);

		ODP_ASSERT((int8_t *)block->addr + block->size <=
			   (int8_t *)best->addr_orig + best->map_size);
	}

	return block;
}

int odp_shm_init_global(void)
{
	void *addr;

#ifndef MAP_HUGETLB
	ODP_DBG("NOTE: mmap does not support huge pages\n");
#endif

	addr = mmap(NULL, sizeof(odp_shm_table_t),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED)
		return -1;

	odp_shm_tbl = addr;

	memset(odp_shm_tbl, 0, sizeof(odp_shm_table_t));
	odp_spinlock_init(&odp_shm_tbl->lock);

	return 0;
}

int odp_shm_term_global(void)
{
	return 0;
}

int odp_shm_init_local(void)
{
	return 0;
}


static int find_block(const char *name, uint32_t *index)
{
	uint32_t i;

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		odp_shm_block_t *block = &odp_shm_tbl->block[i];
		if (block->addr &&
			strcmp(name, odp_shm_tbl->block[i].name) == 0) {
			/* found it */
			if (index != NULL)
				*index = i;

			return 1;
		}
	}

	return 0;
}

odp_shm_t odp_shm_lookup_addr(void *addr)
{
	uint32_t i;

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++)
		if (odp_shm_tbl->block[i].addr == addr) {
			/* found it */
			return (odp_shm_t)&odp_shm_tbl->block[i];
		}

	return ODP_SHM_INVALID;
}

int odp_shm_free_addr(void *mem)
{
	return odp_shm_free(odp_shm_lookup_addr(mem));
}

int odp_shm_free(odp_shm_t shm)
{
	odp_shm_block_t *block = (odp_shm_block_t *)shm;

	if (block == (odp_shm_block_t *)ODP_SHM_INVALID)
		return 0;

	ODP_ASSERT(block != NULL);

	if (NULL == block->addr) {
		ODP_DBG("odp_shm_free: Free block\n");
		return 0;
	}
	odp_spinlock_lock(&odp_shm_tbl->lock);

	ODP_ASSERT(block->map->refcnt > 0);

	block->addr = NULL;
	block->name[0] = 0;
	if (--block->map->refcnt == 0) {
		int rc;
		/* Free an unused map */
		rc = munmap(block->map->addr_orig, block->map->map_size);
		if (rc)
			ODP_ERR("munmap: %s\n", strerror(errno));
		memset(block->map, 0, sizeof(*block->map));
	}
	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return 0;
}

static int phys_map(void *va, uint64_t pa[], uint32_t pg_num, uint32_t pg_sz)
{
	int32_t fd, rc;
	uint32_t i, nb;
	off_t vpfn, ofs;

	vpfn = (uintptr_t)va / pg_sz;
	ofs =  sizeof(uint64_t) * vpfn;
	nb = pg_num * sizeof(uint64_t);

	if ((fd = open(PAGEMAP_FNAME, O_RDONLY)) < 0)
		return (ENOENT);

	if ((rc = pread(fd, pa, nb, ofs)) < 0 || (rc -= nb) != 0) {

		printf("failed read of %u bytes from \'%s\' "
			"at offset %zu, error code: %d\n",
			nb, PAGEMAP_FNAME, (size_t)ofs, errno);
		rc = ENOENT;
	}

	close(fd);

	for (i = 0; i != pg_num; i++) {
		pa[i] = (pa[i] & PAGEMAP_PFN_MASK) * pg_sz;
	}
	return (rc);
}

static int phys_map_range(void *va, uint32_t pg_num, uint64_t pa[pg_num], size_t pg_sz)
{
	int fd, rc = 0;
	size_t i;
	size_t sys_pgsz = odp_sys_page_size();

	if ((fd = open(PAGEMAP_FNAME, O_RDONLY)) < 0)
		return (ENOENT);

	for (i = 0; i < pg_num; i++) {
		off_t vpfn, ofs;

		va = (int8_t *)va + i * pg_sz;
		vpfn = (uintptr_t)va / sys_pgsz;
		ofs =  sizeof(uint64_t) * vpfn;

		rc = pread(fd, &pa[i], sizeof(uint64_t), ofs);
		rc -= sizeof(uint64_t);
		if (rc != 0) {
			printf("failed read of %lu bytes from \'%s\' "
				"at offset %zu, error code: %d\n",
				sizeof(uint64_t), PAGEMAP_FNAME, (size_t)ofs, errno);
			break;
		}
		pa[i] = (pa[i] & PAGEMAP_PFN_MASK) * sys_pgsz;
	}

	close(fd);

	return rc;
}

static int page_attr(uint64_t pa, uint64_t *attr, uint32_t pg_sz)
{
	int32_t fd, rc;
	off_t pfn, ofs;
	unsigned nb = sizeof(uint64_t);

	pfn = pa / pg_sz;
	ofs =  sizeof(uint64_t) * pfn;

	if ((fd = open("/proc/kpageflags", O_RDONLY)) < 0)
		return (ENOENT);

	if ((rc = pread(fd, attr, nb, ofs)) != (int)nb) {

		printf("failed read of %u bytes from \'%s\' "
			"at offset %zu, error code: %d\n",
			nb, PAGEMAP_FNAME, (size_t)ofs, errno);
		rc = ENOENT;
	}

	close(fd);

	return (rc);
}

static int hp_cmp(const void *a, const void *b)
{
	int64_t r = ((const struct hp *)a)->pa - ((const struct hp *)b)->pa;
	if (r < 0L)
		return -1;
	else if (r > 0L)
		return 1;
	else
		return 0;
}

static int find_contiguous(struct hp *hp, size_t n, size_t pg_sz,
			size_t req_num,	unsigned *basepg)
{
	unsigned i, base, best, k, s;
	base = k = 0;
	best = UINT_MAX;
	s = 1;

	ODP_DBG2("va=%lx pa=%lx\n", hp[0].va, hp[0].pa);

	for (i = 1; i < n; i++) {
		ODP_DBG2("va=%lx pa=%lx\n", hp[i].va, hp[i].pa);
		if (hp[i].pa - hp[i-1].pa == pg_sz) {
			s++;
		} else {
			if (s >= req_num && s < best) {
				best = s;
				base = k;
			}
			k = i;
			s = 1;
		}
	}
	if (s >= req_num && s < best) {
		best = s;
		base = k;
	}
	if (best == UINT_MAX)
		return -ENOENT;
	*basepg = base;
	return 0;
}


static void *alloc_virt(size_t size, size_t pg_sz)
{
	int fd;
	void *va = NULL;

	fd = open("/dev/zero",O_RDONLY);
	if (fd<0) {
		ODP_ERR("open:%s\n", strerror(errno));
		goto ret;
	}

	/* make room for alignment */
	size += pg_sz;

	va = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
	if (va == MAP_FAILED) {
		ODP_ERR("mmap: %s\n", strerror(errno));
		va = NULL;
		goto ret;
	}

	munmap(va, size);

	/* Align address to huge page*/
	va = (void *)((((uintptr_t)va) + pg_sz -1) & (~(pg_sz - 1)));
ret:
	close(fd);
	return va;
}

/* TODO CLEANUP: move prototype to internal header */
const char *odp_sys_huge_page_dir(void);

/* allocate memory for DMA in pages and obtain a physical address map*/
static void *hp_contig_alloc(size_t size, size_t n, uint64_t pa[n])
{
	int rc;
	uint64_t pg_sz, pg_num, i, sys_hpsz, sys_pgsz;
	uint32_t alloc_num = 0;
	unsigned cont_base;
	char hugefile[PATH_MAX];

	snprintf(hugefile, sizeof(hugefile), "%s/" FILE_NAME,
						odp_sys_huge_page_dir());

	sys_hpsz = odp_sys_huge_page_size();
	sys_pgsz = odp_sys_page_size();
	pg_sz = sys_hpsz;

	ODP_ASSERT((size & (sys_pgsz - 1)) == 0); /* size must be aligned to page */

	pg_num = (size + pg_sz - 1) / pg_sz;
	alloc_num = (pg_num > 1) ? pg_num * 10 : pg_num;

	ODP_ASSERT(pg_num <= n); /* check space for phys map */

	struct hp a[alloc_num];
	memset(a, 0, sizeof(a));

	for (i = 0; i < alloc_num; i++) {
		a[i].fd = open(hugefile, O_CREAT | O_RDWR , 0755);
		if (a[i].fd < 0) {
			ODP_ERR("open: %s\n",strerror(errno));
			goto err;
		}

		unlink(hugefile); //make it temp

		a[i].ptr = mmap(0, pg_sz,
			      PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_LOCKED | MAP_POPULATE, a[i].fd, 0);
		if (MAP_FAILED == a[i].ptr) {
			break;
		}
		ODP_DBG2("mmap va=%lx\n", a[i].va);
	}

	if (i < pg_num) {
		ODP_ERR("Not enough pages to satisfy mapping: %u out of %u\n", i, pg_num);
		goto err;
	}

	alloc_num = i;

	for (i = 0; i < alloc_num; i++) {
		rc = phys_map((void *)a[i].va, &a[i].pa, 1, sys_pgsz);
		if (rc)
			goto err;
		ODP_DBG2("va=%lx pa=%lx\n", a[i].va, a[i].pa);
	}

	qsort(a, alloc_num, sizeof(*a),hp_cmp);

	rc = find_contiguous(a, alloc_num, pg_sz, pg_num, &cont_base);
	if (rc) {
		ODP_ERR("Looked for contiguous %u pages but not found\n",
			pg_num);
		__odp_errno = ENOMEM;
		goto err;
	}

	ODP_DBG("Found contiguous memory va=%lx pa=%lx size=%u idx=%u\n",
		a[cont_base].va, a[cont_base].pa, pg_num, cont_base);

	void *va_base = alloc_virt(size, pg_sz);
	if (va_base == NULL)
		goto err;

	ODP_DBG2("va_base=%p size=%lu\n", va_base, size);
	ODP_ASSERT(cont_base+pg_num <= alloc_num); /* check hugepage array bounds */

	for (i = 0; i < pg_num; i++) {
		void *va = ((char *)va_base) + pg_sz*i;
		a[cont_base+i].new.ptr = mmap(va, pg_sz,
			      PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_LOCKED | MAP_FIXED, a[cont_base+i].fd, 0);
		if (a[cont_base+i].new.ptr == MAP_FAILED) {
			ODP_ERR("mmap: %s, va=%p\n", strerror(errno), va);
			goto err;
		}
		pa[i] = a[cont_base+i].pa;
		ODP_DBG2("va=%lx pa=%lx\n", a[cont_base+i].new.va, a[cont_base+i].pa);
	}

	void *va_out = a[cont_base].new.ptr;

	ODP_DBG2("va=%p\n", va_out);

	for (i = 0; i < alloc_num; i++) {
		munmap(a[i].ptr, pg_sz);
		if (a[i].new.ptr == NULL || a[i].new.ptr == MAP_FAILED)
			close(a[i].fd);
	}

	return va_out;
err:
	for (i = 0; i < alloc_num; i++) {
		if (a[i].new.ptr != NULL && a[i].new.ptr != MAP_FAILED)
			munmap(a[i].new.ptr, pg_sz);
		if (a[i].ptr != NULL && a[i].ptr != MAP_FAILED)
			munmap(a[i].ptr, pg_sz);
		close(a[i].fd);
	}

	return NULL;
}

static void __attribute__((unused)) print_pa(odp_shm_block_t *block)
{
	unsigned i;
	uint64_t pg_attr;

//	printf("va=%p size=%zukB pg_num=%u pg_sz=%x\n",
//		dma->va, dma->size/1024, dma->pg_num, dma->pg_size);

	for (i = 0; i < block->map->page_num; i++) {
		page_attr(block->map->phys_map[i], &pg_attr, odp_sys_page_size());
		ODP_PRINT("pa[%u]=%lx attr=%lx\n", i, block->map->phys_map[i], pg_attr);
	}
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	odp_shm_block_t *block;
	void *addr = MAP_FAILED;
	int fd = -1;
	uint64_t page_sz, huge_sz, sys_page_sz;
	uint64_t alloc_size;
	uint64_t alloc_offset;
	uint64_t *pa = NULL;

	if (align == 0) {
		ODP_ERR("Alignment must not be 0\n");
		return ODP_SHM_INVALID;
	}

	/* If already exists: O_EXCL: error, O_TRUNC: truncate to zero */
	int oflag = O_RDWR | O_CREAT | O_TRUNC;

	/* Create shared mapping and prefault all pages */
	int map_flag = MAP_SHARED | MAP_POPULATE;

	ODP_DBG("size=%llu align=%llu flags=%x\n", size, align, flags);

	huge_sz = odp_sys_huge_page_size();
	sys_page_sz = odp_sys_page_size();
	page_sz = sys_page_sz;

	/*
	 * Align size so that page-aligned memory can be anjusted to
	 * arbitrary alignment, ie 192 bytes need 192 - 4096 % 192
	 */

	alloc_offset = ODP_ALIGN_ROUNDUP(sys_page_sz, align) - sys_page_sz;
	alloc_size = size + alloc_offset;

	if (flags & ODP_SHM_PROC) {
		/* Creates a file to /dev/shm */
		fd = shm_open(name, oflag,
			      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		if (fd == -1) {
			ODP_DBG("odp_shm_reserve: shm_open failed\n");
			goto err;
		}

		if (ftruncate(fd, alloc_size) == -1) {
			ODP_DBG("odp_shm_reserve: ftruncate failed\n");
			goto err;
		}

	} else {
		map_flag |= MAP_ANONYMOUS;
	}

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (name != NULL && find_block(name, NULL)) {
		/* Found a block with the same name */
		ODP_ERR("odp_shm_reserve: name %s already used\n", name);
		__odp_errno = EEXIST;
		goto err;
	}

	/* At first try to reuse an existing mmap-ed block */
	block = alloc_free_block(size, align, flags);

	/* No more blocks or maps*/
	if (block == NULL) {
		__odp_errno = ENFILE;
		goto err;
	}
	/* Found and allocated a block*/
	if (block->addr != NULL) {
		if (name != NULL)
			strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
		block->name[ODP_SHM_NAME_LEN - 1] = 0;
		goto ret;
	}

	ODP_ASSERT(block->map != NULL); /* Map must be assigned to block */
	ODP_ASSERT(block->map->addr_orig == NULL); /* Map must be free */
	ODP_ASSERT(block->addr == NULL); /* Block must be free */

	/* Block not found. Now try to mmap a new memory region */
	block->map->huge = 0;
	addr        = MAP_FAILED;

#ifdef MAP_HUGETLB
	/* Try first contiguous huge pages */
	/* TODO OTHER: Find a way to advise the app if there is no need for
	 * contiguius memory, e.g. DMA*/

	if (huge_sz && alloc_size > page_sz && !(flags & ODP_SHM_SW_ONLY)) {
		page_sz      = huge_sz;
		map_flag    |= MAP_HUGETLB;
		block->map->huge  = 1;

		size_t hp_size = ODP_ALIGN_ROUNDUP(alloc_size, huge_sz);

		block->map->page_sz = page_sz;
		block->map->page_num = (hp_size + page_sz - 1) / page_sz;
		block->map->map_size = hp_size;

		pa = calloc(block->map->page_num, sizeof(*pa));
		if (!pa) {
			ODP_DBG("odp_shm_reserve: malloc failed\n");
			goto err;
		}

		addr = hp_contig_alloc(hp_size, block->map->page_num, pa);
		if (!addr)
			goto err;
	}

#endif

	/* Map a block using normal pages.
	 * The memory will not be contiguous.
	 */
	if (addr == NULL || addr == MAP_FAILED) {

		addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			    map_flag , fd, 0);

		if (addr == MAP_FAILED) {
			/* Alloc failed */
			ODP_DBG("odp_shm_reserve: mmap failed\n");
			goto err;
		} else {
			block->map->page_sz = page_sz;
			block->map->page_num = (alloc_size + page_sz - 1) / page_sz;
			block->map->map_size = alloc_size;
		}

		pa = calloc(block->map->page_num, sizeof(*pa));
		if (!pa) {
			ODP_DBG("odp_shm_reserve: malloc failed\n");
			goto err;
		}

		ODP_DBG("va=%p size=%lu pg_num=%lu page_sz=0x%lx\n", addr,
				alloc_size, block->map->page_num, page_sz);

		/* Obtain physical addresses of pages */
		/*XXX: do we need this if memory is not contiguous?*/

		if (phys_map_range(addr, block->map->page_num, pa, page_sz)) {
			ODP_DBG("odp_shm_reserve: phys_map failed\n");
			goto err;
		}
	}

	block->map->phys_map = pa;
	block->map->addr_orig = addr;
	block->map->flags = flags;
	block->map->free_size = block->map->map_size - alloc_size;
	block->map->free_offset = alloc_size;

	if (name != NULL)
		strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;

	block->alloc_size = alloc_size;
	block->size = size;
	block->align = align;
	block->map->fd = fd;
	/* move to correct alignment */
	block->addr = ODP_ALIGN_ROUNDUP_PTR(addr, align);
	block->phys = block->map->phys_map[0] +
		((uintptr_t)block->addr - (uintptr_t)block->map->addr_orig);

ret:
	block->map->refcnt++;
	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return (odp_shm_t)block;
err:
	if (addr != MAP_FAILED && addr != NULL)
		munmap(addr, alloc_size);
	if (pa)
		free(pa);
	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return ODP_SHM_INVALID;
}

odp_shm_t odp_shm_lookup(const char *name)
{
	uint32_t i;
	odp_shm_t shm;

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name, &i) == 0) {
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return ODP_SHM_INVALID;
	}

	shm = (odp_shm_t)&odp_shm_tbl->block[i];
	odp_spinlock_unlock(&odp_shm_tbl->lock);

	return shm;
}


void *odp_shm_addr(odp_shm_t shm)
{
	if (shm == ODP_SHM_INVALID)
		return NULL;

	odp_shm_block_t *block = (odp_shm_block_t *)shm;

	return block->addr;
}

uintptr_t odp_shm_phys_addr_offset(odp_shm_t shm)
{
	odp_shm_block_t *block = (odp_shm_block_t *)shm;

#ifdef PAGING
#error "Paged virt to phys not implemented"
#else
	return (uintptr_t)block->addr - (uintptr_t)block->phys;
#endif
}

void *odp_shm_virt_addr(odp_shm_t shm, uint64_t pa)
{
#ifdef PAGING
#error "Paged virt to phys not implemented"
#else
	uintptr_t off;
	odp_shm_block_t *block = (odp_shm_block_t *)shm;

	off = pa - block->phys;

	ODP_ASSERT_MSG(off < block->size,
		"Offset %lx out of range %lx\n", off, block->size);

	return (int8_t *)block->addr + off;
#endif
}

int odp_shm_phys_addr_n(odp_shm_t shm, size_t len,
			void ** __restrict__ va, uint64_t * __restrict__ pa,
			uintptr_t addoffset)
{
	size_t idx;
	uintptr_t off;
	odp_shm_block_t * __restrict__ block;

	block = (odp_shm_block_t *)shm;

	for (idx = 0; idx < len; idx++) {

		ODP_ASSERT(((uintptr_t)va[idx] - (uintptr_t)block->addr) < block->size);

		off = ((uintptr_t)va[idx] - (uintptr_t)block->addr);
#ifdef PAGING
		uintptr_t pg = off / block->page_sz;
		uintptr_t pg_off = off % block->page_sz;
		pa[idx] = block->map->phys_map[pg] + pg_off + addoffset;
#else
		/* Memory is physically contiguous */
		pa[idx] = block->phys + off + addoffset;
#endif
	}

	return 0;
}

uint64_t odp_shm_phys_addr(odp_shm_t shm, void *va)
{
	uintptr_t off;
	odp_shm_block_t *block = (odp_shm_block_t *)shm;

	ODP_ASSERT(((uintptr_t)va - (uintptr_t)block->addr) < block->size);

	off = ((uintptr_t)va - (uintptr_t)block->addr);
#ifdef PAGING
	uintptr_t pg = off / block->page_sz;
	uintptr_t pg_off = off % block->page_sz;
	return block->map->phys_map[pg] + pg_off;
#else
	/* Memory is physically contiguous */
	return block->phys + off;
#endif
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	odp_shm_block_t *block;

	block = (odp_shm_block_t *)shm;

	info->name      = block->name;
	info->addr      = block->addr;
	info->size      = block->size;
	info->page_size = block->map->page_sz;
	info->flags     = block->map->flags;

	return 0;
}


void odp_shm_print_all(void)
{
	int i;

	ODP_PRINT("\nShared memory\n");
	ODP_PRINT("--------------\n");
	ODP_PRINT("  page size:      %"PRIu64" kB\n",
		  odp_sys_page_size() / 1024);
	ODP_PRINT("  huge page size: %"PRIu64" kB\n",
		  odp_sys_huge_page_size() / 1024);
	ODP_PRINT("\n");

	ODP_PRINT("  id name                       kB align huge addr end map_addr map_size map_resvd map_free phys\n");

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		odp_shm_block_t *block;

		block = &odp_shm_tbl->block[i];

		const char *name = block->name[0] ? block->name : "N/A";

		if (block->addr) {
			ODP_PRINT("  %2i %-24s %4"PRIu64"  %4"PRIu64
				  " %2c   %p %p %p %"PRIu64" %"PRIu64" %"PRIu64" %"PRIx64"\n",
				  i,
				  name,
				  block->size/1024,
				  block->align,
				  (block->map->huge ? '*' : 'x'),
				  block->addr,
				  (int8_t *)block->addr+block->size,
				  block->map->addr_orig,
				  block->map->map_size,
				  block->map->free_offset,
				  block->map->free_size,
				  block->phys);
		}
	}
	ODP_PRINT("\n");
}
