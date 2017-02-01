/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP alignments
 */

#ifndef ODP_PLAT_ALIGN_H_
#define ODP_PLAT_ALIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_compiler_optim
 *  @{
 */

#ifdef __GNUC__

#define ODP_ALIGNED(x) __attribute__((__aligned__(x)))

#define ODP_PACKED __attribute__((__packed__))

#define ODP_OFFSETOF(type, member) __builtin_offsetof(type, member)

#define ODP_FIELD_SIZEOF(type, member) sizeof(((type *)0)->member)

/*
 * Warning: it's not possible to have conditional odp/api
 * so we need to enforce HAVE_THUNDERX in this case.
 */

#else
#error Non-gcc compatible compiler
#endif

/*
 * Warning: it's not possible to have conditional odp/api
 * so we need to enforce HAVE_THUNDERX in this case.
 */
#if 1 /* ifndef HAVE_THUNDERX */
#define ODP_PAGE_SIZE       (odp_sys_page_size())
#define ODP_PAGE_SIZE_MAX   (64 * 1024)

#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)

#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE_MAX)
#else
#define ODP_PAGE_SIZE       4096

#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)

#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE)
#endif

/**
 * @}
 */

#include <odp/api/spec/align.h>
#include <odp/api/cpu_arch.h>

#ifdef __cplusplus
}
#endif

#endif
