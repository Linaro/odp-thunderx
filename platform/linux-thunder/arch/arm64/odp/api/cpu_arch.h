/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_CPU_ARCH_H_
#define ODP_PLAT_CPU_ARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @ingroup odp_compiler_optim
 *  @{
 */

#define ODP_CACHE_LINE_SIZE 128

/**
 * @}
 */

static inline void odp_cpu_pause(void)
{
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
}

#define MRS(reg) ({ \
	uint64_t val; \
	__asm volatile("mrs %0, " #reg : "=r" (val)); \
	val; \
	})

#define GIGA 1000000000

static inline uint64_t odp_cpu_cycles(void)
{
	return MRS(cntvct_el0);
}

#ifdef __cplusplus
}
#endif

#endif
