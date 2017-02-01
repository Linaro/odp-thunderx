/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <stdlib.h>
#include <time.h>

#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp_debug_internal.h>

uint64_t odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

uint64_t odp_cpu_cycles_resolution(void)
{
	return 1;
}
