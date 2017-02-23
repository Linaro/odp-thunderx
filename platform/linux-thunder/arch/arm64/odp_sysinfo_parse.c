/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/cpu_arch.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <string.h>

static const char *get_implementer_str(unsigned implementer)
{
	switch (implementer) {
		case 0x43:
			return "Cavium";
		case 0x41:
		case 0x50:
			return "APM";
		case 0x42:
			return "Broadcom";
		default:
			return "Unknown";
	};
}

static const char *get_part_str(unsigned part)
{
	switch (part) {
		case 0xA1:
			return "ThunderX";
		case 0xA2:
			return "ThunderX 81XX";
		case 0xA3:
			return "Octeon TX 83XX";
		default:
			return "Unknown";
	};
}

int cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	unsigned implementer,part,id = 0;
	size_t max = sizeof(sysinfo->model_str);
	char str[1024];

	//ODP_DBG("Warning: use dummy values for freq and model string\n");
	strcpy(sysinfo->cpu_arch_str, "arm64");
	while (fgets(str, sizeof(str), file) != NULL && id < MAX_CPU_NUMBER) {
		if ( sscanf(str, "processor : %u", &id) == 1)
			sysinfo->cpu_hz_max[id] = odp_cpu_hz_current(id);

		if (sscanf(str, "CPU implementer : 0x%x", &implementer) == 1)
			snprintf(sysinfo->model_str[id], max, "%s ",
					get_implementer_str(implementer));
		if (sscanf(str, "CPU part : 0x%x", &part) == 1)
			strncat(sysinfo->model_str[id],
				get_part_str(part), max);

	}
	return 0;
}

#define USE(x) __asm volatile ("" :: "r" (x));
#define X4(x) x x x x
#define X16(x) X4(X4(x))

/*The loop yields good results only when optimized*/

__attribute__((noinline,optimize("-O2")))
static void calibrating_loop(size_t n)
{
	size_t i;
	long r = 1;
	for (i=0; i < n; i++) {
		X16(
		r ^= r + 4;
		)
	}
	USE(r);
}

uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	uint64_t t1,t2;
	uint64_t hz = odp_cpu_cycles_resolution();
	size_t n = 100000;

	t1 = odp_cpu_cycles();
	calibrating_loop(n);
	t2 = odp_cpu_cycles();

	double t_cyc = ((double)(t2-t1))/(n*32.0);
	double cyc_mhz = hz/(t_cyc*1000000.0);
	return (((long)cyc_mhz + 50) / 100) * 100000000;
}
