/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

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
		sscanf(str, "processor : %u", &id);

		if (sscanf(str, "CPU implementer : 0x%x", &implementer) == 1)
			snprintf(sysinfo->model_str[id], max, "%s ",
					get_implementer_str(implementer));
		if (sscanf(str, "CPU part : 0x%x", &part) == 1)
			strncat(sysinfo->model_str[id],
				get_part_str(part), max);

		sysinfo->cpu_hz_max[id] = 1400000000;
	}
	return 0;
}

uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	return 0;
}
