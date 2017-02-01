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
#include <assert.h>

#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>

odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

void *odp_buffer_addr(odp_buffer_t buf)
{
	return ((struct odp_buffer_hdr_t*)buf)->data;
}


uint32_t odp_buffer_size(odp_buffer_t buf)
{
	return ((struct odp_buffer_hdr_t*)buf)->data_size;
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	return (buf != NULL);
}

void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = buffer_snprint(str, max_len-1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);
int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	return buffer_snprint(str, n, buf);
}

/* Internal functions */

int buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	int len = 0;

	if (!buf) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  pool         %p\n",        ((struct odp_buffer_hdr_t*)buf)->pool);
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",        ((struct odp_buffer_hdr_t*)buf)->data);
	len += snprintf(&str[len], n-len,
			"  size         %u\n",        ((struct odp_buffer_hdr_t*)buf)->data_size);
	len += snprintf(&str[len], n-len,
			"  type         %i\n",        ((struct odp_buffer_hdr_t*)buf)->type);

	return len;
}
