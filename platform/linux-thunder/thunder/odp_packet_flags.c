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

#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>

int odp_packet_has_error(odp_packet_t pkt)
{
	return packet_hdr_has_error((struct packet_hdr_t *)pkt);
}

/* Get Input Flags */

int odp_packet_has_l2(odp_packet_t pkt)
{
	return packet_hdr_has_l2((struct packet_hdr_t*)pkt);
}

int odp_packet_has_l2_error(odp_packet_t pkt)
{
	return packet_hdr_has_l2_error((struct packet_hdr_t*)pkt);
}

int odp_packet_has_l3(odp_packet_t pkt)
{
	return packet_hdr_has_l3((struct packet_hdr_t*)pkt);
}

int odp_packet_has_l3_error(odp_packet_t pkt)
{
	return packet_hdr_has_l3_error((struct packet_hdr_t*)pkt);
}

int odp_packet_has_l4(odp_packet_t pkt)
{
	return packet_hdr_has_l4((struct packet_hdr_t*)pkt);
}

int odp_packet_has_l4_error(odp_packet_t pkt)
{
	return packet_hdr_has_l4_error((struct packet_hdr_t*)pkt);
}

int odp_packet_has_eth(odp_packet_t pkt)
{
	return packet_hdr_has_eth((struct packet_hdr_t*)pkt);
}

int odp_packet_has_eth_bcast(odp_packet_t pkt)
{
	return packet_hdr_has_eth_bcast((struct packet_hdr_t*)pkt);
}

int odp_packet_has_eth_mcast(odp_packet_t pkt)
{
	return packet_hdr_has_eth_mcast((struct packet_hdr_t*)pkt);
}

int odp_packet_has_jumbo(odp_packet_t pkt)
{
	return packet_hdr_has_jumbo((struct packet_hdr_t*)pkt);
}

int odp_packet_has_vlan(odp_packet_t pkt)
{
	return packet_hdr_has_vlan((struct packet_hdr_t*)pkt);
}

int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	return packet_hdr_has_vlan_qinq((struct packet_hdr_t*)pkt);
}

int odp_packet_has_arp(odp_packet_t pkt)
{
	return packet_hdr_has_arp((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ipv4(odp_packet_t pkt)
{
	return packet_hdr_has_ipv4((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ipv6(odp_packet_t pkt)
{
	return packet_hdr_has_ipv6((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ip_bcast(odp_packet_t pkt)
{
	return packet_hdr_has_ip_bcast((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ip_mcast(odp_packet_t pkt)
{
	return packet_hdr_has_ip_mcast((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	return packet_hdr_has_ipfrag((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ipopt(odp_packet_t pkt)
{
	return packet_hdr_has_ipopt((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ipsec(odp_packet_t pkt)
{
	return packet_hdr_has_ipsec((struct packet_hdr_t*)pkt);
}

int odp_packet_has_udp(odp_packet_t pkt)
{
	return packet_hdr_has_udp((struct packet_hdr_t*)pkt);
}

int odp_packet_has_tcp(odp_packet_t pkt)
{
	return packet_hdr_has_tcp((struct packet_hdr_t*)pkt);
}

int odp_packet_has_sctp(odp_packet_t pkt)
{
	return packet_hdr_has_sctp((struct packet_hdr_t*)pkt);
}

int odp_packet_has_icmp(odp_packet_t pkt)
{
	return packet_hdr_has_icmp((struct packet_hdr_t*)pkt);
}

int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	return packet_hdr_has_flow_hash((struct packet_hdr_t*)pkt);
}

int odp_packet_has_ts(odp_packet_t pkt)
{
	return packet_hdr_has_ts((struct packet_hdr_t*)pkt);
}

odp_packet_color_t odp_packet_color(odp_packet_t pkt)
{
	return packet_hdr_color((struct packet_hdr_t*)pkt);
}

void odp_packet_color_set(odp_packet_t pkt, odp_packet_color_t color)
{
	packet_hdr_color_set((struct packet_hdr_t*)pkt, color);
}

odp_bool_t odp_packet_drop_eligible(odp_packet_t pkt)
{
	return packet_hdr_drop_eligible((struct packet_hdr_t*)pkt);
}

void odp_packet_drop_eligible_set(odp_packet_t pkt, odp_bool_t drop)
{
	packet_hdr_drop_eligible_set((struct packet_hdr_t*)pkt, drop);
}

int8_t odp_packet_shaper_len_adjust(odp_packet_t pkt)
{
	return packet_hdr_shaper_len_adjust((struct packet_hdr_t*)pkt);
}

void odp_packet_shaper_len_adjust_set(odp_packet_t pkt, int8_t adj)
{
	packet_hdr_shaper_len_adjust_set((struct packet_hdr_t*)pkt, adj);
}

/* Set Input Flags */

void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_l2_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_l3_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_l4_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_eth_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_eth_bcast_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_eth_bcast_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_eth_mcast_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_eth_mcast_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_jumbo_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_vlan_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_vlan_qinq_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_arp_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ipv4_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ipv6_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ip_bcast_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ip_bcast_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ip_mcast_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ip_mcast_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ipfrag_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ipopt_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_ipsec_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_udp_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_tcp_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_sctp_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	packet_hdr_has_icmp_set((struct packet_hdr_t*)pkt, val);
}

void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	packet_hdr_has_flow_hash_clr((struct packet_hdr_t*)pkt);
}

void odp_packet_has_ts_clr(odp_packet_t pkt)
{
	packet_hdr_has_ts_set((struct packet_hdr_t*)pkt, 0);
}
