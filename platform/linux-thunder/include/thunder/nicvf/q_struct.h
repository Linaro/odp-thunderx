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

#ifndef Q_STRUCT_H
#define Q_STRUCT_H

#include <inttypes.h>
#include <endian.h>
#include <asm/byteorder.h>

#if defined(__BIG_ENDIAN_BITFIELD)
#elif defined(__LITTLE_ENDIAN_BITFIELD)
#else
#error Endianing not defined
#endif

#define NICVF_CQE_RBPTR_WORD            (6)
#define NICVF_CQE_RX2_RBPTR_WORD        (7)

/* Load transaction types for reading segment bytes specified by
 * NIC_SEND_GATHER_S[LD_TYPE].
 */
enum nic_send_ld_type_e {
	NIC_SEND_LD_TYPE_E_LDD = 0x0,
	NIC_SEND_LD_TYPE_E_LDT = 0x1,
	NIC_SEND_LD_TYPE_E_LDWB = 0x2,
	NIC_SEND_LD_TYPE_E_ENUM_LAST = 0x3,
};

enum ether_type_algorithm {
	ETYPE_ALG_NONE = 0x0,
	ETYPE_ALG_SKIP = 0x1,
	ETYPE_ALG_ENDPARSE = 0x2,
	ETYPE_ALG_VLAN = 0x3,
	ETYPE_ALG_VLAN_STRIP = 0x4,
};

enum layer3_type {
	L3TYPE_NONE = 0x00,
	L3TYPE_GRH = 0x01,
	L3TYPE_IPV4 = 0x04,
	L3TYPE_IPV4_OPTIONS = 0x05,
	L3TYPE_IPV6 = 0x06,
	L3TYPE_IPV6_OPTIONS = 0x07,
	L3TYPE_ET_STOP = 0x0D,
	L3TYPE_OTHER = 0x0E,
};

enum layer4_type {
	L4TYPE_NONE = 0x00,
	L4TYPE_IPSEC_ESP = 0x01,
	L4TYPE_IPFRAG = 0x02,
	L4TYPE_IPCOMP = 0x03,
	L4TYPE_TCP = 0x04,
	L4TYPE_UDP = 0x05,
	L4TYPE_SCTP = 0x06,
	L4TYPE_GRE = 0x07,
	L4TYPE_ROCE_BTH = 0x08,
	L4TYPE_OTHER = 0x0E,
};

/* CPI and RSSI configuration */
enum cpi_algorithm_type {
	CPI_ALG_NONE = 0x0,
	CPI_ALG_VLAN = 0x1,
	CPI_ALG_VLAN16 = 0x2,
	CPI_ALG_DIFF = 0x3,
};

enum rss_algorithm_type {
	RSS_ALG_NONE = 0x00,
	RSS_ALG_PORT = 0x01,
	RSS_ALG_IP = 0x02,
	RSS_ALG_TCP_IP = 0x03,
	RSS_ALG_UDP_IP = 0x04,
	RSS_ALG_SCTP_IP = 0x05,
	RSS_ALG_GRE_IP = 0x06,
	RSS_ALG_ROCE = 0x07,
};

enum rss_hash_cfg {
	RSS_HASH_L2ETC = 0x00,
	RSS_HASH_IP = 0x01,
	RSS_HASH_TCP = 0x02,
	RSS_HASH_TCP_SYN_DIS = 0x03,
	RSS_HASH_UDP = 0x04,
	RSS_HASH_L4ETC = 0x05,
	RSS_HASH_ROCE = 0x06,
	RSS_L3_BIDI = 0x07,
	RSS_L4_BIDI = 0x08,
};

/* Completion queue entry types */
enum cqe_type {
	CQE_TYPE_INVALID = 0x0,
	CQE_TYPE_RX = 0x2,
	CQE_TYPE_RX_SPLIT = 0x3,
	CQE_TYPE_RX_TCP = 0x4,
	CQE_TYPE_SEND = 0x8,
	CQE_TYPE_SEND_PTP = 0x9,
};

enum cqe_rx_tcp_status {
	CQE_RX_STATUS_VALID_TCP_CNXT = 0x00,
	CQE_RX_STATUS_INVALID_TCP_CNXT = 0x0F,
};

enum cqe_send_status {
	CQE_SEND_STATUS_GOOD = 0x00,
	CQE_SEND_STATUS_DESC_FAULT = 0x01,
	CQE_SEND_STATUS_HDR_CONS_ERR = 0x11,
	CQE_SEND_STATUS_SUBDESC_ERR = 0x12,
	CQE_SEND_STATUS_IMM_SIZE_OFLOW = 0x80,
	CQE_SEND_STATUS_CRC_SEQ_ERR = 0x81,
	CQE_SEND_STATUS_DATA_SEQ_ERR = 0x82,
	CQE_SEND_STATUS_MEM_SEQ_ERR = 0x83,
	CQE_SEND_STATUS_LOCK_VIOL = 0x84,
	CQE_SEND_STATUS_LOCK_UFLOW = 0x85,
	CQE_SEND_STATUS_DATA_FAULT = 0x86,
	CQE_SEND_STATUS_TSTMP_CONFLICT = 0x87,
	CQE_SEND_STATUS_TSTMP_TIMEOUT = 0x88,
	CQE_SEND_STATUS_MEM_FAULT = 0x89,
	CQE_SEND_STATUS_CSUM_OVERLAP = 0x8A,
	CQE_SEND_STATUS_CSUM_OVERFLOW = 0x8B,
};

enum cqe_rx_tcp_end_reason {
	CQE_RX_TCP_END_FIN_FLAG_DET = 0,
	CQE_RX_TCP_END_INVALID_FLAG = 1,
	CQE_RX_TCP_END_TIMEOUT = 2,
	CQE_RX_TCP_END_OUT_OF_SEQ = 3,
	CQE_RX_TCP_END_PKT_ERR = 4,
	CQE_RX_TCP_END_QS_DISABLED = 0x0F,
};

/* Packet protocol level error enumeration */
enum cqe_rx_err_level {
	CQE_RX_ERRLVL_RE = 0x0,
	CQE_RX_ERRLVL_L2 = 0x1,
	CQE_RX_ERRLVL_L3 = 0x2,
	CQE_RX_ERRLVL_L4 = 0x3,
};

/* Packet protocol level error type enumeration */
enum cqe_rx_err_opcode {
	CQE_RX_ERR_RE_NONE = 0x0,
	CQE_RX_ERR_RE_PARTIAL = 0x1,
	CQE_RX_ERR_RE_JABBER = 0x2,
	CQE_RX_ERR_RE_FCS = 0x7,
	CQE_RX_ERR_RE_TERMINATE = 0x9,
	CQE_RX_ERR_RE_RX_CTL = 0xb,
	CQE_RX_ERR_PREL2_ERR = 0x1f,
	CQE_RX_ERR_L2_FRAGMENT = 0x20,
	CQE_RX_ERR_L2_OVERRUN = 0x21,
	CQE_RX_ERR_L2_PFCS = 0x22,
	CQE_RX_ERR_L2_PUNY = 0x23,
	CQE_RX_ERR_L2_MAL = 0x24,
	CQE_RX_ERR_L2_OVERSIZE = 0x25,
	CQE_RX_ERR_L2_UNDERSIZE = 0x26,
	CQE_RX_ERR_L2_LENMISM = 0x27,
	CQE_RX_ERR_L2_PCLP = 0x28,
	CQE_RX_ERR_IP_NOT = 0x41,
	CQE_RX_ERR_IP_CHK = 0x42,
	CQE_RX_ERR_IP_MAL = 0x43,
	CQE_RX_ERR_IP_MALD = 0x44,
	CQE_RX_ERR_IP_HOP = 0x45,
	CQE_RX_ERR_L3_ICRC = 0x46,
	CQE_RX_ERR_L3_PCLP = 0x47,
	CQE_RX_ERR_L4_MAL = 0x61,
	CQE_RX_ERR_L4_CHK = 0x62,
	CQE_RX_ERR_UDP_LEN = 0x63,
	CQE_RX_ERR_L4_PORT = 0x64,
	CQE_RX_ERR_TCP_FLAG = 0x65,
	CQE_RX_ERR_TCP_OFFSET = 0x66,
	CQE_RX_ERR_L4_PCLP = 0x67,
	CQE_RX_ERR_RBDR_TRUNC = 0x70,
};

struct cqe_rx_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t   cqe_type:4; /* W0 */
	uint64_t   stdn_fault:1;
	uint64_t   rsvd0:1;
	uint64_t   rq_qs:7;
	uint64_t   rq_idx:3;
	uint64_t   rsvd1:12;
	uint64_t   rss_alg:4;
	uint64_t   rsvd2:4;
	uint64_t   rb_cnt:4;
	uint64_t   vlan_found:1;
	uint64_t   vlan_stripped:1;
	uint64_t   vlan2_found:1;
	uint64_t   vlan2_stripped:1;
	uint64_t   l4_type:4;
	uint64_t   l3_type:4;
	uint64_t   l2_present:1;
	uint64_t   err_level:3;
	uint64_t   err_opcode:8;

	uint64_t   pkt_len:16; /* W1 */
	uint64_t   l2_ptr:8;
	uint64_t   l3_ptr:8;
	uint64_t   l4_ptr:8;
	uint64_t   cq_pkt_len:8;
	uint64_t   align_pad:3;
	uint64_t   rsvd3:1;
	uint64_t   chan:12;

	uint64_t   rss_tag:32; /* W2 */
	uint64_t   vlan_tci:16;
	uint64_t   vlan_ptr:8;
	uint64_t   vlan2_ptr:8;

	uint16_t   rb3_sz; /* W3 */
	uint16_t   rb2_sz;
	uint16_t   rb1_sz;
	uint16_t   rb0_sz;

	uint16_t   rb7_sz; /* W4 */
	uint16_t   rb6_sz;
	uint16_t   rb5_sz;
	uint16_t   rb4_sz;

	uint16_t   rb11_sz; /* W5 */
	uint16_t   rb10_sz;
	uint16_t   rb9_sz;
	uint16_t   rb8_sz;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	union {
		uint64_t w0_val;
		struct w0_struct_t {
			uint64_t   err_opcode:8;
			uint64_t   err_level:3;
			uint64_t   l2_present:1;
			uint64_t   l3_type:4;
			uint64_t   l4_type:4;
			uint64_t   vlan2_stripped:1;
			uint64_t   vlan2_found:1;
			uint64_t   vlan_stripped:1;
			uint64_t   vlan_found:1;
			uint64_t   rb_cnt:4;
			uint64_t   rsvd2:4;
			uint64_t   rss_alg:4;
			uint64_t   rsvd1:12;
			uint64_t   rq_idx:3;
			uint64_t   rq_qs:7;
			uint64_t   rsvd0:1;
			uint64_t   stdn_fault:1;
			uint64_t   cqe_type:4; /* W0 */
		} w0;
	};
	union {
		uint64_t w1_val;
		struct w1_struct_t {
			uint64_t   chan:12;
			uint64_t   rsvd3:1;
			uint64_t   align_pad:3;
			uint64_t   cq_pkt_len:8;
			uint64_t   l4_ptr:8;
			uint64_t   l3_ptr:8;
			uint64_t   l2_ptr:8;
			uint64_t   pkt_len:16; /* W1 */
		} w1;
	};
	union {
		uint64_t w2_val;
		struct w2_struct_t {
			uint64_t   vlan2_ptr:8;
			uint64_t   vlan_ptr:8;
			uint64_t   vlan_tci:16;
			uint64_t   rss_tag:32; /* W2 */
		} w2;
	};
	uint16_t   rb0_sz;
	uint16_t   rb1_sz;
	uint16_t   rb2_sz;
	uint16_t   rb3_sz; /* W3 */
	uint16_t   rb4_sz;
	uint16_t   rb5_sz;
	uint16_t   rb6_sz;
	uint16_t   rb7_sz; /* W4 */
	uint16_t   rb8_sz;
	uint16_t   rb9_sz;
	uint16_t   rb10_sz;
	uint16_t   rb11_sz; /* W5 */
#endif
};

struct cqe_rx_tcp_err_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t   cqe_type:4; /* W0 */
	uint64_t   rsvd0:60;

	uint64_t   rsvd1:4; /* W1 */
	uint64_t   partial_first:1;
	uint64_t   rsvd2:27;
	uint64_t   rbdr_bytes:8;
	uint64_t   rsvd3:24;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t   rsvd0:60;
	uint64_t   cqe_type:4;

	uint64_t   rsvd3:24;
	uint64_t   rbdr_bytes:8;
	uint64_t   rsvd2:27;
	uint64_t   partial_first:1;
	uint64_t   rsvd1:4;
#endif
};

struct cqe_rx_tcp_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t   cqe_type:4; /* W0 */
	uint64_t   rsvd0:52;
	uint64_t   cq_tcp_status:8;

	uint64_t   rsvd1:32; /* W1 */
	uint64_t   tcp_cntx_bytes:8;
	uint64_t   rsvd2:8;
	uint64_t   tcp_err_bytes:16;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t   cq_tcp_status:8;
	uint64_t   rsvd0:52;
	uint64_t   cqe_type:4; /* W0 */

	uint64_t   tcp_err_bytes:16;
	uint64_t   rsvd2:8;
	uint64_t   tcp_cntx_bytes:8;
	uint64_t   rsvd1:32; /* W1 */
#endif
};

struct cqe_send_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t   cqe_type:4; /* W0 */
	uint64_t   rsvd0:4;
	uint64_t   sqe_ptr:16;
	uint64_t   rsvd1:4;
	uint64_t   rsvd2:10;
	uint64_t   sq_qs:7;
	uint64_t   sq_idx:3;
	uint64_t   rsvd3:8;
	uint64_t   send_status:8;

	uint64_t   ptp_timestamp:64; /* W1 */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t   send_status:8;
	uint64_t   rsvd3:8;
	uint64_t   sq_idx:3;
	uint64_t   sq_qs:7;
	uint64_t   rsvd2:10;
	uint64_t   rsvd1:4;
	uint64_t   sqe_ptr:16;
	uint64_t   rsvd0:4;
	uint64_t   cqe_type:4; /* W0 */

	uint64_t   ptp_timestamp:64;
#endif
};

struct cq_entry_type_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t cqe_type:4;
	uint64_t __pad:60;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t __pad:60;
	uint64_t cqe_type:4;
#endif
};

union cq_entry_t {
	uint64_t u[64];
	struct cq_entry_type_t type;
	struct cqe_send_t tx_hdr;
	struct cqe_rx_t rx_hdr;
	struct cqe_rx_tcp_t rx_tcp_hdr;
	struct cqe_rx_tcp_err_t rx_tcp_err_hdr;
};
/* must be aligned with HW definition */
_Static_assert(sizeof(union cq_entry_t) == 512, "CQ entry is 512 bytes");

struct rbdr_entry_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	union {
		struct {
			uint64_t   rsvd0:15;
			uint64_t   buf_addr:42;
			uint64_t   cache_align:7;
		};
		uint64_t full_addr;
	};
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	union {
		struct {
			uint64_t   cache_align:7;
			uint64_t   buf_addr:42;
			uint64_t   rsvd0:15;
		};
		uint64_t full_addr;
	};
#endif
};
_Static_assert(sizeof(struct rbdr_entry_t) == sizeof(uint64_t),"RBDR entry is 8 bytes");

/* TCP reassembly context */
struct rbe_tcp_cnxt_t {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t   tcp_pkt_cnt:12;
	uint64_t   rsvd1:4;
	uint64_t   align_hdr_bytes:4;
	uint64_t   align_ptr_bytes:4;
	uint64_t   ptr_bytes:16;
	uint64_t   rsvd2:24;
	uint64_t   cqe_type:4;
	uint64_t   rsvd0:54;
	uint64_t   tcp_end_reason:2;
	uint64_t   tcp_status:4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t   tcp_status:4;
	uint64_t   tcp_end_reason:2;
	uint64_t   rsvd0:54;
	uint64_t   cqe_type:4;
	uint64_t   rsvd2:24;
	uint64_t   ptr_bytes:16;
	uint64_t   align_ptr_bytes:4;
	uint64_t   align_hdr_bytes:4;
	uint64_t   rsvd1:4;
	uint64_t   tcp_pkt_cnt:12;
#endif
};

/* Always Big endian */
struct rx_hdr_t {
	uint64_t   opaque:32;
	uint64_t   rss_flow:8;
	uint64_t   skip_length:6;
	uint64_t   disable_rss:1;
	uint64_t   disable_tcp_reassembly:1;
	uint64_t   nodrop:1;
	uint64_t   dest_alg:2;
	uint64_t   rsvd0:2;
	uint64_t   dest_rq:11;
};

enum send_l4_csum_type {
	SEND_L4_CSUM_DISABLE = 0x00,
	SEND_L4_CSUM_UDP = 0x01,
	SEND_L4_CSUM_TCP = 0x02,
	SEND_L4_CSUM_SCTP = 0x03,
};

enum send_crc_alg {
	SEND_CRCALG_CRC32 = 0x00,
	SEND_CRCALG_CRC32C = 0x01,
	SEND_CRCALG_ICRC = 0x02,
};

enum send_load_type {
	SEND_LD_TYPE_LDD = 0x00,
	SEND_LD_TYPE_LDT = 0x01,
	SEND_LD_TYPE_LDWB = 0x02,
};

enum send_mem_alg_type {
	SEND_MEMALG_SET = 0x00,
	SEND_MEMALG_ADD = 0x08,
	SEND_MEMALG_SUB = 0x09,
	SEND_MEMALG_ADDLEN = 0x0A,
	SEND_MEMALG_SUBLEN = 0x0B,
};

enum send_mem_dsz_type {
	SEND_MEMDSZ_B64 = 0x00,
	SEND_MEMDSZ_B32 = 0x01,
	SEND_MEMDSZ_B8 = 0x03,
};

enum sq_subdesc_type {
	SQ_DESC_TYPE_INVALID = 0x00,
	SQ_DESC_TYPE_HEADER = 0x01,
	SQ_DESC_TYPE_CRC = 0x02,
	SQ_DESC_TYPE_IMMEDIATE = 0x03,
	SQ_DESC_TYPE_GATHER = 0x04,
	SQ_DESC_TYPE_MEMORY = 0x05,
};

struct sq_crc_subdesc {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t    rsvd1:32;
	uint64_t    crc_ival:32;
	uint64_t    subdesc_type:4;
	uint64_t    crc_alg:2;
	uint64_t    rsvd0:10;
	uint64_t    crc_insert_pos:16;
	uint64_t    hdr_start:16;
	uint64_t    crc_len:16;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t    crc_len:16;
	uint64_t    hdr_start:16;
	uint64_t    crc_insert_pos:16;
	uint64_t    rsvd0:10;
	uint64_t    crc_alg:2;
	uint64_t    subdesc_type:4;
	uint64_t    crc_ival:32;
	uint64_t    rsvd1:32;
#endif
};

struct sq_gather_subdesc {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t    subdesc_type:4; /* W0 */
	uint64_t    ld_type:2;
	uint64_t    rsvd0:42;
	uint64_t    size:16;

	uint64_t    rsvd1:15; /* W1 */
	uint64_t    addr:49;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t    size:16;
	uint64_t    rsvd0:42;
	uint64_t    ld_type:2;
	uint64_t    subdesc_type:4; /* W0 */

	uint64_t    addr:49;
	uint64_t    rsvd1:15; /* W1 */
#endif
};

/* SQ immediate subdescriptor */
struct sq_imm_subdesc {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t    subdesc_type:4; /* W0 */
	uint64_t    rsvd0:46;
	uint64_t    len:14;

	uint64_t    data:64; /* W1 */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t    len:14;
	uint64_t    rsvd0:46;
	uint64_t    subdesc_type:4; /* W0 */

	uint64_t    data:64; /* W1 */
#endif
};

struct sq_mem_subdesc {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t    subdesc_type:4; /* W0 */
	uint64_t    mem_alg:4;
	uint64_t    mem_dsz:2;
	uint64_t    wmem:1;
	uint64_t    rsvd0:21;
	uint64_t    offset:32;

	uint64_t    rsvd1:15; /* W1 */
	uint64_t    addr:49;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t    offset:32;
	uint64_t    rsvd0:21;
	uint64_t    wmem:1;
	uint64_t    mem_dsz:2;
	uint64_t    mem_alg:4;
	uint64_t    subdesc_type:4; /* W0 */

	uint64_t    addr:49;
	uint64_t    rsvd1:15; /* W1 */
#endif
};

struct sq_hdr_subdesc {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t    subdesc_type:4;
	uint64_t    tso:1;
	uint64_t    post_cqe:1; /* Post CQE on no error also */
	uint64_t    dont_send:1;
	uint64_t    tstmp:1;
	uint64_t    subdesc_cnt:8;
	uint64_t    csum_l4:2;
	uint64_t    csum_l3:1;
	uint64_t    rsvd0:5;
	uint64_t    l4_offset:8;
	uint64_t    l3_offset:8;
	uint64_t    rsvd1:4;
	uint64_t    tot_len:20; /* W0 */

	uint64_t    tso_sdc_cont:8;
	uint64_t    tso_sdc_first:8;
	uint64_t    tso_l4_offset:8;
	uint64_t    tso_flags_last:12;
	uint64_t    tso_flags_first:12;
	uint64_t    rsvd2:2;
	uint64_t    tso_max_paysize:14; /* W1 */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t    tot_len:20;
	uint64_t    rsvd1:4;
	uint64_t    l3_offset:8;
	uint64_t    l4_offset:8;
	uint64_t    rsvd0:5;
	uint64_t    csum_l3:1;
	uint64_t    csum_l4:2;
	uint64_t    subdesc_cnt:8;
	uint64_t    tstmp:1;
	uint64_t    dont_send:1;
	uint64_t    post_cqe:1; /* Post CQE on no error also */
	uint64_t    tso:1;
	uint64_t    subdesc_type:4; /* W0 */

	uint64_t    tso_max_paysize:14;
	uint64_t    rsvd2:2;
	uint64_t    tso_flags_first:12;
	uint64_t    tso_flags_last:12;
	uint64_t    tso_l4_offset:8;
	uint64_t    tso_sdc_first:8;
	uint64_t    tso_sdc_cont:8; /* W1 */
#endif
};

/* Each sq entry is 16 bytes wide */
union sq_entry_t {
	uint64_t buff[2];
	struct sq_hdr_subdesc hdr;
	struct sq_imm_subdesc imm;
	struct sq_gather_subdesc gather;
	struct sq_crc_subdesc crc;
	struct sq_mem_subdesc mem;
};
_Static_assert(sizeof(union sq_entry_t) == 16, "SQ entry is 16 bytes");

/* Queue config register formats */
struct rq_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_2_63:62;
	uint64_t ena:1;
	uint64_t tcp_ena:1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t tcp_ena:1;
	uint64_t ena:1;
	uint64_t reserved_2_63:62;
#endif
	};
	uint64_t value;
};};

struct cq_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_43_63:21;
	uint64_t ena:1;
	uint64_t reset:1;
	uint64_t caching:1;
	uint64_t reserved_35_39:5;
	uint64_t qsize:3;
	uint64_t reserved_25_31:7;
	uint64_t avg_con:9;
	uint64_t reserved_0_15:16;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t reserved_0_15:16;
	uint64_t avg_con:9;
	uint64_t reserved_25_31:7;
	uint64_t qsize:3;
	uint64_t reserved_35_39:5;
	uint64_t caching:1;
	uint64_t reset:1;
	uint64_t ena:1;
	uint64_t reserved_43_63:21;
#endif
	};
	uint64_t value;
};};

struct sq_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_20_63:44;
	uint64_t ena:1;
	uint64_t reserved_18_18:1;
	uint64_t reset:1;
	uint64_t ldwb:1;
	uint64_t reserved_11_15:5;
	uint64_t qsize:3;
	uint64_t reserved_3_7:5;
	uint64_t tstmp_bgx_intf:3;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t tstmp_bgx_intf:3;
	uint64_t reserved_3_7:5;
	uint64_t qsize:3;
	uint64_t reserved_11_15:5;
	uint64_t ldwb:1;
	uint64_t reset:1;
	uint64_t reserved_18_18:1;
	uint64_t ena:1;
	uint64_t reserved_20_63:44;
#endif
	};
	uint64_t value;
};};

struct rbdr_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_45_63:19;
	uint64_t ena:1;
	uint64_t reset:1;
	uint64_t ldwb:1;
	uint64_t reserved_36_41:6;
	uint64_t qsize:4;
	uint64_t reserved_25_31:7;
	uint64_t avg_con:9;
	uint64_t reserved_12_15:4;
	uint64_t lines:12;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t lines:12;
	uint64_t reserved_12_15:4;
	uint64_t avg_con:9;
	uint64_t reserved_25_31:7;
	uint64_t qsize:4;
	uint64_t reserved_36_41:6;
	uint64_t ldwb:1;
	uint64_t reset:1;
	uint64_t ena: 1;
	uint64_t reserved_45_63:19;
#endif
	};
	uint64_t value;
};};

struct qs_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
	uint64_t reserved_32_63:32;
	uint64_t ena:1;
	uint64_t reserved_27_30:4;
	uint64_t sq_ins_ena:1;
	uint64_t sq_ins_pos:6;
	uint64_t lock_ena:1;
	uint64_t lock_viol_cqe_ena:1;
	uint64_t send_tstmp_ena:1;
	uint64_t be:1;
	uint64_t reserved_7_15:9;
	uint64_t vnic:7;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t vnic:7;
	uint64_t reserved_7_15:9;
	uint64_t be:1;
	uint64_t send_tstmp_ena:1;
	uint64_t lock_viol_cqe_ena:1;
	uint64_t lock_ena:1;
	uint64_t sq_ins_pos:6;
	uint64_t sq_ins_ena:1;
	uint64_t reserved_27_30:4;
	uint64_t ena:1;
	uint64_t reserved_32_63:32;
#endif
	};
	uint64_t value;
};};

struct drop_cfg { union { struct {
#if defined(__BIG_ENDIAN_BITFIELD)
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	uint64_t reserved1:8;
	uint64_t cq_drop:8;
	uint64_t cq_pass:8;
	uint64_t reserved2:8;
	uint64_t rbdr_drop:8;
	uint64_t rbdr_pass:8;
	uint64_t reserved3:14;
	uint64_t cq_red:1;
	uint64_t rbdr_red:1;
#endif
	};
	uint64_t value;
};};

#endif /* Q_STRUCT_H */
