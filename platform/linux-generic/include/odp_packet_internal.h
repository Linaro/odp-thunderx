/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_crypto_internal.h>
#ifdef HAVE_THUNDERX
#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_packet_io_internal.h>
#include <odp/api/plat/packet_types.h>
#include <thunder/nicvf/q_struct.h>
#endif

#define PACKET_JUMBO_LEN	(9 * 1024)

#ifdef HAVE_THUNDERX
typedef struct packet_hdr_t odp_packet_hdr_t;

/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint16_t all;

	struct {
		struct l2_flags_t {
			uint8_t		l2_pressent:1;
			uint8_t		l2_vlan_pressent:1;
			uint8_t		__reserved:6;
		}			l2_flags;
		uint8_t			l3_type:4;
		uint8_t			l4_type:4;
	};
} nic_input_flags_t;

/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint64_t all;

	struct {
		uint64_t parsed_all:1;/**< Parsing complete */
		uint64_t dst_queue:1; /**< Dst queue present */

		uint64_t flow_hash:1; /**< Flow hash present */
		uint64_t timestamp:1; /**< Timestamp present */

		uint64_t eth_bcast:1; /**< Ethernet broadcast */
		uint64_t eth_mcast:1; /**< Ethernet multicast */
		uint64_t jumbo:1;     /**< Jumbo frame */
		uint64_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint64_t snap:1;      /**< SNAP */
		uint64_t arp:1;       /**< ARP */

		uint64_t ip_bcast:1;  /**< IP broadcast */
		uint64_t ip_mcast:1;  /**< IP multicast */
		uint64_t ipsec_ah:1;  /**< IPSec authentication header */
		uint64_t ipsec_esp:1; /**< IPSec encapsulating security
					   payload */
		uint64_t tcpopt:1;    /**< TCP options present */
		uint64_t icmp:1;      /**< ICMP */

		uint64_t color:2;     /**< Packet color for traffic mgmt */
		uint64_t nodrop:1;    /**< Drop eligibility status */

		int8_t shaper_len_adj;    /**< adjustment for traffic mgr */
	};
} input_flags_t;

ODP_STATIC_ASSERT(sizeof(input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

enum l3_type_t {
	NIC_L3TYPE_NONE		= 0x00,
	NIC_L3TYPE_GRH		= 0x01,
	NIC_L3TYPE_IPV4		= 0x04,
	NIC_L3TYPE_IPV4_OPTIONS = 0x05,
	NIC_L3TYPE_IPV6		= 0x06,
	NIC_L3TYPE_IPV6_OPTIONS = 0x07,
	NIC_L3TYPE_ET_STOP	= 0x0D,
	NIC_L3TYPE_OTHER	= 0x0E,
};

#define NIC_L3TYPE_OPTIONS_MASK		((uint8_t)1)
#define NIC_L3TYPE_IPVX_MASK		((uint8_t)0x06)

enum l4_type_t {
	NIC_L4TYPE_NONE		= 0x00,
	NIC_L4TYPE_IPSEC_ESP	= 0x01,
	NIC_L4TYPE_IPFRAG	= 0x02,
	NIC_L4TYPE_IPCOMP	= 0x03,
	NIC_L4TYPE_TCP		= 0x04,
	NIC_L4TYPE_UDP		= 0x05,
	NIC_L4TYPE_SCTP		= 0x06,
	NIC_L4TYPE_GRE		= 0x07,
	NIC_L4TYPE_ROCE_BTH	= 0x08,
	NIC_L4TYPE_OTHER	= 0x0E,
};

ODP_STATIC_ASSERT(sizeof(nic_input_flags_t) == sizeof(uint16_t),
		   "INPUT_FLAGS_SIZE_ERROR");
#else
/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint64_t all;

	struct {
		uint64_t parsed_l2:1; /**< L2 parsed */
		uint64_t parsed_all:1;/**< Parsing complete */
		uint64_t dst_queue:1; /**< Dst queue present */

		uint64_t flow_hash:1; /**< Flow hash present */
		uint64_t timestamp:1; /**< Timestamp present */

		uint64_t l2:1;        /**< known L2 protocol present */
		uint64_t l3:1;        /**< known L3 protocol present */
		uint64_t l4:1;        /**< known L4 protocol present */

		uint64_t eth:1;       /**< Ethernet */
		uint64_t eth_bcast:1; /**< Ethernet broadcast */
		uint64_t eth_mcast:1; /**< Ethernet multicast */
		uint64_t jumbo:1;     /**< Jumbo frame */
		uint64_t vlan:1;      /**< VLAN hdr found */
		uint64_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint64_t snap:1;      /**< SNAP */
		uint64_t arp:1;       /**< ARP */

		uint64_t ipv4:1;      /**< IPv4 */
		uint64_t ipv6:1;      /**< IPv6 */
		uint64_t ip_bcast:1;  /**< IP broadcast */
		uint64_t ip_mcast:1;  /**< IP multicast */
		uint64_t ipfrag:1;    /**< IP fragment */
		uint64_t ipopt:1;     /**< IP optional headers */

		uint64_t ipsec:1;     /**< IPSec packet. Required by the
					   odp_packet_has_ipsec_set() func. */
		uint64_t ipsec_ah:1;  /**< IPSec authentication header */
		uint64_t ipsec_esp:1; /**< IPSec encapsulating security
					   payload */
		uint64_t udp:1;       /**< UDP */
		uint64_t tcp:1;       /**< TCP */
		uint64_t tcpopt:1;    /**< TCP options present */
		uint64_t sctp:1;      /**< SCTP */
		uint64_t icmp:1;      /**< ICMP */

		uint64_t color:2;     /**< Packet color for traffic mgmt */
		uint64_t nodrop:1;    /**< Drop eligibility status */
	};
} input_flags_t;

ODP_STATIC_ASSERT(sizeof(input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");
#endif

#ifdef HAVE_THUNDERX
/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint8_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint8_t app_error:1; /**< Error bit for application use */
		uint8_t frame_len:1; /**< Frame length error */
		uint8_t snap_len:1;  /**< Snap length error */
		uint8_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint8_t ip_err:1;    /**< IP error,  checks TBD */
		uint8_t tcp_err:1;   /**< TCP error, checks TBD */
		uint8_t udp_err:1;   /**< UDP error, checks TBD */
		uint8_t l1_err:1;   /**< L1/MAC error */
	};
} nic_error_flags_t;

ODP_STATIC_ASSERT(sizeof(nic_error_flags_t) == sizeof(uint8_t),
		   "ERROR_FLAGS_SIZE_ERROR");

#else
/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t app_error:1; /**< Error bit for application use */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t snap_len:1;  /**< Snap length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
	};
} error_flags_t;

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		  "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each output option */
		uint32_t l3_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l3_chksum:1;     /**< L3 chksum override */
		uint32_t l4_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l4_chksum:1;     /**< L4 chksum override  */

		int8_t shaper_len_adj;    /**< adjustment for traffic mgr */
	};
} output_flags_t;

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		  "OUTPUT_FLAGS_SIZE_ERROR");

#endif

#ifdef HAVE_THUNDERX
/**
 * User context held in packet
 */
typedef union {
	void*		ptr;
	const void*	const_ptr;
	uint64_t	val;
} user_ctx_t;

ODP_STATIC_ASSERT(sizeof(user_ctx_t) == sizeof(uint64_t),
		   "OUTPUT_FLAGS_SIZE_ERROR");

struct pkt_hw_fields_t {
	nic_input_flags_t	input_flags; /* uint16_t */
	nic_error_flags_t	error_flags; /* uint8_t */
	uint8_t		l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */
	uint8_t		l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint8_t		l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
} hw; /* keeped together as taken from HW */

/**
 * Internal Packet header
 * Packet is extension of buffer. It knows how many data is stored in
 * underlaying buffer and where what are the packet layer offsets.
 * When trawersing throung packet segments it only operates on used space
 * (oposite to buffer which does not know anything about payload).
 */
struct packet_hdr_t {
	struct odp_buffer_hdr_t buf_hdr;
	struct packet_hdr_t     *last;
	struct {
		uint64_t        total_len:14;
		uint64_t        segment_len:14;
		uint64_t        rss_alg:4;
		uint64_t        rss_tag:32;
	};
	struct pkt_hw_fields_t  hw;
	uint16_t                segment_offset;
	user_ctx_t              user_ctx;
	odp_pktio_t             input;
	input_flags_t		input_flags;
	odp_queue_t dst_queue;   /**< Classifier destination queue */
	odp_time_t timestamp;    /**< Timestamp value */
	odp_crypto_generic_op_result_t op_result;  /**< Result for crypto */
} ODP_ALIGNED_CACHE;

ODP_STATIC_ASSERT(sizeof(struct packet_hdr_t) % sizeof(uint64_t) == 0,
		   "ODP_PACKET_HDR_T__SIZE_ERR2");
#else
/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/* Following members are initialized by packet_init() */
	input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	uint32_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint32_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint32_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */

	uint32_t frame_len;
	uint32_t headroom;
	uint32_t tailroom;

	odp_pktio_t input;

	/* Members below are not initialized by packet_init() */
	uint32_t l3_len;         /**< Layer 3 length */
	uint32_t l4_len;         /**< Layer 4 length */

	odp_queue_t dst_queue;   /**< Classifier destination queue */

	uint32_t flow_hash;      /**< Flow hash value */
	odp_time_t timestamp;    /**< Timestamp value */

	odp_crypto_generic_op_result_t op_result;  /**< Result for crypto */
} odp_packet_hdr_t;

typedef struct odp_packet_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t))];
} odp_packet_hdr_stride;
#endif /* !HAVE_THUNDERX */

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

static inline void copy_packet_parser_metadata(odp_packet_hdr_t *src_hdr,
					       odp_packet_hdr_t *dst_hdr)
{
#ifdef HAVE_THUNDERX
	dst_hdr->hw.input_flags    = src_hdr->hw.input_flags;
	dst_hdr->hw.error_flags    = src_hdr->hw.error_flags;

	dst_hdr->hw.l2_offset      = src_hdr->hw.l2_offset;
	dst_hdr->hw.l3_offset      = src_hdr->hw.l3_offset;
	dst_hdr->hw.l4_offset      = src_hdr->hw.l4_offset;

	dst_hdr->rss_tag	   = src_hdr->rss_tag;
	dst_hdr->rss_alg	   = src_hdr->rss_alg;

	dst_hdr->user_ctx	   = src_hdr->user_ctx;

	dst_hdr->input_flags    = src_hdr->input_flags;
	dst_hdr->dst_queue      = src_hdr->dst_queue;
#else
	dst_hdr->input_flags    = src_hdr->input_flags;
	dst_hdr->error_flags    = src_hdr->error_flags;
	dst_hdr->output_flags   = src_hdr->output_flags;

	dst_hdr->l2_offset      = src_hdr->l2_offset;
	dst_hdr->l3_offset      = src_hdr->l3_offset;
	dst_hdr->l4_offset      = src_hdr->l4_offset;

	dst_hdr->l3_len         = src_hdr->l3_len;
	dst_hdr->l4_len         = src_hdr->l4_len;

	dst_hdr->dst_queue      = src_hdr->dst_queue;
#endif
}

/*
 * ODP ThunderX provides it's own packet implementation
 * so we can disable some generic inlines.
 */
#ifndef HAVE_THUNDERX
static inline void *packet_map(odp_packet_hdr_t *pkt_hdr,
			       uint32_t offset, uint32_t *seglen)
{
	if (offset > pkt_hdr->frame_len)
		return NULL;

	return buffer_map(&pkt_hdr->buf_hdr,
			  pkt_hdr->headroom + offset, seglen,
			  pkt_hdr->headroom + pkt_hdr->frame_len);
}

static inline void push_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  -= len;
	pkt_hdr->frame_len += len;
}

static inline void pull_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  += len;
	pkt_hdr->frame_len -= len;
}

static inline int push_head_seg(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	uint32_t extrasegs =
		(len - pkt_hdr->headroom + pkt_hdr->buf_hdr.segsize - 1) /
		pkt_hdr->buf_hdr.segsize;

	if (pkt_hdr->buf_hdr.segcount + extrasegs > ODP_BUFFER_MAX_SEG ||
	    seg_alloc_head(&pkt_hdr->buf_hdr, extrasegs))
		return -1;

	pkt_hdr->headroom += extrasegs * pkt_hdr->buf_hdr.segsize;
	return 0;
}

static inline void pull_head_seg(odp_packet_hdr_t *pkt_hdr)
{
	uint32_t extrasegs = (pkt_hdr->headroom - 1) / pkt_hdr->buf_hdr.segsize;

	seg_free_head(&pkt_hdr->buf_hdr, extrasegs);
	pkt_hdr->headroom -= extrasegs * pkt_hdr->buf_hdr.segsize;
}

static inline void push_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  -= len;
	pkt_hdr->frame_len += len;
}

static inline int push_tail_seg(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	uint32_t extrasegs =
		(len - pkt_hdr->tailroom + pkt_hdr->buf_hdr.segsize - 1) /
		pkt_hdr->buf_hdr.segsize;

	if (pkt_hdr->buf_hdr.segcount + extrasegs > ODP_BUFFER_MAX_SEG ||
	    seg_alloc_tail(&pkt_hdr->buf_hdr, extrasegs))
		return -1;

	pkt_hdr->tailroom += extrasegs * pkt_hdr->buf_hdr.segsize;
	return 0;
}

static inline void pull_tail_seg(odp_packet_hdr_t *pkt_hdr)
{
	uint32_t extrasegs = pkt_hdr->tailroom / pkt_hdr->buf_hdr.segsize;

	seg_free_tail(&pkt_hdr->buf_hdr, extrasegs);
	pkt_hdr->tailroom -= extrasegs * pkt_hdr->buf_hdr.segsize;
}

static inline void pull_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
}
#endif /* !HAVE_THUNDERX */

static inline uint32_t packet_len(odp_packet_hdr_t *pkt_hdr)
{
#ifdef HAVE_THUNDERX
	return pkt_hdr->total_len;
#else
	return pkt_hdr->frame_len;
#endif
}

#ifndef HAVE_THUNDERX
static inline void packet_set_len(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->frame_len = len;
}
#endif /* !HAVE_THUNDERX */

static inline int packet_parse_l2_not_done(odp_packet_hdr_t *pkt_hdr)
{
#ifdef HAVE_THUNDERX
	return !pkt_hdr->hw.input_flags.l2_flags.l2_pressent;
#else
	return !pkt_hdr->input_flags.parsed_l2;
#endif
}

static inline int packet_parse_not_complete(odp_packet_hdr_t *pkt_hdr)
{
	return !pkt_hdr->input_flags.parsed_all;
}

/* Forward declarations */
void _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

/* TODO: fix conflicting names */
#ifndef HAVE_THUNDERX
odp_packet_t packet_alloc(odp_pool_t pool_hdl, uint32_t len, int parse);
#endif

/* Fill in parser metadata for L2 */
void packet_parse_l2(odp_packet_hdr_t *pkt_hdr);

/* Perform full packet parse */
int packet_parse_full(odp_packet_hdr_t *pkt_hdr);

/* Reset parser metadata for a new parse */
void packet_parse_reset(odp_packet_hdr_t *pkt_hdr);

#ifndef HAVE_THUNDERX /* following are inline for thunder */
/* Convert a packet handle to a buffer handle */
odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt);

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf);
#else
static inline odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

static inline odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

static inline uint8_t * packet_ptr(struct packet_hdr_t *pkt, uint32_t *len)
{
	if (len)
		*len = pkt->segment_len;
	return (uint8_t *)pkt->buf_hdr.data + pkt->segment_offset;
}
#endif

/*
 * ODP ThunderX provides it's own packet implementation
 * so we can disable some generic inlines.
 */
static inline int packet_hdr_has_l2(odp_packet_hdr_t *pkt_hdr)
{
#ifdef HAVE_THUNDERX
	return pkt_hdr->hw.input_flags.l2_flags.l2_pressent;
#else
	return pkt_hdr->input_flags.l2;
#endif /* HAVE_THUNDERX */
}

static inline void packet_hdr_has_l2_set(odp_packet_hdr_t *pkt_hdr, int val)
{
#ifdef HAVE_THUNDERX
	pkt_hdr->hw.input_flags.l2_flags.l2_pressent = val;
#else
	pkt_hdr->input_flags.l2 = val;
#endif /* HAVE_THUNDERX */
}

/* additionaly ThunderX implementation use following inline function */
#ifdef HAVE_THUNDERX
static inline int packet_hdr_has_l2_error(struct packet_hdr_t * pkt)
{
	return pkt->hw.error_flags.frame_len
		| pkt->hw.error_flags.snap_len
		| pkt->hw.error_flags.l2_chksum;
}

static inline int packet_hdr_has_l3(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l3_type != NIC_L3TYPE_NONE;
}

static inline int packet_hdr_has_l3_error(struct packet_hdr_t * pkt)
{
	return pkt->hw.error_flags.ip_err;
}

static inline int packet_hdr_has_l4(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l4_type != NIC_L4TYPE_NONE;
}

static inline int packet_hdr_has_l4_error(struct packet_hdr_t * pkt)
{
	return pkt->hw.error_flags.tcp_err | pkt->hw.error_flags.udp_err;
}

static inline uint8_t packet_l2_offset(struct packet_hdr_t *pkt)
{
	return pkt->hw.l2_offset;
}

static inline size_t packet_l2_len(struct packet_hdr_t *pkt)
{
	return pkt->total_len - pkt->hw.l2_offset;
}

static inline uint8_t packet_l3_offset(struct packet_hdr_t *pkt)
{
	return pkt->hw.l3_offset;
}

static inline size_t packet_l3_len(struct packet_hdr_t *pkt)
{
	return pkt->total_len - pkt->hw.l3_offset;
}

static inline uint8_t packet_l4_offset(struct packet_hdr_t *pkt)
{
	return pkt->hw.l4_offset;
}

static inline size_t packet_l4_len(struct packet_hdr_t *pkt)
{
	return pkt->total_len - pkt->hw.l4_offset;
}

static inline int packet_hdr_has_error(struct packet_hdr_t * pkt)
{
	return (pkt->hw.error_flags.all != 0);
}

/* Get Error Flags */
#if 0
static inline int odp_packet_errflag_frame_len(struct packet_hdr_t * pkt)
{
	return pkt->hw.error_flags.frame_len;
}
#endif
#endif /* HAVE_THUNDERX */

static inline int packet_hdr_has_eth(odp_packet_hdr_t *pkt_hdr)
{
#ifdef HAVE_THUNDERX
	return pkt_hdr->hw.input_flags.l2_flags.l2_pressent;
#else
	return pkt_hdr->input_flags.eth;
#endif /* HAVE_THUNDERX */
}

/* additionaly ThunderX implementation use following inline function */
#ifdef HAVE_THUNDERX
static inline int packet_hdr_has_eth_bcast(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.eth_bcast;
}

static inline int packet_hdr_has_eth_mcast(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.eth_mcast;
}

static inline int packet_hdr_has_jumbo(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.jumbo;
}

static inline int packet_hdr_has_vlan(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l2_flags.l2_vlan_pressent;
}

static inline int packet_hdr_has_vlan_qinq(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.vlan_qinq;
}

static inline int packet_hdr_has_arp(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.arp;
}

static inline int packet_hdr_has_ipv4(struct packet_hdr_t * pkt)
{
	/* return 1 in case of NIC_L3TYPE_IPV4 or NIC_L3TYPE_IPV4_OPTIONS */
	return (pkt->hw.input_flags.l3_type & (~NIC_L3TYPE_OPTIONS_MASK)) == NIC_L3TYPE_IPV4;
}

static inline int packet_hdr_has_ipv6(struct packet_hdr_t * pkt)
{
	/* return 1 in case of NIC_L3TYPE_IPV6 or NIC_L3TYPE_IPV6_OPTIONS */
	return (pkt->hw.input_flags.l3_type & (~NIC_L3TYPE_OPTIONS_MASK)) == NIC_L3TYPE_IPV6;
}

static inline int packet_hdr_has_ip_bcast(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.ip_bcast;
}

static inline int packet_hdr_has_ip_mcast(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.ip_mcast;
}

static inline int packet_hdr_has_ipfrag(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l4_type == NIC_L4TYPE_IPFRAG;
}

static inline int packet_hdr_has_ipopt(struct packet_hdr_t * pkt)
{
	/* return 1 in case of NIC_L3TYPE_IPV4_OPTIONS or NIC_L3TYPE_IPV6_OPTIONS */
	return (pkt->hw.input_flags.l3_type & NIC_L3TYPE_OPTIONS_MASK) ? 1 : 0;
}

static inline int packet_hdr_has_ipsec_ah(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.ipsec_ah;
}

static inline int packet_hdr_has_ipsec_esp(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.ipsec_esp;
}

static inline int packet_hdr_has_ipsec(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l4_type == NIC_L4TYPE_IPSEC_ESP;
}

static inline int packet_hdr_has_udp(struct packet_hdr_t * pkt ODP_UNUSED)
{
	return pkt->hw.input_flags.l4_type == NIC_L4TYPE_UDP;
}

static inline int packet_hdr_has_tcp(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l4_type == NIC_L4TYPE_TCP;
}

static inline int packet_hdr_has_sctp(struct packet_hdr_t * pkt)
{
	return pkt->hw.input_flags.l4_type == NIC_L4TYPE_SCTP;
}

static inline int packet_hdr_has_icmp(struct packet_hdr_t * pkt)
{
	return pkt->input_flags.icmp;
}

static inline int packet_hdr_has_flow_hash(struct packet_hdr_t *pkt)
{
	return pkt->rss_alg == RSS_ALG_NONE ? 0 : 1;
}

static inline void packet_hdr_has_flow_hash_clr(struct packet_hdr_t *pkt)
{
	pkt->rss_tag = 0xffffffff;
	pkt->rss_alg = RSS_ALG_NONE;
}

static inline uint32_t packet_flow_hash(struct packet_hdr_t *pkt)
{
	if (!packet_hdr_has_flow_hash(pkt))
		return 0;

	return pkt->rss_tag;
}

static inline void packet_flow_hash_set(struct packet_hdr_t *pkt, uint32_t flow_hash)
{
	pkt->rss_tag = flow_hash;
	pkt->rss_alg = RSS_ALG_TCP_IP; /* /TODO OTHER: not the best choice */
}

static inline int packet_hdr_has_ts(struct packet_hdr_t *pkt)
{
	return pkt->input_flags.timestamp;
}

static inline void packet_hdr_has_ts_set(struct packet_hdr_t *pkt, int val)
{
	pkt->input_flags.timestamp = val;
}

static inline int packet_hdr_color(struct packet_hdr_t *pkt)
{
	return pkt->input_flags.color;
}

static inline void packet_hdr_color_set(struct packet_hdr_t *pkt, int color)
{
	if (packet_parse_not_complete(pkt))
		packet_parse_full(pkt);

	pkt->input_flags.color = color;
}

static inline int packet_hdr_drop_eligible(struct packet_hdr_t *pkt)
{
	if (packet_parse_not_complete(pkt))
		packet_parse_full(pkt);

	return !pkt->input_flags.nodrop;
}

static inline void packet_hdr_drop_eligible_set(struct packet_hdr_t *pkt, int drop)
{
	pkt->input_flags.nodrop = !drop;
}

static inline int packet_hdr_shaper_len_adjust(struct packet_hdr_t *pkt)
{
	return pkt->input_flags.shaper_len_adj;
}

static inline void packet_hdr_shaper_len_adjust_set(struct packet_hdr_t *pkt, int adj)
{
	if (packet_parse_not_complete(pkt))
		packet_parse_full(pkt);

	pkt->input_flags.shaper_len_adj = adj;
}

/* Set Input Flags */

static inline void packet_hdr_has_l3_set(struct packet_hdr_t * pkt, int val)
{
	if (val) {
		/* do not modify the l3_type only set it to unknown if not
		 * already set */
		if (pkt->hw.input_flags.l3_type == NIC_L3TYPE_NONE) {
			pkt->hw.input_flags.l3_type = NIC_L3TYPE_OTHER;
		}
	} else {
		pkt->hw.input_flags.l3_type = NIC_L3TYPE_NONE;
	}
}

static inline void packet_hdr_has_l4_set(struct packet_hdr_t * pkt, int val)
{
	if (val) {
		/* do not modify the l3_type only set it to unknown if not
		 * already set */
		if (pkt->hw.input_flags.l4_type == NIC_L4TYPE_NONE) {
			pkt->hw.input_flags.l4_type = NIC_L4TYPE_OTHER;
		}
	} else {
		pkt->hw.input_flags.l4_type = NIC_L4TYPE_NONE;
	}
}

static inline void packet_hdr_has_eth_set(struct packet_hdr_t * pkt, int val)
{
	/* eth is same as l2 */
	pkt->hw.input_flags.l2_flags.l2_pressent = val;
}

static inline void packet_hdr_has_eth_bcast_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.eth_bcast = val;
}

static inline void packet_hdr_has_eth_mcast_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.eth_mcast = val;
}

static inline void packet_hdr_has_jumbo_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.jumbo = val;
}

static inline void packet_hdr_has_vlan_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l2_flags.l2_vlan_pressent = val;
}

static inline void packet_hdr_has_vlan_qinq_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.vlan_qinq = val;
}

static inline void packet_hdr_has_arp_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.arp = val;
}

static inline void packet_hdr_has_ipv4_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l3_type = val ? NIC_L3TYPE_IPV4 : NIC_L3TYPE_NONE;
}

static inline void packet_hdr_has_ipv6_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l3_type = val ? NIC_L3TYPE_IPV6 : NIC_L3TYPE_NONE;
}

static inline void packet_hdr_has_ip_bcast_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.ip_bcast = val;
}

static inline void packet_hdr_has_ip_mcast_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.ip_mcast = val;
}

static inline void packet_hdr_has_ipfrag_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l4_type = val ? NIC_L4TYPE_IPFRAG : NIC_L4TYPE_NONE;
}

static inline void packet_hdr_has_ipopt_set(struct packet_hdr_t * pkt, int val)
{
	/* the IPVx_OPTIONS may be set only in case of IPV4 and IPV6 */
	if (pkt->hw.input_flags.l3_type & NIC_L3TYPE_IPVX_MASK) {
		/* force the IPVx_OPTIONS bit */
		pkt->hw.input_flags.l3_type =
			(pkt->hw.input_flags.l3_type & (~NIC_L3TYPE_OPTIONS_MASK)) |
			(val ? NIC_L3TYPE_OPTIONS_MASK : 0);
	}
}

static inline void packet_hdr_has_ipsec_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l4_type = val ? NIC_L4TYPE_IPSEC_ESP : NIC_L4TYPE_NONE;
}

static inline void packet_hdr_has_udp_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l4_type = val ? NIC_L4TYPE_UDP : NIC_L4TYPE_NONE;
}

static inline void packet_hdr_has_tcp_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l4_type = val ? NIC_L4TYPE_TCP : NIC_L4TYPE_NONE;
}

static inline void packet_hdr_has_sctp_set(struct packet_hdr_t * pkt, int val)
{
	pkt->hw.input_flags.l4_type = val ? NIC_L4TYPE_SCTP : NIC_L4TYPE_NONE;
}

static inline void packet_hdr_has_icmp_set(struct packet_hdr_t * pkt, int val)
{
	pkt->input_flags.icmp = val;
}
#endif /* HAVE_THUNDERX */

static inline void packet_set_ts(odp_packet_hdr_t *pkt_hdr, odp_time_t *ts)
{
	if (ts != NULL) {
		pkt_hdr->timestamp = *ts;
#ifdef HAVE_THUNDERX
		packet_hdr_has_ts_set(pkt_hdr, 1);
#else
		pkt_hdr->input_flags.timestamp = 1;
#endif
	}
}

int _odp_parse_common(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

#ifdef __cplusplus
}
#endif

#endif
