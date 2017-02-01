/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_THUNDERX
#define ODP_CONFIG_POOL_CACHE_SIZE 4096
#define ODP_CONFIG_POOL_FLUSH_SIZE (ODP_CONFIG_POOL_CACHE_SIZE * 3 / 2)

/*
 * Maximum number of threads
 */
#define ODP_CONFIG_MAX_THREADS  128
#endif /* HAVE_THUNDERX */

/*
 * Maximum number of pools
 */
#define ODP_CONFIG_POOLS 16

#ifdef HAVE_THUNDERX
/*
 * Gather statistics in pool
 * For debugging purposes.
 */
#define ODP_CONFIG_POOL_STATS 0

/*
 * Maximum number of interfaces. Single interface may be used for creating
 * multiple packet IO's
 */
#define ODP_CONFIG_INTERFACES_ENTRIES 8
#endif /* HAVE_THUNDERX */

/*
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES 1024

/*
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/*
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#ifdef HAVE_THUNDERX
#define ODP_CONFIG_BUFFER_ALIGN_MIN 128
#else
#define ODP_CONFIG_BUFFER_ALIGN_MIN 16
#endif

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In odp-linux implementation:
 * The default value (66) allows a 1500-byte packet to be received into a single
 * segment with Ethernet offset alignment and room for some header expansion.
 *
 * Warning: For ThunderX we must use headroom alligned with 128B because of HW
 * constrains. This is due buffer start address need to be 128B aligned for
 * proper RX and TX operations.
 */
#ifdef HAVE_THUNDERX
#define ODP_CONFIG_PACKET_HEADROOM 128
#else
#define ODP_CONFIG_PACKET_HEADROOM 66
#endif

/*
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define ODP_CONFIG_PACKET_TAILROOM 0

/*
 * Maximum number of segments per packet
 */
#define ODP_CONFIG_PACKET_MAX_SEGS 6

/*
 * Minimum packet segment length
 *
 * This defines the minimum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) will be rounded up into
 * this value.
 */
#ifdef HAVE_THUNDERX
#define ODP_CONFIG_PACKET_SEG_LEN_MIN 1664
#else
#define ODP_CONFIG_PACKET_SEG_LEN_MIN 1598
#endif

/*
 * Maximum packet segment length
 *
 * This defines the maximum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) must not be larger than
 * this.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MAX (64 * 1024)

/*
 * Maximum packet buffer length
 *
 * This defines the maximum number of bytes that can be stored into a packet
 * (maximum return value of odp_packet_buf_len(void)). Attempts to allocate
 * (including default head- and tailrooms) or extend packets to sizes larger
 * than this limit will fail.
 *
 * @internal In odp-linux implementation:
 * - The value MUST be an integral number of segments
 * - The value SHOULD be large enough to accommodate jumbo packets (9K)
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MAX (ODP_CONFIG_PACKET_SEG_LEN_MIN * 6)

/* Maximum number of shared memory blocks.
 *
 * This the the number of separate SHM areas that can be reserved concurrently
 */
#define ODP_CONFIG_SHM_BLOCKS (ODP_CONFIG_POOLS + 48)

#ifdef __cplusplus
}
#endif

#endif
