/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_generator.c ODP loopback demo application
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#include <example_debug.h>

#include <odp.h>

#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/icmp.h>

#define MAX_WORKERS            32		/**< max number of works */
/**< pkt pool size */
#define POOL_SIZE_GLOBAL      16384 * 6

#define POOL_SIZE_THREAD      2000

#define SHM_PKT_POOL_BUF_SIZE  1856		/**< pkt pool buf size */
#define MAX_PKTIO		8

#define MAX_PKT_BURST          128

/** print appl mode */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define APPL_MODE_SND 1
#define APPL_MODE_RCV 2

/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;		/**< system CPU count */
	unsigned if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	odp_pool_t pool;	/**< Pool for packet IO */
	odp_pktio_t pktio[MAX_PKTIO]; /**< Array of open pktio */
	odp_pktout_queue_t pktout[MAX_PKTIO * MAX_WORKERS];
	odp_pktin_queue_t pktin[MAX_PKTIO * MAX_WORKERS];
	odph_ethaddr_t srcmac;	/**< src mac addr */
	odph_ethaddr_t dstmac;	/**< dest mac addr */
	uint32_t srcip;	/**< src ip addr */
	uint32_t dstip;	/**< dest ip addr */
	int mode;		/**< work mode */
	int number;		/**< packets number to be sent */
	int payload;		/**< data len */
	int timeout;		/**< wait time */
	int interval;		/**< wait interval ms between sending
				     each packet */
} appl_args_t;

/**
 * counters
*/
static struct {
	odp_atomic_u64_t seq;	/**< ip seq to be send */
	odp_atomic_u64_t ip;	/**< ip packets */
	odp_atomic_u64_t udp;	/**< udp packets */
	odp_atomic_u64_t icmp;	/**< icmp packets */
} counters;

/** * Thread specific arguments
 */
typedef struct {
	odp_pktout_queue_t pktout; /**< Pktout to use by worker */
	odp_pktin_queue_t  pktin;  /**< Pktin to use by worker */
	odp_pool_t pool;	/**< Pool for packet IO */
	int mode;		/**< Thread mode */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

struct stat {
	volatile uint64_t tx;
	volatile uint64_t rx;
	volatile uint64_t txe;
	volatile uint64_t rxe;
	volatile uint64_t rxd;
	volatile uint64_t pad[16-5];
};

_Static_assert(sizeof(struct stat) == 128, "struct stat must fill a cache line");

struct stat stat[MAX_WORKERS] __attribute__((aligned(128)));

struct stat stat0[MAX_WORKERS];
struct stat stat1[MAX_WORKERS];

/** Global pointer to args */
static args_t *args;

/** GLobal worker flag */
static bool glob_work = true;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int scan_ip(char *buf, unsigned int *paddr);
static int scan_mac(char *in, odph_ethaddr_t *des);

/* Signal handler function which abort workers */
static void sig_func(int signum, siginfo_t *siginfo,
		     void *ucontext)
{
	signum = signum;
	siginfo = siginfo;
	ucontext = ucontext;

	printf("Signal handler ... exiting\n");
	glob_work = false;
}

/**
 * Scan ip
 * Parse ip address.
 *
 * @param buf ip address string xxx.xxx.xxx.xx
 * @param paddr ip address for odp_packet
 * @return 1 success, 0 failed
*/
static int scan_ip(char *buf, unsigned int *paddr)
{
	int part1, part2, part3, part4;
	char tail = 0;
	int field;

	if (buf == NULL)
		return 0;

	field = sscanf(buf, "%d . %d . %d . %d %c",
		       &part1, &part2, &part3, &part4, &tail);

	if (field < 4 || field > 5) {
		printf("expect 4 field,get %d/n", field);
		return 0;
	}

	if (tail != 0) {
		printf("ip address mixed with non number/n");
		return 0;
	}

	if ((part1 >= 0 && part1 <= 255) && (part2 >= 0 && part2 <= 255) &&
	    (part3 >= 0 && part3 <= 255) && (part4 >= 0 && part4 <= 255)) {
		if (paddr)
			*paddr = part1 << 24 | part2 << 16 | part3 << 8 | part4;
		return 1;
	} else {
		printf("not good ip %d:%d:%d:%d/n", part1, part2, part3, part4);
	}

	return 0;
}

/**
 * Scan mac addr form string
 *
 * @param  in mac string
 * @param  des mac for odp_packet
 * @return 1 success, 0 failed
 */
static int scan_mac(char *in, odph_ethaddr_t *des)
{
	int field;
	int i;
	unsigned int mac[7];

	field = sscanf(in, "%2x:%2x:%2x:%2x:%2x:%2x",
		       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	for (i = 0; i < 6; i++)
		des->addr[i] = mac[i];

	if (field != 6)
		return 0;
	return 1;
}

/**
 * set up an udp packet
 *
 * @param pool Buffer pool to create packet in
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t pack_udp_pkt(odp_pool_t pool, uint32_t ip_off)
{
	odp_packet_t pkt;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	unsigned short seq;

	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = odp_packet_data(pkt);

	/* ether */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	/* ip */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip + ip_off);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	printf("IP: %x %x\n", ip->src_addr, ip->dst_addr);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_UDP;
	seq = odp_atomic_fetch_add_u64(&counters.seq, 1) % 0xFFFF;
	ip->id = odp_cpu_to_be_16(seq);
	ip->ttl = 64;
	ip->chksum = 0;
	/* udp */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = 0x1234;
	udp->dst_port = 0x5678;
	udp->length = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN);
	udp->chksum = 0;

	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_has_udp_set(pkt, 1);

	return pkt;
}

/**
 * Create a pktio object
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 *
 * @return The handle of the created pktio object.
 * @warning This routine aborts if the create is unsuccessful.
 */
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktio_config_t pktio_config;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode  = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);

	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", dev);

	odp_pktio_config_init(&pktio_config);
	pktio_config.pktout.bit.ipv4_chksum = true;
	pktio_config.pktout.bit.udp_chksum = true;
	pktio_config.pktout.bit.tcp_chksum = true;
	pktio_config.pktout.bit.tx_no_recl_buff = true;
	if (odp_pktio_config(pktio, &pktio_config))
		EXAMPLE_ABORT("Error: pktio config failed for %s\n", dev);

	printf("  created pktio:%02" PRIu64
	       ", dev:%s,\n",
	       odp_pktio_to_u64(pktio), dev);

	return pktio;
}

/**
 * Close pktio handle
 */
static int close_pktio(odp_pktio_t pktio)
{
	int ret = 0;

	ret = odp_pktio_stop(pktio);
	if (ret)
		EXAMPLE_ERR("Error: cannot stop pktio\n");

	ret = odp_pktio_close(pktio);
	if (ret)
		EXAMPLE_ERR("Error: error while closing pktio\n");

	return ret;
}

static int create_pktout_queues(odp_pktio_t pktio,
				odp_pktout_queue_t pktout[],
				size_t cnt)
{
	odp_pktout_queue_param_t queue_params;
	int ret_cnt;

	odp_pktout_queue_param_init(&queue_params);
	queue_params.op_mode = ODP_PKTIO_OP_MT; /* Multithread safe */
	queue_params.num_queues = cnt;

	if (odp_pktout_queue_config(pktio, &queue_params))
		EXAMPLE_ABORT("Error: cannot configure pktout queues");

	ret_cnt = odp_pktout_queue(pktio, pktout, cnt);
	if ((size_t)ret_cnt != cnt)
		EXAMPLE_ABORT("Error: cannot get the pktout queues");

	return 0;
}

static int create_pktin_queues(odp_pktio_t pktio,
			       odp_pktin_queue_t pktin[],
			       size_t cnt)
{
	odp_pktin_queue_param_t queue_params;
	int ret_cnt;

	odp_pktin_queue_param_init(&queue_params);
	queue_params.op_mode = ODP_PKTIO_OP_MT; /* Multithread safe */
	queue_params.num_queues = cnt;

	if (odp_pktin_queue_config(pktio, &queue_params))
		EXAMPLE_ABORT("Error: cannot configure pktin queues");

	ret_cnt = odp_pktin_queue(pktio, pktin, cnt);
	if ((size_t)ret_cnt != cnt)
		EXAMPLE_ABORT("Error: cannot get the pktin queues");

	return 0;
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */

static void *gen_send_thread(void *arg)
{
	int thr;
	unsigned i;
	unsigned tx_ok;
	unsigned n;
	odp_pktout_queue_t pktout;
	thread_args_t *thr_args;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_packet_t pkt;

	thr = odp_thread_id();
	thr_args = arg;

	pktout = thr_args->pktout;

	pkt = pack_udp_pkt(thr_args->pool, thr*MAX_PKT_BURST);
	if (pkt == ODP_PACKET_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: cannot create packet\n", thr);
		return NULL;
	}
	printf("  [%02i] send\n", thr);

	for (i=0; i < MAX_PKT_BURST; i++) {
		pkt_tbl[i] = odp_packet_copy(pkt, thr_args->pool);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			return NULL;
		uint32_t len;
		odph_ipv4hdr_t *ip;
		ip = odp_packet_l3_ptr(pkt_tbl[i], &len);
		ip->src_addr = odp_cpu_to_be_32(odp_be_to_cpu_32(ip->src_addr) + i);
	}

	n = MAX_PKT_BURST;

	while (glob_work) {
		tx_ok = odp_pktout_send(pktout, pkt_tbl, n);

		stat[thr].tx += tx_ok;
		stat[thr].txe += n - tx_ok;

		if (tx_ok == 0)
			usleep(1);
	}

	return arg;
}

#ifndef ODP_PKTGEN_NOT_PRINT
/**
 * calc time period
 *
 *@param recvtime start time
 *@param sendtime end time
*/
static void tv_sub(struct timeval *recvtime, struct timeval *sendtime)
{
	long sec = recvtime->tv_sec - sendtime->tv_sec;
	long usec = recvtime->tv_usec - sendtime->tv_usec;
	if (usec >= 0) {
		recvtime->tv_sec = sec;
		recvtime->tv_usec = usec;
	} else {
		recvtime->tv_sec = sec - 1;
		recvtime->tv_usec = -usec;
	}
}

/**
 * Print odp packets
 *
 * @param  thr worker id
 * @param  pkt_tbl packets to be print
 * @param  len packet number
 */
static void print_pkts(int thr, odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	char *buf;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odph_icmphdr_t *icmp;
	struct timeval tvrecv;
	struct timeval tvsend;
	double rtt;
	unsigned i;
	size_t offset;
	char msg[1024];
	int rlen;
	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		rlen = 0;

		/* only ip pkts */
		if (!odp_packet_has_ipv4(pkt))
			continue;

		odp_atomic_inc_u64(&counters.ip);
		rlen += sprintf(msg, "receive Packet proto:IP\n");
		buf = odp_packet_data(pkt);
		//ip = (odph_ipv4hdr_t *)(buf + odp_packet_l3_offset(pkt));

		if (odp_packet_has_error(pkt)) {
			const char *error= "";

			if (odp_packet_has_l2_error(pkt))
				error = "L2 ";
			else if (odp_packet_has_l3_error(pkt))
				error = "L3 ";
			else if (odp_packet_has_l4_error(pkt))
				error = "L4 ";

			rlen += sprintf(msg + rlen, "packet has %sERROR\n", error);
		}



		ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
		rlen += sprintf(msg + rlen, "IP fields\n"
				"ver_ihl\t0x%"PRIx8"\n"
				"tos\t0x%"PRIx8"\n"
				"tot_len\t%"PRIu16"\n"
				"id\t0x%"PRIx16"\n"
				"frag_offset\t%"PRIu16"\n"
				"ttl\t%"PRIu8" 0x%"PRIx8"\n"
				"proto\t%"PRIu8" 0x%"PRIx8"\n"
				"chksum\t0x%"PRIx16"\n"
				"srcip\t0x%"PRIx32"\n"
				"dstip\t0x%"PRIx32"\n",
				ip->ver_ihl, ip->tos,
				odp_be_to_cpu_16(ip->tot_len),
				odp_be_to_cpu_16(ip->id),
				odp_be_to_cpu_16(ip->frag_offset),
				ip->ttl, ip->ttl, ip->proto, ip->proto,
				odp_be_to_cpu_16(ip->chksum),
				odp_be_to_cpu_32(ip->src_addr),
				odp_be_to_cpu_32(ip->dst_addr));

		offset = odp_packet_l4_offset(pkt);

		/* udp */
		if (ip->proto == ODPH_IPPROTO_UDP) {
			rlen += sprintf(msg + rlen, "Packet proto:IP:UDP\n");
			odp_atomic_inc_u64(&counters.udp);
			udp = (odph_udphdr_t *)(buf + offset);
			rlen += sprintf(msg + rlen, "UDP fields\n"
					"src_port\t%"PRIu16" 0x%"PRIx16"\n"
					"dst_port\t%"PRIu16" 0x%"PRIx16"\n"
					"length\t%"PRIu16"\n"
					"chksum\t0x%"PRIx16"\n",
					odp_be_to_cpu_16(udp->src_port),
					odp_be_to_cpu_16(udp->src_port),
					odp_be_to_cpu_16(udp->dst_port),
					odp_be_to_cpu_16(udp->dst_port),
					odp_be_to_cpu_16(udp->length),
					odp_be_to_cpu_16(udp->chksum));
		}

		/* icmp */
		if (ip->proto == ODPH_IPPROTO_ICMP) {
			icmp = (odph_icmphdr_t *)(buf + offset);
			/* echo reply */
			if (icmp->type == ICMP_ECHOREPLY) {
				odp_atomic_inc_u64(&counters.icmp);
				memcpy(&tvsend, buf + offset + ODPH_ICMPHDR_LEN,
				       sizeof(struct timeval));
				/* TODO This should be changed to use an
				 * ODP timer API once one exists. */
				gettimeofday(&tvrecv, NULL);
				tv_sub(&tvrecv, &tvsend);
				rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
				rlen += sprintf(msg + rlen,
					"ICMP Echo Reply seq %d time %.1f ",
					odp_be_to_cpu_16(icmp->un.echo.sequence)
					, rtt);
			} else if (icmp->type == ICMP_ECHO) {
				rlen += sprintf(msg + rlen,
						"Icmp Echo Request");
			}
		}

		msg[rlen] = '\0';
		printf("  [%02i] %s\n", thr, msg);
	}
}
#endif

/**
 * Main receive funtion
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
void *gen_recv_thread(void *arg);

void *gen_recv_thread(void *arg)
{
	int thr;
	unsigned i;
	unsigned rx_tot;
	unsigned rx_err;
	odp_pktin_queue_t pktin;
	thread_args_t *thr_args;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];

	thr = odp_thread_id();
	thr_args = arg;

	pktin = thr_args->pktin;

	printf("  [%02i] recv\n", thr);

	while (glob_work) {
		rx_tot = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (rx_tot <= 0)
			continue;

#ifndef ODP_PKTGEN_NOT_PRINT
		print_pkts(thr, pkt_tbl, rx_tot);
#endif

		/* Count packets with errors */
		rx_err = 0;
		for (i=0; i < rx_tot; i++)
			if (odp_unlikely(odp_packet_has_error(pkt_tbl[i])))
				rx_err++;

		stat[thr].rxe += rx_err;
		stat[thr].rx += rx_tot - rx_err;

		for (i=0; i < rx_tot; i++)
			odp_packet_free(pkt_tbl[i]);
	}

	return arg;
}

static void thr_stat_func(unsigned num_workers)
{
	struct stat *s0, *s1, *tmp;
	unsigned i;
	uint64_t rx, tx, rxe, txe, rxd;
	uint64_t sum_rx, sum_tx;

	s0 = stat0;
	s1 = stat1;
	while (glob_work) {
		sleep(1);
		sum_rx = sum_tx = 0;

		for (i = 1; i <= num_workers; i++) {
			odp_pktio_stats_t st;
			odp_pktio_stats(args->appl.pktio[i], &st);

			stat[i].rxd = st.in_discards;
		}

		/* TODO: alarm instead of sleep or adjust sleep for
		printf time */
		memcpy(s1+1, stat+1, num_workers * sizeof(struct stat));

		printf("thr%12s%12s%12s%12s%12s\n","tx","txe","rx","rxe","rxd");
		for (i = 1; i <= num_workers; i++) {
			tx = s1[i].tx - s0[i].tx;
			txe = s1[i].txe - s0[i].txe;
			sum_tx += tx;
			rx = s1[i].rx - s0[i].rx;
			rxe = s1[i].rxe - s0[i].rxe;
			rxd = s1[i].rxd - s0[i].rxd;
			sum_rx += rx;
			printf("%3u%12lu%12lu%12lu%12lu%12lu\n", i, tx, txe, rx, rxe, rxd);
		}
		printf("SUM TX %lu RX %lu\n", sum_tx, sum_rx);

		/* Swap stats */
		tmp = s1; s1 = s0; s0 = tmp;
	}
}
static int create_cpumask(odp_cpumask_t *mask, int first, int num_in)
{
	int i;
	int first_cpu = first;
	int num = num_in;
	int cpu_count;

	cpu_count = odp_cpu_count();

	/*
	 * If no user supplied number or it's too large, then attempt
	 * to use all CPUs
	 */
	if (0 == num)
		num = cpu_count;
	if (cpu_count < num)
		num = cpu_count;

	/*
	 * Always force "first_cpu" to a valid CPU
	 */
	if (first_cpu >= cpu_count)
		first_cpu = cpu_count - 1;

	/* Build the mask */
	odp_cpumask_zero(mask);
	for (i = 0; i < num; i++) {
		int cpu;

		cpu = (first_cpu + i) % cpu_count;
		odp_cpumask_set(mask, cpu);
	}

	return num;
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	unsigned num_workers;
	unsigned num_pktq_per_if;
	unsigned i;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_instance_t instance;

	if (odph_linux_sigaction(SIGINT, sig_func)) {
		EXAMPLE_ERR("Error: ODP sighandler setup failed.\n");
		exit(EXIT_FAILURE);
	}
	if (odph_linux_sigaction(SIGQUIT, sig_func)) {
		EXAMPLE_ERR("Error: ODP sighandler setup failed.\n");
		exit(EXIT_FAILURE);
	}
	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* init counters */
	odp_atomic_init_u64(&counters.seq, 0);
	odp_atomic_init_u64(&counters.ip, 0);
	odp_atomic_init_u64(&counters.udp, 0);
	odp_atomic_init_u64(&counters.icmp, 0);

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	args = odp_shm_addr(shm);

	if (args == NULL) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = args->appl.if_count;

	if (args->appl.cpu_count)
		num_workers = args->appl.cpu_count;
	if (num_workers > MAX_WORKERS) {
		EXAMPLE_ERR("Num workers %d > %d\n", num_workers, MAX_WORKERS);
		exit(EXIT_FAILURE);
	}

	if (num_workers % args->appl.if_count) {
		EXAMPLE_ERR("Num workers must be a multiply of interface count\n");
		exit(EXIT_FAILURE);
	}
	num_pktq_per_if = num_workers / args->appl.if_count;
	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */

	num_workers = create_cpumask(&cpumask, args->appl.number, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	memset(&params, 0, sizeof(params));
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = POOL_SIZE_GLOBAL + POOL_SIZE_THREAD*num_workers;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	for (i = 0; i < args->appl.if_count; ++i)
		args->appl.pktio[i] = create_pktio(args->appl.if_names[i], pool);
	for (i = 0; i < args->appl.if_count; ++i) {
		if (create_pktin_queues(args->appl.pktio[i],
					&args->appl.pktin[i * num_pktq_per_if],
					num_pktq_per_if))
			EXAMPLE_ABORT("Error: while craeting pktout\n");
		if (create_pktout_queues(args->appl.pktio[i],
					 &args->appl.pktout[i * num_pktq_per_if],
					 num_pktq_per_if))
			EXAMPLE_ABORT("Error: while craeting pktout\n");
	}
	for (i = 0; i < args->appl.if_count; ++i)
		if (odp_pktio_start(args->appl.pktio[i]))
			EXAMPLE_ABORT("Error: cannot start pktio\n");

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	int cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		odph_linux_thr_params_t thr_params;
		void *(*thr_run_func) (void *);

		memset(&args->thread[i], 0, sizeof(args->thread[i]));
		args->thread[i].pool = pool;
		args->thread[i].mode = args->appl.mode;
		if (args->appl.mode == APPL_MODE_SND) {
			args->thread[i].pktout = args->appl.pktout[i];
			thr_run_func = gen_send_thread;
		} else {
			args->thread[i].pktin = args->appl.pktin[i];
			thr_run_func = gen_recv_thread;
		}
		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);

		thr_params.start = thr_run_func;
		thr_params.arg = &args->thread[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		if (1 != odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
						   &thr_params)) {
			EXAMPLE_ABORT("Error: while creating worker thread\n");
		}

		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	thr_stat_func(num_workers);

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);
	printf("Exit\n\n");

	for (i = 0; i < args->appl.if_count; ++i) {
		if (close_pktio(args->appl.pktio[i]))
			EXAMPLE_ERR("Error: error while closing pktio\n");
	}
	if (odp_pool_destroy(pool))
		EXAMPLE_ERR("Error: error while destroying buffer pool\n");
	if (odp_shm_free(shm))
		EXAMPLE_ERR("Error: error while freeing shm\n");

	return 0;
}


/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"interface", required_argument, NULL, 'I'},
		{"workers", required_argument, NULL, 'w'},
		{"srcmac", required_argument, NULL, 'a'},
		{"dstmac", required_argument, NULL, 'b'},
		{"srcip", required_argument, NULL, 'c'},
		{"dstip", required_argument, NULL, 'd'},
		{"packetsize", required_argument, NULL, 's'},
		{"mode", required_argument, NULL, 'm'},
		{"count", required_argument, NULL, 'n'},
		{"timeout", required_argument, NULL, 't'},
		{"interval", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_SND; /* Invalid, must be changed by parsing */
	appl_args->number = 11;
	appl_args->payload = 0;
	appl_args->timeout = -1;

	while (1) {
		opt = getopt_long(argc, argv, "+I:a:b:c:d:s:i:m:n:t:w:h",
					longopts, &long_index);
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->cpu_count = atoi(optarg);
			break;
		/* parse packet-io interface names */
		case 'I':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;
		case 'm':
			if (optarg[0] == 's') {
				appl_args->mode = APPL_MODE_SND;
			} else if (optarg[0] == 'r') {
				appl_args->mode = APPL_MODE_RCV;
			} else {
				EXAMPLE_ERR("wrong mode!\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'a':
			if (scan_mac(optarg, &appl_args->srcmac) != 1) {
				EXAMPLE_ERR("wrong src mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			if (scan_mac(optarg, &appl_args->dstmac) != 1) {
				EXAMPLE_ERR("wrong dst mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'c':
			if (scan_ip(optarg, &appl_args->srcip) != 1) {
				EXAMPLE_ERR("wrong src ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			if (scan_ip(optarg, &appl_args->dstip) != 1) {
				EXAMPLE_ERR("wrong dst ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			appl_args->payload = atoi(optarg);
			break;

		case 'n':
			appl_args->number = atoi(optarg);
			break;

		case 't':
			appl_args->timeout = atoi(optarg);
			break;

		case 'i':
			appl_args->interval = atoi(optarg);
			if (appl_args->interval <= 200 && geteuid() != 0) {
				EXAMPLE_ERR("should be root user\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}
#if 0
	if (appl_args->if_count == 0 || appl_args->mode == -1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
#endif
	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	unsigned i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU max freq (hz): %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	if (appl_args->mode == 0)
		PRINT_APPL_MODE(0);
	else
		PRINT_APPL_MODE(0);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -I eth1 -r\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "  Work mode:\n"
	       "    1.send udp packets\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m u\n"
	       "    2.receive udp packets\n"
	       "      odp_generator -I eth0 -m r\n"
	       "    3.work likes ping\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m p\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -I, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -a, --srcmac src mac address\n"
	       "  -b, --dstmac dst mac address\n"
	       "  -c, --srcip src ip address\n"
	       "  -d, --dstip dst ip address\n"
	       "  -s, --packetsize payload length of the packets\n"
	       "  -m, --mode work mode: send udp(u), receive(r), send icmp(p)\n"
	       "  -n, --count the number of packets to be send\n"
	       "  -t, --timeout only for ping mode, wait ICMP reply timeout seconds\n"
	       "  -i, --interval wait interval ms between sending each packet\n"
	       "                 default is 1000ms. 0 for flood mode\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       " environment variables: ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_BASIC\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	      );
}
