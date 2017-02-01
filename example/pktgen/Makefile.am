include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = pktgen
pktgen_LDFLAGS = $(AM_LDFLAGS) -static
pktgen_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_pktgen_SOURCES = pktgen.c
