include ../Makefile.inc

# TODO: investigate why shmem test fails without this setting
if HAVE_THUNDERX
AM_CFLAGS += -DMAP_HUGETLB
endif

noinst_LTLIBRARIES = libtestshmem.la
libtestshmem_la_SOURCES = shmem.c

test_PROGRAMS = shmem_main$(EXEEXT)
dist_shmem_main_SOURCES = shmem_main.c
shmem_main_LDADD = libtestshmem.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = shmem.h
