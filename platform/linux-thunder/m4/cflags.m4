##########################################################################
# Configure default flags for the platform
##########################################################################
CFLAGS?="-O3 -g -static"
LIBS="-ldl $LIBS"

AC_MSG_CHECKING([whether CC supports -flto])
lto_supported=no
my_save_cflags=$CFLAGS
CFLAGS="$CFLAGS -flto"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	[lto_gcc=yes],
	[lto_gcc=no])
CFLAGS=$my_save_cflags
if test "$lto_gcc" = yes -a `expr index "$CC" thunderx` -gt 0; then
	lto_supported=yes
fi
AC_MSG_RESULT($lto_supported)

AC_ARG_ENABLE([lto],
    [  --enable-lto       enable Link Time Optimization],
    [if test "$lto_supported" = yes; then
        CFLAGS="$CFLAGS -flto"
    fi])

