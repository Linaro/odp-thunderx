PROG=test/performance/odp_l2fwd
if [ -n "$GDB" ]
then
	PROG="gdb --args $PROG"
fi

if [ -z $1 ]
then
	echo $(basename $0) DEV [THREADS]
	exit
fi

DEV=$1
N=${2-1}
ARGS="-i vfio:$DEV -c $N -m 0"
echo $PROG $ARGS
$PROG $ARGS
