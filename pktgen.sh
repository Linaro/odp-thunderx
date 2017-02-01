PROG=example/pktgen/pktgen
if [ -n "$GDB" ]
then
	PROG="gdb --args $PROG"
fi

if [ -z $1 ]
then
	echo $(basename $0) DEV [THREADS]
	exit
fi

MODE=${MODE:=s}
SIZE=${SIZE:=0}
CORE=${CORE:=11}
DEV=$1
WORKERS=$2
ARGS="-I vfio:${DEV} --srcmac 02:01:01:01:01:01 --dstmac 02:01:01:01:01:02 --srcip 192.168.0.1 --dstip 192.168.0.2 -s $SIZE -m $MODE -n $CORE -w $WORKERS"
echo $PROG $ARGS
$PROG $ARGS

