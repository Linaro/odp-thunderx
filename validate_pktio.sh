if [ "$#" -lt 2 ]; then
    echo $(basename $0) DEV0 DEV1
    exit
fi
DEV0=$1; shift
DEV1=$1; shift
VF0=$(./bind.sh | sed -ne "s/\(^[^ ]*\).* $DEV0$/\1/p")
VF1=$(./bind.sh | sed -ne "s/\(^[^ ]*\).* $DEV1$/\1/p")
./bind.sh $VF0 vfio-pci
./bind.sh $VF1 vfio-pci
ODP_PKTIO_IF0=vfio:$DEV0 ODP_PKTIO_IF1=vfio:$DEV1 test/validation/pktio/pktio_main
./bind.sh $VF0 thunder-nicvf
./bind.sh $VF1 thunder-nicvf
