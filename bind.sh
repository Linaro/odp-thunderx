#!/bin/bash

CLASS_NET=0200
VENDOR_CAVIUM=177d
NICVF_DEVICE_PASS20=a034
NICVF_DEVICE_PASS10=0011

DEVICES_PASS10=$(lspci -Dmmn -d $VENDOR_CAVIUM:$NICVF_DEVICE_PASS10 | cut -f1 -d\ )
DEVICES_PASS20=$(lspci -Dmmn -d $VENDOR_CAVIUM:$NICVF_DEVICE_PASS20 | cut -f1 -d\ )

if [ -n "$DEVICES_PASS20" ]
then
	NICVF_DEVICE=$NICVF_DEVICE_PASS20
	DEVICES=$DEVICES_PASS20
elif [ -n "$DEVICES_PASS10" ]
then
	NICVF_DEVICE=$NICVF_DEVICE_PASS10
	DEVICES=$DEVICES_PASS10
else
	echo No VNIC found in system
	exit 1
fi


if [ $# -eq 0 ]
then 
	for dev in $DEVICES
	do
		devpath=/sys/bus/pci/devices/$dev
		driver=$(basename $(readlink $devpath/driver) 2>/dev/null)
		if [ "a$driver" = "a" ]; then driver="no-driver"; fi
		netdev=$(ls $devpath/net 2> /dev/null)
		uio_num=$(ls $devpath/uio 2> /dev/null)
		iommu_grp=$(basename $(readlink $devpath/iommu_group) 2> /dev/null || echo "<none>")
		echo $dev $driver $netdev $uio_num iommu group $iommu_grp
	done
	exit
fi

if [ $# -ne 2 ]
then 
	echo -e "Usage: \n\t`basename $0` <DEVICE> <DRIVER>"
	echo -e "<DEVICE>\t\t[[[<domain>:]<bus>:]<slot>].<func>"
	echo examples:
	echo -e Bind function 1 of the first matching device, e.g. 0002:01:00.1 to vfio-pci
	echo -e "\t`basename $0` 1 vfio-pci"
	echo -e Bind device 01:00.2 of the first matching domain, e.g. 0002:01:00.2 to vfio-pci
	echo -e "\t`basename $0` 01:00.2 vfio-pci"
	exit
fi
DRV=$2
VF=$1

if [ ! -d /sys/bus/pci/drivers/$DRV ]
then
	echo "Driver \"$DRV\" is not loaded or it is invalid driver name"
	exit
fi

ETH=$(echo "$DEVICES" | grep -E "$VF$" | head -n1)

if [ -d /sys/bus/pci/devices/$ETH/driver ]
then
	echo "Unbinding $ETH > /sys/bus/pci/devices/$ETH/driver/unbind"
	echo $ETH > /sys/bus/pci/devices/$ETH/driver/unbind
fi
echo Binding $ETH to $DRV...
echo $VENDOR_CAVIUM $NICVF_DEVICE > /sys/bus/pci/drivers/$DRV/new_id || \
echo $ETH > /sys/bus/pci/drivers/$DRV/bind

echo $ETH $(basename $(readlink /sys/bus/pci/devices/$ETH/driver)) 

DEV=/sys/bus/pci/devices/$ETH
if [ "$DRV" == "vfio-pci" ]
then
	echo "vfio group" $(basename $(readlink $DEV/iommu_group))
fi
if [ "$DRV" == "nicvf_uio" ]
then
	echo "uio dev" $(ls $DEV/uio)
fi
