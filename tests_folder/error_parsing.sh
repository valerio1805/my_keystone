#!/bin/sh

export HOST_PORT=5749;

echo "**** Running QEMU SSH on port ${HOST_PORT} ****";

export SMP=1;

while [ "$1" != "" ]; do
    if [ "$1" = "-debug" ];
    then
        echo "**** GDB port $((HOST_PORT + 1)) ****";
        DEBUG="-gdb tcp::$((HOST_PORT + 1)) -S -d in_asm -D debug.log";
    fi;
    if [ "$1" = "-smp" ];
    then
        SMP="$2";
        shift;
    fi;
    shift;
done;

/home/valerio/keystone/qemu/build/riscv64-softmmu/qemu-system-riscv64 \
 $DEBUG \
 -m 2G \
 -nographic \
 -machine virt,rom=/home/valerio/keystone/build_dir/scripts/functioning_test/bootrom_error_parsing.bin \
 -bios /home/valerio/keystone/build_dir/scripts/functioning_test/fw_jump_error_parsing.elf \
 -kernel /home/valerio/keystone/build_dir/scripts/functioning_test/Image_error_parsing \
       -append "console=ttyS0 ro root=/dev/vda"       -drive file=/home/valerio/keystone/build_dir/scripts/functioning_test/rootfs_error_parsing.ext2,format=raw,id=hd0       -device virtio-blk-device,drive=hd0    \
 -netdev user,id=net0,net=192.168.100.1/24,dhcpstart=192.168.100.128,hostfwd=tcp::${HOST_PORT}-:22 \
 -device virtio-net-device,netdev=net0 \
 -device virtio-rng-pci \
 -smp $SMP
