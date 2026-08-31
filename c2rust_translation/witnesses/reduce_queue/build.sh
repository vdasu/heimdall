#!/bin/sh
# Compile the two example eBPF objects. Needs clang with the bpf target.
set -e
cd "$(dirname "$0")"
CLANG="${CLANG:-clang}"
CFLAGS="-target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -O2 -g -Wall"
$CLANG $CFLAGS -c orig.bpf.c -o orig.bpf.o
$CLANG $CFLAGS -c opt.bpf.c  -o opt.bpf.o
echo "built orig.bpf.o and opt.bpf.o"
