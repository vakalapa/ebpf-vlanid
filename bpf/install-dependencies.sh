#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ "$1" = "ins" ] ; then
    apt-get update && apt-get upgrade
    bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
    apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex  graphviz 

    if [ ! -d "/usr/include/asm" ] 
    then
        if [ -d "/usr/include/asm-generic" ] 
        then
            ln -s /usr/include/asm-generic /usr/include/asm
        else
            echo "Missing /usr/include/asm directory. Try to compile manually,"
            exit
        fi
    fi
    exit
fi

interface=$1

clang -O2 -Wall -target bpf -c main.c -o vlan_tag.o

tc qdisc add dev $interface clsact
tc filter add dev $interface egress bpf da obj vlan_tag.o sec egress

#  sudo tc filter show dev eth0 egress
#  sudo  tc filter add dev vethd81a9eb egress bpf da obj vlan_tag.o sec egress
#  sudo tc filter del dev eth0 egress pref 49152

