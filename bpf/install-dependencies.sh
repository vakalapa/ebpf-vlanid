#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

apt-get update && apt-get upgrade
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
apt-get install gcc-multilib

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


