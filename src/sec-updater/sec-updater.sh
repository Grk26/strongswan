#!/bin/sh

DIR="/etc/pts"
DATE=`date +%Y%m%d-%H%M`
UBUNTU="http://security.ubuntu.com/ubuntu/dists"
UBUNTU_VERSIONS="xenial"
UBUNTU_DIRS="main multiverse restricted universe"
UBUNTU_ARCH="binary-amd64"
DEBIAN="http://security.debian.org/dists"
DEBIAN_VERSIONS=""
DEBIAN_DIRS="main contrib non-free"
DEBIAN_ARCH="binary-amd64 binary-i386"
PACMAN=/usr/libexec/ipsec/pacman
PACMAN_LOG="$DIR/$DATE-pacman.log"

mkdir -p $DIR/dists
cd $DIR/dists

for v in $UBUNTU_VERSIONS
do
  for a in $UBUNTU_ARCH
  do
    mkdir -p $v-security/$a $v-updates/$a
    for d in $UBUNTU_DIRS
    do
      wget $UBUNTU/$v-security/$d/$a/Packages.xz -O $v-security/$a/Packages-$d.xz
      unxz -f $v-security/$a/Packages-$d.xz
      wget $UBUNTU/$v-updates/$d/$a/Packages.xz  -O $v-updates/$a/Packages-$d.xz
      unxz -f $v-updates/$a/Packages-$d.xz
	done
  done
done

for v in $DEBIAN_VERSIONS
do
  for a in $DEBIAN_ARCH
  do
    mkdir -p $v-updates/$a
    for d in $DEBIAN_DIRS
    do
      wget $DEBIAN/$v/updates/$d/$a/Packages.xz  -O $v-updates/$a/Packages-$d.xz
      unxz -f $v-updates/$a/Packages-$d.xz
	done
  done
done

for f in xenial-security/binary-amd64/*
do
  echo "security: $f"
  $PACMAN --product "Ubuntu 16.04 x86_64" --file $f --security >> $PACMAN_LOG
done
echo
for f in xenial-updates/binary-amd64/*
do
  echo "updates: $f"
  $PACMAN --product "Ubuntu 16.04 x86_64" --file $f >> $PACMAN_LOG
done
