#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue, dd
#
# Author: Kent Yoder <shpedoikal@gmail.com>
#

set -x

PATH=/usr/sbin:/usr/bin:/sbin:/bin
. /lib/dracut-crypt-lib.sh

TPM_LUKS_CONF=/etc/tpm-luks.conf
TMPFS_MNT=/tmp/cryptroot-mnt
KEYFILE=$TMPFS_MNT/key

#SEALEDKEY=/boot/.key

DEVICE=$1
SEALEDKEY=$2
NAME=$3
PASS=$4

if [ "$PASS" == "" ]; then

	# Mount tmpfs to store luks keys
	if [ ! -d $TMPFS_MNT ]; then
		mkdir $TMPFS_MNT
		if [ $? -ne 0 ]; then
			warn "Unable to create $TMPFS_MNT folder to securely store TPM NVRAM data."
			exit 255
		fi
	fi

	mount -t tmpfs -o size=16K tmpfs $TMPFS_MNT
	if [ $? -ne 0 ]; then
		warn "Unable to mount tmpfs area to securely store TPM NVRAM data."
		exit 255
	fi

	# Read key from sealed keyfile into keyfile
	info "Reading from file $SEALEDKEY"
	touch $KEYFILE
	chmod a-rwx $KEYFILE
	chmod u+rw $KEYFILE

	info "Root:"
	ls -alh /

	info "Boot:"
	ls -alh /boot

	
	tpm_unseal -z -i $SEALEDKEY -o $KEYFILE
	RC=$?
	if [ $RC -eq 24 ]; then
		warn "TPM Unseal PCR mismatch."
	elif [ $RC -ne 0 ]; then
		warn "TPM Unseal Unknown error ($RC)"
	fi
	
	info "Opening LUKS partition $DEVICE using TPM key."
	cryptsetup luksOpen $DEVICE $NAME --key-file $KEYFILE
	RC=$?
	# Zeroize keyfile regardless of success/fail and unmount
	dd if=/dev/zero of=$KEYFILE bs=1c count=$F_SIZE >/dev/null 2>&1
	umount $TMPFS_MNT
	# if error
	
	if [ $RC -ne 0 ]; then
		umount $TMPFS_MNT
		exit 255
	fi
	
	F_SIZE=$(stat -c %s $KEYFILE)

	# Open the luks partition using the key
	info "Opening LUKS partition $DEVICE using TPM key."
	cryptsetup luksOpen $DEVICE $NAME --key-file $KEYFILE
	RC=$?
	# Zeroize keyfile regardless of success/fail and unmount
	dd if=/dev/zero of=$KEYFILE bs=1c count=$F_SIZE >/dev/null 2>&1
	umount $TMPFS_MNT
	# if error
	
	if [ $RC -ne 0 ]; then
		warn "cryptsetup failed."
		exit 255
	fi
	
	#success
	exit 0

fi

