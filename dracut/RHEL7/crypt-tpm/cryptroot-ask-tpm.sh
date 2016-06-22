#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue, dd
#
# Author: Kent Yoder <shpedoikal@gmail.com>
#
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

if [ "$PASS" == "" -o "$PASS" == "read" ]; then

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
	
	tpm_unseal -z -i $SEALEDKEY -o $KEYFILE >/dev/null 2>&1
	RC=$?
	if [ $RC -eq 24 ]; then
		warn "TPM Unseal PCR mismatch."
	elif [ $RC -ne 0 ]; then
		warn "TPM Unseal Unknown error ($RC)"
	fi
	
	if [ $RC -ne 0 ]; then
		umount $TMPFS_MNT
		[ "$PASS" == "read" ] && exit 255
		cryptroot-ask-tpm $DEVICE $SEALEDKEY $NAME input
		exit 0
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
		[ "$PASS" == "read" ] && exit 255
		cryptroot-ask-tpm $DEVICE $SEALEDKEY $NAME input
		exit 0
	fi
	
	#success
	exit 0

fi

if [ "$PASS" == "input" ]; then

	ask_for_password --tries 3 --tty-echo-off \
		--cmd "cryptroot-ask-tpm $DEVICE $SEALEDKEY $NAME pass" \
		--prompt "Enter LUKS password for device $DEVICE\nESC to show, '' to skip, start with '=' for base64, '==' to escape\n"
	exit 0

fi

if [ "$PASS" == "pass" ]; then

	# Mount tmpfs to store luks keys
	if [ ! -d $TMPFS_MNT ]; then
		mkdir $TMPFS_MNT
		if [ $? -ne 0 ]; then
			warn "Unable to create $TMPFS_MNT folder to securely store TPM NVRAM data."
			exit 0
		fi
	fi

	mount -t tmpfs -o size=16K tmpfs $TMPFS_MNT
	if [ $? -ne 0 ]; then
		warn "Unable to mount tmpfs area to securely store TPM NVRAM data."
		exit 0
	fi

	# Save input key into key file
	readpass NVPASS
	if [ -z "$NVPASS" ]; then
		warn "Regular password is empty, abort."
		exit 0
	elif [[ "$NVPASS" == ==* ]]; then
		NVPASS=${NVPASS:1}
		echo -n "$NVPASS" > $KEYFILE
	elif [[ "$NVPASS" == =* ]]; then
		NVPASS=${NVPASS:1}
		echo -n "$NVPASS" | base64 -d > $KEYFILE
		if [ $? -ne 0 ]; then
			warn "Invalid base64 password."
			exit 255
		fi
	else
		echo -n "$NVPASS" > $KEYFILE
	fi
	
	NVSIZE=$(stat -c%s $KEYFILE)
	
	# Open the luks partition using the key
	info "Opening LUKS partition $DEVICE using input password."
	cryptsetup luksOpen $DEVICE $NAME --key-file $KEYFILE --keyfile-size $NVSIZE
	RC=$?
	# Zeroize keyfile regardless of success/fail and unmount
	dd if=/dev/zero of=$KEYFILE bs=1c count=$NVSIZE >/dev/null 2>&1
	umount $TMPFS_MNT
	# if error
	if [ $RC -ne 0 ]; then
		warn "cryptsetup failed."
		exit 255
	fi
	
	#success
	exit 0

fi
