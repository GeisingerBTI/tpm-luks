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
KEY_MNT=/tmp/key-mnt
KEYFILE=$TMPFS_MNT/key

#SEALEDKEY=/boot/.key

TPM_LUKS_CONF=/etc/tpm-luks.conf

DEVICE=$1
NAME=$2

# Find the name of the sealed keyfile to use
SEALEDKEY=$(cat $TPM_LUKS_CONF | grep -v "^\s*#" | grep $DEVICE | cut -d: -f2)
if [ -z "$SEALEDKEY" ]; then
	warn "Unable to determine key name; falling back to password"
	exit 255
fi


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
touch $KEYFILE
chmod go-rwx $KEYFILE



info "Root:"
ls -alh /

info "etc:"
ls -alh /etc

info "dev/disk"
ls -alhR /dev/disk

# Go through the devices searching for an unencrypted boot device that has the 
# sealed key on it
if [ ! -d $KEY_MNT ]; then
	mkdir $KEY_MNT
	if [ $? -ne 0 ]; then
		warn "Unable to create $KEY_MNT folder to mount filesystem."
		exit 255
	fi
fi

exit 255


tpm_unseal -z -i $KEY_MNT/$SEALEDKEY -o $KEYFILE
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


