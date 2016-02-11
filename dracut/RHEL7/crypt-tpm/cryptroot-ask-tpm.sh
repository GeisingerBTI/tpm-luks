#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue, dd
#
# Author: Kent Yoder <shpedoikal@gmail.com>
#
PATH=/usr/sbin:/usr/bin:/sbin:/bin
. /lib/dracut-crypt-lib.sh

TPM_LUKS_CONF=/etc/tpm-luks.conf
TPM_NV_PER_AUTHREAD=0x00040000
TPM_NV_PER_OWNERREAD=0x00020000
TMPFS_MNT=/tmp/cryptroot-mnt
KEYFILE=$TMPFS_MNT/key

DEVICE=$1
NAME=$2
PASS=$3

if [ "$PASS" == "" -o "$PASS" == "read" ]; then

	# Find the device index based on the device name
	NVINDEX=$(cat $TPM_LUKS_CONF | grep -v "^\s*#" | grep $DEVICE | cut -d: -f2)

	if [ -z "$NVINDEX" ]; then
		cryptroot-ask-tpm $DEVICE $NAME input
		exit 0
	fi

	NVINDEX=$(printf "0x%x" $NVINDEX)

	NVMATCH=$(getcapability -cap 0x11 -scap $NVINDEX | awk -F ": " '$1 ~ /Matches/ { print $2 }')
	NVSIZE=$(getcapability -cap 0x11 -scap $NVINDEX | awk -F= '$1 ~ /dataSize/ { print $2 }')
	NVRESULT=$(getcapability -cap 0x11 -scap $NVINDEX | awk '$1 ~ /Result/ { print $11 }')

	# An index is viable if its composite hash matches current PCR state, or if
	# it doesn't require PCR state at all
	if [ -z "$NVSIZE" ]; then
		cryptroot-ask-tpm $DEVICE $NAME input
		exit 0
	fi

	if [ -n "$MATCH1" -a "$MATCH1" != "Yes" ]; then
		warn "TPM NV index does not match PCR state."
		cryptroot-ask-tpm $DEVICE $NAME input
		exit 0
	fi

	# An index needs a password if authentication bits matches AUTHREAD or OWNERREAD
	if [ -n "$NVRESULT" -a -z "$PASS" ]; then
		AUTHREAD=$(( 0x$NVRESULT & $TPM_NV_PER_AUTHREAD ))
		OWNERREAD=$(( 0x$NVRESULT & $TPM_NV_PER_OWNERREAD ))
		
		if [ $AUTHREAD -ne 0 -o $OWNERREAD -ne 0 ]; then
			ask_for_password --tries 3 --tty-echo-off \
				--cmd "cryptroot-ask-tpm $DEVICE $NAME read" \
				--prompt "Enter TPM NVRAM password for device: $DEVICE\nESC to show, '' to skip\n"
			exit 0
		fi
	fi

	# Plymouth feeds in this password for us, if we need a password
	NVPASS_OPTIONS=
	if [ -n "$PASS" ]; then
		readpass NVPASS
		if [ -z "$NVPASS" ]; then
			warn "TPM NVRAM password is empty, fall back to regular password."
			cryptroot-ask-tpm $DEVICE $NAME input
			exit 0
		fi
		NVPASS_OPTIONS="-pwdd $NVPASS"
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

	# Read key from TPM NVRAM into keyfile
	info "Reading from NV index $NVINDEX."
	nv_readvalue -ix $NVINDEX $NVPASS_OPTIONS -sz $NVSIZE -of $KEYFILE >/dev/null 2>&1
	RC=$?
	if [ $RC -eq 1 ]; then
		warn "TPM NV index $NVINDEX: Bad password."
	elif [ $RC -eq 24 ]; then
		warn "TPM NV index $NVINDEX: PCR mismatch."
	elif [ $RC -eq 2 ]; then
		warn "TPM NV index $NVINDEX: Invalid NVRAM Index."
	elif [ $RC -ne 0 ]; then
		warn "TPM NV index $NVINDEX: Unknown error ($RC)"
	fi
	
	if [ $RC -ne 0 ]; then
		umount $TMPFS_MNT
		[ "$PASS" == "read" ] && exit 255
		cryptroot-ask-tpm $DEVICE $NAME input
		exit 0
	fi

	# Open the luks partition using the key
	info "Opening LUKS partition $DEVICE using TPM key."
	cryptsetup luksOpen $DEVICE $NAME --key-file $KEYFILE --keyfile-size $NVSIZE
	RC=$?
	# Zeroize keyfile regardless of success/fail and unmount
	dd if=/dev/zero of=$KEYFILE bs=1c count=$NVSIZE >/dev/null 2>&1
	umount $TMPFS_MNT
	# if error
	if [ $RC -ne 0 ]; then
		warn "cryptsetup failed."
		[ "$PASS" == "read" ] && exit 255
		cryptroot-ask-tpm $DEVICE $NAME input
		exit 0
	fi
	
	#success
	exit 0

fi

if [ "$PASS" == "input" ]; then

	ask_for_password --tries 3 --tty-echo-off \
		--cmd "cryptroot-ask-tpm $DEVICE $NAME pass" \
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
