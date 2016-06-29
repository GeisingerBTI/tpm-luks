#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

check() {
    local _rootdev
    # if cryptsetup is not installed, then we cannot support encrypted devices.
    type -P cryptsetup >/dev/null || return 1

    [[ $hostonly ]] || [[ $mount_needs ]] && {
        for fs in "${host_fs_types[@]}"; do
            [[ $fs = "crypto_LUKS" ]] && return 0
        done
        return 255
    }

    return 0
}

depends() {
    echo dm rootfs-block
    return 0
}

installkernel() {
    instmods dm_crypt =crypto
}

cmdline() {
    local dev UUID
    for dev in "${!host_fs_types[@]}"; do
        [[ "${host_fs_types[$dev]}" != "crypto_LUKS" ]] && continue

        UUID=$(
            blkid -u crypto -o export $dev \
                | while read line; do
                [[ ${line#UUID} = $line ]] && continue
                printf "%s" "${line#UUID=}"
                break
            done
        )
        [[ ${UUID} ]] || continue
        printf "%s" " rd.luks.uuid=luks-${UUID}"
    done
}

install() {

    if [[ $hostonly_cmdline == "yes" ]]; then
        cmdline >> "${initdir}/etc/cmdline.d/90crypt.conf"
        echo >> "${initdir}/etc/cmdline.d/90crypt.conf"
    fi
    
    inst_multiple getcapability nv_readvalue awk od dd cut cat grep stat mkdir read base64
    inst_script "$moddir"/cryptroot-ask-tpm.sh /sbin/cryptroot-ask-tpm

    inst_multiple cryptsetup rmdir readlink umount
    inst_script "$moddir"/cryptroot-ask.sh /sbin/cryptroot-ask
    inst_script "$moddir"/probe-keydev.sh /sbin/probe-keydev
    inst_hook cmdline 10 "$moddir/parse-keydev.sh"
    inst_hook cmdline 30 "$moddir/parse-crypt.sh"
#    if ! dracut_module_included "systemd"; then
        inst_hook cleanup 30 "$moddir/crypt-cleanup.sh"
#    fi

    if [[ $hostonly ]] && [[ -f /etc/crypttab ]]; then
        cp -f /etc/crypttab $initdir/etc/crypttab
    fi
    
    if [[ $hostonly ]] && [[ -f /etc/tpm-luks.conf ]]; then
    	# copy file as-is
    	cp /etc/tpm-luks.conf $initdir/etc/tpm-luks.conf
    fi

    inst_simple "$moddir/crypt-lib.sh" "/lib/dracut-crypt-lib.sh"

    inst_multiple -o \
        $systemdutildir/system-generators/systemd-cryptsetup-generator \
        $systemdutildir/systemd-cryptsetup \
        $systemdsystemunitdir/systemd-ask-password-console.path \
        $systemdsystemunitdir/systemd-ask-password-console.service \
        $systemdsystemunitdir/cryptsetup.target \
        $systemdsystemunitdir/sysinit.target.wants/cryptsetup.target \
        systemd-ask-password systemd-tty-ask-password-agent
#    inst_script "$moddir"/crypt-run-generator.sh /sbin/crypt-run-generator
    dracut_need_initqueue
}
