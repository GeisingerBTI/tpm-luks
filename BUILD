
= build pre-reqs =

 Packages: automake, autoconf, libtool, gcc, openssl-devel, make

= build steps =

 $ autoreconf -ivf
 $ ./configure
 $ make
 # make install

= runtime pre-reqs =

 For using tpm-luks with a LUKS key on your rootfs volume: dracut grubby

 All uses: cryptsetup gawk coreutils tpm-tools-1.3.9 trousers-0.3.9

 tpm-luks requires very recent tpm-tools versions, not included in any distro.
 To get these versions, you'll need to install them from our repository:
 NOTE: branch rpm_fixes will also cleanly build an RPM on RHEL7 and derivatives.

 $ git clone git://github.com/GeisingerBTI/tpm-tools
 $ cd tpm-tools
 $ git checkout rpm_fixes
 $ sh bootstrap.sh
 $ ./configure
 $ make
 # make install
 
EOF
