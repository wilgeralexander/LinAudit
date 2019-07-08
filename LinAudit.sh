#!/bin/bash

ECHO=`which echo`
GREP=`which grep`
AWK=`which awk`

if [ -z "$ECHO" -o -z "$GREP" -o -z "$AWK" ]; then
        $ECHO "ERROR: Not all necessary commands could be found. Exitting..."
        exit
fi

function printfailure {
	$ECHO "$1 - FAILURE"
	CHECKS_FAILED=$((CHECKS_FAILED+1))
}

function printsuccess {
	if [ $PRINT_SUCCESS -eq 1 ]; then $ECHO "$1 - SUCCESS"; fi
	CHECKS_PASSED=$((CHECKS_PASSED+1))
}

function printmanualcheck {
	$ECHO "$1 - MANUAL CHECK"
}

PRINT_SUCCESS=0
PRINT_EVIDENCE=1
CHECKS_PASSED=0
CHECKS_FAILED=0
SECURITY_LEVEL=1

if [ ! -e /etc/redhat-release ]; then
	$ECHO "ERROR: The system does not appear to be Red Hat or CentOS. Exitting..."
	exit
else
	if [ `$GREP -E -c 'CentOS' /etc/redhat-release` -eq 1 ]; then
		OS="CentOS"
		CentOS_VERSION=`$AWK '{print $(NF-1)}' /etc/redhat-release | $AWK -F. '{print $1}'`
		VERSION=$CentOS_VERSION
		if [ ! \( $CentOS_VERSION -eq 7 -o $CentOS_VERSION -eq 6 \) ]; then
			$ECHO "Only CentOS versions 6 and 7 supported. (Version $CentOS_VERSION detected) Exitting..."
			exit
		fi
	else
		OS="RHEL"
		RHEL_VERSION=`$AWK '{print $(NF-1)}' /etc/redhat-release | $AWK -F. '{print $1}'`
		VERSION=$RHEL_VERSION
		if [ ! \( $RHEL_VERSION -eq 7 -o $RHEL_VERSION -eq 6 \) ]; then
			$ECHO "Only RHEL versions 6 and 7 supported. (Version $RHEL_VERSION detected) Exitting..."
			exit
		fi
	fi
	if [ -z "$OS" ]; then
		$ECHO "ERROR: Operating system not supported. Exitting..."
		exit
	fi
fi

if [ $VERSION -eq 7 ]; then
	GRUB_FILE="/boot/grub2/grub.cfg"
	MAX_SYSTEM_UID=1000
else # $VERSION -eq 6
	GRUB_FILE="/boot/grub/grub.conf"
	MAX_SYSTEM_UID=500
fi

RPM=`which rpm`
CHKCONFIG=`which chkconfig`
STAT=`which stat`
DF=`which df`
FIND=`which find`
USERADD=`which useradd`
SED=`which sed`
LSMOD=`which lsmod`
MODPROBE=`which modprobe`

if [ -z "$RPM" -o -z "$CHKCONFIG" -o -z "$STAT" -o -z "$AWK" -o -z "$ECHO" -o -z "$GREP" -o -z "$DF" -o -z "$FIND" -o -z "$USERADD" -o \
     -z "$SED" -o -z "$LSMOD" -o -z "$MODPROBE" ]; then
        $ECHO "ERROR: Not all necessary commands could be found. Exitting..."
        exit
fi

i=1
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
	if [ ! \( `$LSMOD | $GREP -c $fs` -eq 0 -a \
	     \( `$MODPROBE -n -v $fs 2>/dev/null | $GREP -E -c "."` -eq 0 -o `$MODPROBE -n -v $fs 2>/dev/null | $GREP -c "install /bin/true"` -eq 1 \) \) ]; then
		printfailure "1.1.$i - Disable Mounting of $fs Filesystems"
		$LSMOD | $GREP $fs; $MODPROBE -n -v $fs
	else
		printsuccess "1.1.$i - Disable Mounting of $fs Filesystems"
	fi
	i=$((i+1))
done

LOCAL_FS=`$DF --local -P | $AWK {'if (NR!=1) print $6'}`

if [ `$GREP -c "[[:space:]]/tmp[[:space:]]" /etc/fstab` -eq 0 ]; then
	printfailure '1.1.2 - Create Separate Partition for /tmp'
	printfailure '1.1.3 - Set nodev option for /tmp Partition'
	printfailure '1.1.4 - Set nosuid option for /tmp Partition'
	printfailure '1.1.5 - Set noexec option for /tmp Partition'
else
	printsuccess '1.1.2 - Create Separate Partition for /tmp'
	i=3
	for option in nodev nosuid noexec; do
		if [ `$GREP [[:space:]]/tmp[[:space:]] /etc/fstab | $GREP -c $option` -eq 0 ]; then
			printfailure "1.1.$i - Set $option option for /tmp Partition"
			$ECHO `$GREP [[:space:]]/tmp[[:space:]] /etc/fstab`
		else
			printsuccess "1.1.$i - Set $option option for /tmp Partition"
		fi
		i=$((i+1))
	done
fi

OUTPUT=
if [ `$GREP -c [[:space:]]/var[[:space:]] /etc/fstab` -eq 0 ]; then
	printfailure '1.1.6 - Create Separate Partition for /var'
else
	printsuccess "1.1.6 - Create Separate Partition for /var"
fi

if [ `$GREP -c [[:space:]]/var/tmp[[:space:]] /etc/fstab` -eq 0 ]; then
	printfailure '1.1.7 - Create Separate Partition for /var/tmp'
else
	printsuccess "1.1.7 - Create Separate Partition for /var/tmp"
	i=8
	for option in nodev nosuid noexec; do
		if [ `$GREP [[:space:]]/var/tmp[[:space:]] /etc/fstab | $GREP -c $option` -eq 0 ]; then
			printfailure "1.1.$i - Set $option option for /var/tmp Partition"
			$ECHO `$GREP [[:space:]]/var/tmp[[:space:]] /etc/fstab`
		else
			printsuccess "1.1.$i - Set $option option for /var/tmp Partition"
		fi
		i=$((i+1))
	done
fi

if [ `$GREP -c [[:space:]]/var/log[[:space:]] /etc/fstab` -eq 0 ]; then
	printfailure '1.1.11 - Create Separate Partition for /var/log'
else
	printsuccess "1.1.11 - Create Separate Partition for /var/log"
fi

if [ `$GREP -c [[:space:]]/var/log/audit[[:space:]] /etc/fstab` -eq 0 ]; then
	printfailure '1.1.12 - Create Separate Partition for /var/log/audit'
else
	printsuccess "1.1.12 - Create Separate Partition for /var/log/audit"
fi

if [ `$GREP -c [[:space:]]/home[[:space:]] /etc/fstab` -eq 0 ]; then
	printfailure '1.1.13 - Create Separate Partition for /home'
	printfailure '1.1.14 - Set nodev option for /home Partition'
else
	printsuccess "1.1.13 - Create Separate Partition for /home"
	if [ `$GREP -c [[:space:]]/home[[:space:]] /etc/fstab | $GREP nodev` -eq 0 ]; then
		printfailure '1.1.14 - Set nodev option for /home Partition'
		$ECHO `$GREP [[:space:]]/home[[:space:]] /etc/fstab`
	else
		printsuccess "1.1.14 - Set nodev option for /home Partition"
	fi
fi

i=15
for option in nodev nosuid noexec; do
	if [ `$GREP [[:space:]]/dev/shm[[:space:]] /etc/fstab | $GREP -c $option` -eq 0 ]; then
		printfailure "1.1.$i - Add $option Option to /dev/shm Partition"
	else
		printsuccess "1.1.$i - Add $option Option to /dev/shm Partition"
	fi
	i=$((i+1))
done

i=18
for option in nodev nosuid noexec; do
	OUTPUT=""
	if [ -z "$OUTPUT" ]; then
		printfailure "1.1.$i - Add $option Option to Removable Media Partitions"
	else
		printsuccess "1.1.$i - Add $option Option to Removable Media Partitions"
	fi
	i=$((i+1))
done

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "1.1.21a - Set Sticky Bit on All World-Writable Directories"
			FIRST=0
		fi
		for file in $OUTPUT; do
			$ECHO $file
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "1.1.21a - Set Sticky Bit on All World-Writable Directories"
fi

FIRST=1
OUTPUT=`$FIND /tmp -xdev -type f -atime +90`
if [ ! -z "$OUTPUT" ]; then
	if [ $FIRST -eq 1 ]; then
		printfailure "1.1.21b - Old files in /tmp"
		FIRST=0
	fi
	for file in $OUTPUT; do
		$ECHO "$file - `$STAT -L '%x' $file`"
	done
fi
if [ $FIRST -eq 1 ]; then
	printsuccess "1.1.21b - Old files in /tmp"
fi

if [ $VERSION -eq 7 ]; then
	if [ `systemctl is-enabled autofs 2>/dev/null | $GREP -c 'enabled'` -eq 1 ]; then
		printfailure "1.1.22 - Disable Automounting"
	else
		printsuccess "1.1.22 - Disable Automounting"
	fi
else # $VERSION -eq 6
	if [ `$CHKCONFIG --list autofs 2>/dev/null | $GREP -c ':on'` -eq 1 ]; then
		printfailure "1.1.22 - Disable Automounting"
	else
		printsuccess "1.1.22 - Disable Automounting"
	fi
fi

printmanualcheck '1.2.1 - Ensure package manager repositories are configured'

if [ `$GREP -c '^gpgcheck=1' /etc/yum.conf` -eq 0 ]; then
	printfailure '1.2.2 - Ensure gpgcheck is globally activated'
else
	printsuccess "1.2.2 - Ensure gpgcheck is globally activated"
fi

if [ `$RPM -qa gpg-pubkey* | $GREP -c '^gpg-pubkey'` -eq 0 ]; then
	printfailure '1.2.3 - Ensure GPG keys are configured'
else
	printsuccess '1.2.3 - Ensure GPG keys are configured'
fi	

if [ `$RPM -q aide | $GREP -c -v 'not installed' 2>/dev/null` -eq 0 ]; then
	printfailure '1.3.1 Install AIDE'
	$RPM -q aide
	printfailure '1.3.2 - Implement Periodic Execution of File Integrity'
	$ECHO "AIDE not installed"
	printfailure '1.3.3 - Initialise AIDE'
	$ECHO "AIDE not installed"
else
	printsuccess "1.3.1 Install AIDE"
	if [ `crontab -u root -l 2>/dev/null | $GREP -E -c 'aide\s+(-C|--check)'` -eq 0 ]; then
		printfailure '1.3.2 - Implement Periodic Execution of File Integrity'
	else
		printsuccess "1.3.2 - Implement Periodic Execution of File Integrity"
	fi
	if [ ! -e /var/lib/aide/aide.db.gz ]; then
		printfailure '1.3.3 - Initialise AIDE'
	else
		printsuccess '1.3.3 - Initialise AIDE'
	fi
fi

if [ `$STAT -L -c "%u %g %c" $GRUB_FILE | $GREP -c -E -v '^0 0 .00$'` -eq 0 ]; then
	printfailure "1.4.1 - Ensure permissions on bootloader config are configured"
else
	printsuccess "1.4.1 Ensure permissions on bootloader config are configured"
fi

if [ $VERSION -eq 7 ]; then
	if [ `$GREP -E -c "^\s*set\s+superusers" $GRUB_FILE` -eq 0 -o \
	     `$GREP -E -c "^\s*password" $GRUB_FILE` -eq 0 ]; then
		printfailure "1.4.2 Set Boot Loader Password"
	else
		printsuccess "1.4.2 Set Boot Loader Password"
	fi
else # $VERSION -eq 6
	if [ `$GREP -E -c "^password" $GRUB_FILE` -eq 0 ]; then
		printfailure "1.4.2 Set Boot Loader Password"
	else
		printsuccess "1.4.2 Set Boot Loader Password"
	fi
fi

if [ $VERSION -eq 7 ]; then
	if [ `$GREP -c "/sbin/sulogin" /usr/lib/systemd/system/rescue.service` -eq 0 -o \
	     `$GREP -c "/sbin/sulogin" /usr/lib/systemd/system/emergency.service` -eq 0 ]; then
		printfailure "1.4.3 - Require Authentication for Single-User Mode"
	else
		printsuccess "1.4.3 - Require Authentication for Single-User Mode"
	fi
else # $VERSION -eq 6
	if [ `$GREP -E -c "^SINGLE" /etc/sysconfig/init` -eq 0 ]; then
		printfailure "1.4.3 - Require Authentication for Single-User Mode"
	else
		printsuccess "1.4.3 - Require Authentication for Single-User Mode"
	fi
fi

if [ `$GREP -E -c "^PROMPT\s*=\s*no" /etc/sysconfig/init` -eq 0 ]; then
	printfailure "1.4.4 -  Ensure interactive boot is not enabled"
else
	printsuccess "1.4.4 -  Ensure interactive boot is not enabled"
fi

if [ `cat /etc/security/limits.conf /etc/security/limits.d/* | $GREP -E -c 'hard[[:space:]]+core[[:space:]]+0'` -eq 0 -o \
     `sysctl fs.suid_dumpable | $GREP -E -c 'fs.suid_dumpable[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure '1.5.1 - Restrict Core Dumps'
else
	printsuccess "1.5.1 - Restrict Core Dumps"
fi

if [ `dmesg | $GREP "NX" | $GREP -c "active"` -eq 0 ]; then
	printfailure '1.5.2 - Ensure XD/NX support is enabled'
else
	printsuccess "1.5.2 - Ensure XD/NX support is enabled"
fi

if [ `sysctl kernel.randomize_va_space | $GREP -c -E 'kernel.randomize_va_space[[:space:]]*=[[:space:]]*2'` -eq 0 ]; then
	printfailure '1.5.3 - Enable Randomized Virtual Memory Region Placement'
else
	printsuccess "1.5.3 - Enable Randomized Virtual Memory Region Placement"
fi

if [ `$RPM -q prelink | $GREP -c "not installed"` -eq 0 ]; then
	printfailure '1.5.4 - Ensure prelink is disabled'
else
	printsuccess "1.5.4 - Ensure prelink is disbaled"
fi

SELINUX=1
if [ $VERSION -eq 7 ]; then
	OUTPUT=`$GREP -E "^\s*linux" $GRUB_FILE | $GREP -E '(selinux|enforcing)=0'`
	if [ -z "$OUTPUT" ]; then
		printfailure "1.6.1.1 - Enable SELinux in ${GRUB_FILE}"
		SELINUX=0
	else
		printsuccess "1.6.1.1 - Enable SELinux in ${GRUB_FILE}"
	fi
else # $VERSION -eq 6
	OUTPUT=`$GREP -E "^\s*kernel" $GRUB_FILE | $GREP -E '(selinux|enforcing)=0'`
	if [ -z "$OUTPUT" ]; then
		printfailure "1.6.1.1 - Enable SELinux in ${GRUB_FILE}"
		SELINUX=0
	else
		printsuccess "1.6.1.1 - Enable SELinux in ${GRUB_FILE}"
	fi
fi

OUTPUT=`$GREP 'SELINUX=enforcing' /etc/selinux/config`
if [ -z "$OUTPUT" ]; then
	printfailure '1.6.1.2 - Set the SELinux State'
	SELINUX=0
else
	printsuccess "1.6.1.2 - Set the SELinux State"
fi

if [ `$GREP -c -E 'SELINUXTYPE=(targeted|mls)' /etc/selinux/config` -eq 0 -a `sestatus | $GREP -E -c "(targeted|mls)"` -eq 0 ]; then
	printfailure '1.6.1.3 - Set the SELinux Policy'
	SELINUX=0
else
	printsuccess "1.6.1.3 - Set the SELinux Policy"
fi

OUTPUT=`$RPM -q setroubleshoot 2>/dev/null | $GREP 'not installed'`
if [ -z "$OUTPUT" ]; then
	printfailure '1.6.1.4 - Remove SETroubleshoot'
else
	printsuccess "1.6.1.4 - Remove SETroubleshoot"
fi

OUTPUT=`$RPM -q mcstrans 2>/dev/null | $GREP 'not installed'`
if [ -z "$OUTPUT" ]; then
	printfailure '1.6.1.5 - Remove MCS Translation Service'
else
	printsuccess "1.6.1.5 - Remove MCS Translation Service"
fi

if [ $SELINUX -eq 0 ]; then
	printfailure "1.6.1.6 - Check for Unconfined Daemons"
	$ECHO "SELinux not used."
else
	OUTPUT=`ps -eZ | $GREP "initrc" | $GREP -E -vw "tr|ps|grep|bash|awk" | tr ':' ' ' | $AWK '{print $NF }'`
	if [ ! -z $OUTPUT ]; then
		printfailure "1.6.1.6 Check for Unconfined Daemons"
		$ECHO $OUTPUT
	else
		printsuccess "1.6.1.6 Check for Unconfined Daemons"
	fi
fi

OUTPUT=`$RPM -q libselinux 2>/dev/null | $GREP 'not installed'`
if [ ! -z "$OUTPUT" ]; then
	printfailure '1.6.2 - Ensure SELinux is installed'
else
	printsuccess "1.6.2 - Ensure SELinux is installed"
fi

i=1
for f in /etc/motd /etc/issue /etc/issue.net; do
	if [ -e $f ]; then
		if [ `$GREP -E -c '(\\\\v|\\\\r|\\\\m|\\\\s)' $f` -ne 0 ]; then
			printfailure "1.7.1.$i - Remove OS Information from $f"
			$GREP -E -c '(\\v|\\r|\\m|\\s)' $f
		else
			printsuccess "1.7.1.$i - Remove OS Information from $f"
		fi
	fi
	i=$((i+1))
done

i=4
for f in /etc/motd /etc/issue /etc/issue.net; do
	if [ -e $f ]; then
		OUTPUT=`$STAT -L -c '%a %u %g' $f | $GREP -v '644 0 0'`
		if [ ! -z "$OUTPUT" ]; then
			printfailure "1.7.2.$i - Ensure permissions on $f are configured"
			$ECHO "$f - $OUTPUT"
		else
			printsuccess "1.7.2.$i - Ensure permissions on $f are configured"
		fi
	fi
done

if [ $OS == "RHEL" ]; then
	if [ $RHEL_VERSION == "5" ]; then
		OUTPUT=`$GREP -v '5.11' /etc/redhat-release`
	elif [ $RHEL_VERSION == "6" ]; then
		OUTPUT=`$GREP -v '6.8' /etc/redhat-release`
	else # Version 7 in use
		OUTPUT=`$GREP -v '7.2' /etc/redhat-release`
	fi
	if [ ! -z "$OUTPUT" ]; then
		printfailure '1.8.1 - Use the Latest OS Release'
		$ECHO $OUTPUT
	else
		printsuccess "1.8.1 - Use the Latest OS Release"
	fi
elif [ $OS == "CentOS" ]; then
	if [ $CentOS_VERSION -eq 7 ]; then
		OUTPUT=`$GREP -v '7.2.' /etc/redhat-release`
	elif [ $CentOS_VERSION -eq 6 ]; then
		OUTPUT=`$GREP -v '6.8' /etc/redhat-release`
	elif [ $CentOS_VERSION -eq 5 ]; then
		OUTPUT=`$GREP -v '5.11' /etc/redhat-release`
	fi
	if [ ! -z "$OUTPUT" ]; then
		printfailure '1.8.1 - Use the Latest OS Release'
		$ECHO $OUTPUT
	else
		printsuccess "1.8.1 - Use the Latest OS Release"
	fi
fi

yum check-update > /dev/null 2>&1
if [ $? -eq 100 ]; then
	printfailure '1.8.2 - Ensure the latest patches have been applied'
else
	printsuccess "1.8.2 - Ensure the latest patches have been applied"
fi

i=1
for legacy_service in chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram \
    time-stream rexec rlogin rsh talk telnet tftp rsync; do
	OUTPUT=`$CHKCONFIG --list $legacy_service 2>/dev/null | $GREP ':on'`
	if [ ! -z "$OUTPUT" ]; then
		printfailure "2.1.$i - Disable $legacy_service"
		$ECHO $OUTPUT
	else
		printsuccess "2.1.$i - Disable $legacy_service"
	fi
	i=$((i+1))
done

if [ $VERSION -eq 7 ]; then
	if [ `systemctl is-enabled xinetd 2>/dev/null | $GREP -c -v "disabled"` -ne 0 ]; then
		printfailure "2.1.$i - Disable xinetd"
	else
		printsuccess "2.1.$i - Disable xinetd"
	fi
else # $VERSION -eq 6
	if [ `$CHKCONFIG --list $legacy_service 2>/dev/null | $GREP -c ':on'` -eq 1 ]; then
		printfailure "2.1.$i - Disable xinetd"
	else
		printsuccess "2.1.$i - Disable xinetd"
	fi
fi

NTP_INSTALLED=0
if [ `$RPM -q ntp | $GREP -c "not installed"` -eq 1 -a `$RPM -q chrony | $GREP -c "not installed"` -eq 1 ]; then
	printfailure "2.2.1.1 - Ensure time synchronisation is in use"
	$RPM -q ntp; $RPM -q chrony
else
	printsuccess "2.2.1.1 - Ensure time synchronisation is in use"
fi

if [ `$RPM -q ntp | $GREP -c "not installed"` -eq 0 ]; then
	FIRST=1
	if [ `$GREP -E -c "restrict[[:space:]]+(-[[:space:]]+)?default" /etc/ntp.conf` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "2.2.1.2 - Configure Network Time Protocol"
			FIRST=0
		fi
		$ECHO "Access to NTP service not restricted."
	fi
	if [ `$GREP -E -c "^server[[:space:]]+" /etc/ntp.conf` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "2.2.1.2 - Configure Network Time Protocol"
			FIRST=0
		fi
		$ECHO "Remote servers not defined."
	fi
	if [ `$GREP -E "^OPTIONS" /etc/ntp.conf | $GREP -E -c -e "-u ntp:ntp"` -eq 0 -a \
	     `$GREP -E "^ExecStart" /usr/lib/systemd/system/ntpd.service | $GREP -E -c -e "-u ntp:ntp"` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "2.2.1.2 - Configure Network Time Protocol"
			FIRST=0
		fi
		$ECHO "NTP user not defined."
	fi
	if [ $FIRST -eq 1 ]; then
		printsuccess "2.2.1.2 - Configure Network Time Protocol"
	fi
else
	printfailure "2.2.1.2 - Configure Network Time Protocol"
	$ECHO "NTP not installed."
fi

if [ `$RPM -q chrony | $GREP -c "not installed"` -eq 0 ]; then
	FIRST=1
	if [ `$GREP -E -c "^server" /etc/chrony.conf` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "2.2.1.3 - Ensure chrony is configured"
			FIRST=0
		fi
		$ECHO "Remote servers not defined."
	fi
	if [ `$GREP -E "^OPTIONS=" /etc/sysconfig/chronyd 2>/dev/null | $GREP -E -c -e "-u chrony"` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "2.2.1.3 - Ensure chrony is configured"
			FIRST=0
		fi
		$ECHO "Chrony user not defined."
	fi
	if [ $FIRST -eq 1 ]; then
		printsuccess "2.2.1.3 - Ensure chrony is configured"
	fi
else
	printfailure "2.2.1.3 - Ensure chrony is configured"
	$ECHO "Chrony not installed"
fi

if [ `$RPM -qa xorg-x11* 2>/dev/null | $GREP -c "xorg-x11"` -eq 0 ]; then
	printfailure "2.2.2 - Ensure X Window System is not installed"
else
	printsuccess "2.2.2 - Ensure X Window System is not installed"
fi

i=3
for legacy_service in avahi-daemon cups dhcp slapd nfs rpcbind named vsftp httpd dovecot smb squid snmpd ypserv; do
	if [ $VERSION -eq 7 ]; then
		if [ `systemctl is-enabled $legacy_service 2>/dev/null | $GREP -c "enabled"` -eq 1 ]; then
			printfailure "2.2.$i - Ensure $legacy_service is not enabled"
		else
			printsuccess "2.2.$i - Ensure $legacy_service is not enabled"
		fi
	else # $VERSION -eq 6
		if [ `$CHKCONFIG --list $legacy_service 2>/dev/null | $GREP -c ':on'` -eq 1 ]; then
			printfailure "2.2.$i - Ensure $legacy_service is not enabled"
		else
			printsuccess "2.2.$i - Ensure $legacy_service is not enabled"
		fi
	fi
	i=$((i+1))
done;

if [ `netstat -an | $GREP LISTEN | $GREP ":25[[:space:]]" | $GREP -E -v -c "(127.0.0.1|localhost|::1):25"` -ne 0 -o \
     `$GREP -E '^inet_interfaces' /etc/postfix/main.cf | $GREP -c 'localhost'` -ne 1 ]; then
	printfailure "2.2.15 - Configure Mail Transfer Agent for Local-Only Mode"
	netstat -an | $GREP LISTEN | $GREP ":25[[:space:]]" | $GREP -E -v -c "(127.0.0.1|localhost|::1):25"
else
	printsuccess "2.2.15 - Configure Mail Transfer Agent for Local-Only Mode"
fi

i=1
for service_client in ypbind rsh talk telnet openldap-clients; do
	if [ `$RPM -q $service_client 2>/dev/null | $GREP "$service_client" | $GREP -c "not installed"` -eq 0 ]; then
		printfailure "2.3.$i - Ensure $service_client is not installed"
		$RPM -q $service_client
	else
		printsuccess "2.3.$i - Ensure $service_client is not installed"
	fi
	i=$((i+1))
done;

if [ `sysctl net.ipv4.ip_forward | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.1.1 - Disable IP Forwarding"
else
	printsuccess "3.1.1 - Disable IP Forwarding"
fi

if [ `sysctl net.ipv4.conf.all.send_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv4.conf.default.send_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.1.2 - Disable Send Packet Redirects"
else
	printsuccess "3.1.2 - Disable Send Packet Redirects"
fi

if [ `sysctl net.ipv4.conf.all.accept_source_route | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv4.conf.default.accept_source_route | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.2.1 - Disable Source Routed Packet Acceptance"
else
	printsuccess "3.2.1 - Disable Source Routed Packet Acceptance"
fi

if [ `sysctl net.ipv4.conf.all.accept_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv4.conf.default.accept_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.2.2 - Disable ICMP Redirect Acceptance"
else
	printsuccess "3.2.2 - Disable ICMP Redirect Acceptance"
fi

if [ `sysctl net.ipv4.conf.all.secure_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv4.conf.all.secure_redirects | $GREP -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.2.3 - Disable Secure ICMP Redirect Acceptance"
else
	printsuccess "3.2.3 - Disable Secure ICMP Redirect Acceptance"
fi

if [ `sysctl net.ipv4.conf.all.log_martians | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 -o \
     `sysctl net.ipv4.conf.default.log_martians | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 ]; then
	printfailure "3.2.4 - Log Suspicious Packets"
else
	printsuccess "3.2.4 - Log Suspicious Packets"
fi

if [ `sysctl  net.ipv4.icmp_echo_ignore_broadcasts | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 ]; then
	printfailure "3.2.5 - Enable Ignore Broadcast Requests"
else
	printsuccess "3.2.5 - Enable Ignore Broadcast Requests"
fi

if [ `sysctl net.ipv4.icmp_ignore_bogus_error_responses | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 ]; then
	printfailure "3.2.6 - Enable Bad Error Message Protection"
else
	printsuccess "3.2.6 - Enable Bad Error Message Protection"
fi

if [ `sysctl net.ipv4.conf.all.rp_filter | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 -o \
     `sysctl net.ipv4.conf.default.rp_filter | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 ]; then
	printfailure "3.2.7 - Enable RFC-recommended Source Route Validation"
else
	printsuccess "3.2.7 - Enable RFC-recommended Source Route Validation"
fi

if [ `sysctl net.ipv4.tcp_syncookies | $GREP -c '[[:space:]]*=[[:space:]]*1'` -eq 0 ]; then
	printfailure "3.2.8 - Enable TCP SYN Cookies"
else
	printsuccess "3.2.8 - Enable TCP SYN Cookies"
fi

if [ `sysctl net.ipv6.conf.all.accept_ra | $GREP -v -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv6.conf.default.accept_ra | $GREP -v -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.3.1 - Disable IPv6 Router Advertisements"
else
	printsuccess "3.3.1 - Disable IPv6 Router Advertisements"
fi

if [ `sysctl net.ipv6.conf.all.accept_redirects | $GREP -v -c '[[:space:]]*=[[:space:]]*0'` -eq 0 -o \
     `sysctl net.ipv6.conf.default.accept_redirects | $GREP -v -c '[[:space:]]*=[[:space:]]*0'` -eq 0 ]; then
	printfailure "3.3.2 - Disable IPv6 Redirect Acceptance"
else
	printsuccess "3.3.2 - Disable IPv6 Redirect Acceptance"
fi

if [ `$MODPROBE -c | $GREP 'ipv6' | $GREP -c 'disable=1'` -eq 0 ]; then
	printfailure "3.3.3 - Disable IPv6"
else
	printsuccess "3.3.3 - Disable IPv6"
fi

OUTPUT=`$RPM -q tcp_wrappers 2>/dev/null | $GREP 'not installed'`
if [ ! -z "$OUTPUT" ]; then
	printfailure "3.4.1 - Install TCP Wrappers"
	$ECHO "$OUTPUT"
else
	printsuccess "3.4.1 - Install TCP Wrappers"
fi

if [ ! -e /etc/hosts.allow ]; then
	printfailure "3.4.2 - Create /etc/hosts.allow"
	printfailure "3.4.3 - Verify Permissions on /etc/hosts.allow"
else
	printsuccess "3.4.2 - Create /etc/hosts.allow"
	OUTPUT=`$STAT -L -c '%a' /etc/hosts.allow | $GREP -v 644`
	if [ ! -z "$OUTPUT" ]; then
		printfailure "3.4.3 - Verify Permissions on /etc/hosts.allow"
		$ECHO "$OUTPUT"
	else
		printsuccess "3.4.3 - Verify Permissions on /etc/hosts.allow"
	fi
fi

if [ ! -e /etc/hosts.deny ]; then
	printfailure "3.4.4 - Create /etc/hosts.deny"
	printfailure "3.4.5 - Verify Permissions on /etc/hosts.deny"
else
	OUTPUT=`$GREP "ALL: ALL" /etc/hosts.deny`
	if [ -z "$OUTPUT" ]; then
		printfailure "3.4.4 - Create /etc/hosts.deny"
		$ECHO "TCP Wrappers not configured to block all traffic not explicitly permitted in /etc/hosts.allow."
	else
		printsuccess "3.4.4 - Create /etc/hosts.deny"
	fi
	OUTPUT=`$STAT -L -c '%a' /etc/hosts.deny | $GREP -v 644`
	if [ ! -z "$OUTPUT" ]; then
		printfailure "3.4.5 - Verify Permissions on /etc/hosts.deny"
		$ECHO "$OUTPUT"
	else
		printsuccess "3.4.5 - Verify Permissions on /etc/hosts.deny"
	fi
fi

i=1
for np in dccp sctp rds tipc ; do
	if [ ! \( `$LSMOD | $GREP -c $np` -eq 0 -a \
	     \( `$MODPROBE -n -v $np 2>/dev/null | $GREP -E -c "."` -eq 0 -o `$MODPROBE -n -v $np 2>/dev/null | $GREP -c "install /bin/true"` -eq 1 \) \) ]; then
		printfailure "3.5.$i - Disable $np"
	else
		printsuccess "3.5.$i - Disable $np"
	fi
	i=$((i+1))
done

if [ `$RPM -q iptables | $GREP -c "not installed"` -eq 1 ]; then
	printfailure '3.6.1 - Ensure iptables is enabled'
	printfailure '3.6.2 - Ensure default deny firewall policy for incoming and outgoing traffic'
	printfailure '3.6.3 - Ensure loopback traffic is configured'
	printfailure '3.6.4 - Ensure outbound and established connections are configured'
	printfailure "3.6.5 - Ensure firewall rules exist for all open ports"
else
	printsuccess "3.6.1 - Ensure iptables is enabled"

	if [ `iptables -L | $GREP -E "Chain (INPUT|OUTPUT) \(policy" | $GREP -v -c "DROP"` -ne 0 ]; then
		printfailure '3.6.2 - Ensure default deny firewall policy for incoming and outgoing traffic'
	else
		printsuccess "3.6.2 - Ensure default deny firewall policy for incoming and outgoing traffic"
	fi

	if [ `iptables -L INPUT -v | $GREP -c '[[:space:]]lo[[:space:]]'` -lt 1 -o `iptables -L OUTPUT -v | $GREP -c '[[:space:]]lo[[:space:]]'` -lt 1 ]; then
		printfailure '3.6.3 - Ensure loopback traffic is configured'
	else
		printsuccess "3.6.3 - Ensure loopback traffic is configured"
	fi

	if [ `iptables -L INPUT -v | $GREP -E -c '\sACCEPT\s.*state\s+RELATED,ESTABLISHED'` -eq 0 -o \
	     `iptables -L OUTPUT -v | $GREP -E -c '\sACCEPT\s.*state\s+NEW,RELATED,ESTABLISHED'` -eq 0 ]; then
		printfailure '3.6.4 - Ensure outbound and established connections are configured'
	else
		printsuccess '3.6.4 - Ensure outbound and established connections are configured'
	fi

	# Only looks at TCP connections at the moment.
	FIRST=1
	netstat -lnt --protocol inet | $GREP -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | $GREP -E -v "127\.0\.0\.1:" | $AWK '{ print $4 }' | $AWK -F: '{ print $1 " " $2 }' | while read local_ip local_port; do
		if [ `iptables -n -L INPUT | $GREP -E -c "^ACCEPT.*tcp dpt:$local_port"` -eq 0 ]; then
			if [ $FIRST -eq 1 ]; then
				printfailure "3.6.5 - Ensure firewall rules exist for all open ports"
				FIRST=0
			fi
			echo "No rule configured to explicitly allow TCP port $local_port"
		fi
	done
	if [ $FIRST -eq 1 ]; then
		printsuccess "3.6.5 - Ensure firewall rules exist for all open ports"
	fi
fi
	

if [ `which iwconfig 2>/dev/null | $GREP -E -c '.'` -ne 0 ]; then
	printfailure '3.7 - Ensure wireless interfaces are disabled'
else
	printsuccess "3.7 - Ensure wireless interfaces are disabled"
fi

if [ `ifconfig | $GREP -E -c '\s+PROMISC\s+'` -ne 0 ]; then
	printfailure '3.8 - Ensure no interfaces are in promiscuous mode'
else
	printsuccess '3.8 - Ensure no interfaces are in promiscuous mode'
fi

if [ `$GREP -E -c 'max_log_file[[:space:]]*=[[:space:]]([1-9]|10)*' /etc/audit/auditd.conf` -eq 0 ]; then
	printfailure '4.1.1.1 - Ensure audit log storage size is configured'
else
	printsuccess "4.1.1.1 - Ensure audit log storage size is configured"
fi

if [ `$GREP -E -c 'space_left_action[[:space:]]*=[[:space:]]*[Ee][Mm][Aa][Ii][Ll]' /etc/audit/auditd.conf` -eq 0 -o \
     `$GREP -E -c 'action_mail_acct[[:space:]]*=[[:space:]]*root' /etc/audit/auditd.conf` -eq 0 -o \
     `$GREP -E -c 'admin_space_left_action[[:space:]]*=[[:space:]]*[Hh][Aa][Ll][Tt]' /etc/audit/auditd.conf` -eq 0 ]; then
	printfailure '4.1.1.2 - Ensure system is disabled when audit logs are full'
else
	printsuccess "4.1.1.2 - Ensure system is disabled when audit logs are full"
fi

if [ `$GREP -c 'max_log_file_action[[:space:]]*=[[:space:]]*[Kk][Ee][Ee][Pp]_[Ll][Oo][Gg][Ss]' /etc/audit/auditd.conf` -eq 0 ]; then
	printfailure '4.1.1.3 - Ensure audit logs are not automatically deleted'
else
	printsuccess '4.1.1.3 - Ensure audit logs are not automatically deleted'
fi

if [ $VERSION -eq 7 ]; then
	if [ `systemctl is-enabled auditd 2>/dev/null | $GREP -c "enabled"` -eq 0 ]; then
		printfailure '4.1.2 - Ensure auditd service is enabled'
	else
		printsuccess "4.1.2 - Ensure auditd service is enabled"
	fi
else # $VERSION -eq 6
	if [ `$CHKCONFIG --list auditd 2>/dev/null | $GREP -c ":on"` -eq 0 ]; then
		printfailure '4.1.2 - Ensure auditd service is enabled'
	else
		printsuccess "4.1.2 - Ensure auditd service is enabled"
	fi
fi

if [ $VERSION -eq 7 ]; then
	if [ `$GREP -E '^\s*linux' $GRUB_FILE | $GREP -E -c 'audit\s*=\s*1'` -eq 0 ]; then
		printfailure '4.1.3 - Ensure auditing for processes that start prior to auditd is enabled'
	else
		printsuccess "4.1.3 - Ensure auditing for processes that start prior to auditd is enabled"
	fi
else
	if [ `$GREP -E '^\s*kernel' $GRUB_FILE | $GREP -E -c 'audit\s*=\s*1'` -eq 0 ]; then
		printfailure '4.1.3 - Ensure auditing for processes that start prior to auditd is enabled'
	else
		printsuccess "4.1.3 - Ensure auditing for processes that start prior to auditd is enabled"
	fi
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.4 - Ensure events that modify date and time information are collected'
	else
		printsuccess "4.1.4 - Ensure events that modify date and time information are collected"
	fi
else
	if [ `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.4 - Ensure events that modify date and time information are collected'
	else
		printsuccess "4.1.4 - Ensure events that modify date and time information are collected"
	fi
fi

if [ `$GREP -c -E -e '-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity' /etc/audit/audit.rules` -eq 0 -o \
     `$GREP -c -E -e '-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity' /etc/audit/audit.rules` -eq 0 -o \
	 `$GREP -c -E -e '-w\s+/etc/gshadow\s+-p\s+wa\s+-k\s+identity' /etc/audit/audit.rules` -eq 0 -o \
	 `$GREP -c -E -e '-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity' /etc/audit/audit.rules` -eq 0 -o \
	 `$GREP -c -E -e '-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.5 - Ensure events that modify user/group information are collected'
else
	printsuccess "4.1.5 - Ensure events that modify user/group information are collected"
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b64\s+-S sethostname\s+-S\s+setdomainname\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S sethostname\s+-S\s+setdomainname\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.6 Ensure events that modify the  network environment are collected'
	else
		printsuccess '4.1.6 Ensure events that modify the  network environment are collected'
	fi
else
	if [ `$GREP -c -E -e '-a\s+always,exit\s+-F\s+arch=b32\s+-S sethostname\s+-S\s+setdomainname\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/issue\s+\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 -o \
		 `$GREP -c -E -e '-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.6 Ensure events that modify the  network environment are collected'
	else
		printsuccess '4.1.6 Ensure events that modify the  network environment are collected'
	fi
fi

if [ `$GREP -c -E -e '-w\s+/etc/selinux/\s+-p\s+wa\s+-k\s+MAC-policy' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.7 Ensure events that modify the Mandatory Access Controls are collected'
else
	printsuccess '4.1.7 Ensure events that modify the Mandatory Access Controls are collected'
fi

if [ `$GREP -c -E -e '-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins' /etc/audit/audit.rules` -eq 0 -o \
     `$GREP -c -E -e '-w\s+/var/run/faillock/\s+-p\s+wa\s+-k\s+logins' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.8 Ensure login and logout events are collected'
else
	printsuccess '4.1.8 Ensure login and logout events are collected'
fi

if [ `$GREP -c -E -e '-w\s+/var/run/utmp\s+-p\s+wa\s+-k\s+session' /etc/audit/audit.rules` -eq 0 -o \
     `$GREP -c -E -e '-w\s+/var/log/wtmp\s+-p\s+wa\s+-k\s+session' /etc/audit/audit.rules` -eq 0 -o \
	 `$GREP -c -E -e '-w\s+/var/log/btmp\s+-p\s+wa\s+-k\s+session' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.9 Ensure session initiation information is collected'
else
	printsuccess '4.1.9 Ensure session initiation information is collected'
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.10 Ensure discretionary access control permission modification events are collected'
	else
		printsuccess '4.1.10 Ensure discretionary access control permission modification events are collected'
	fi
else
	if [ `$GREP -c -E -e "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.10 Ensure discretionary access control permission modification events are collected'
	else
		printsuccess '4.1.10 Ensure discretionary access control permission modification events are collected'
	fi
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.11 Ensure unsuccessful unauthorized file access attempts are collected'
	else
		printsuccess '4.1.11 Ensure unsuccessful unauthorized file access attempts are collected'
	fi
else
	if [ `$GREP -c -E -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k access" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.11 Ensure unsuccessful unauthorized file access attempts are collected'
	else
		printsuccess '4.1.11 Ensure unsuccessful unauthorized file access attempts are collected'
	fi
fi

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -type f \( -perm -4000 -o -perm -2000 \) -perm /u+x,g+x,o+x -print 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		for file in $OUTPUT; do
			if [ `$GREP -E -c -e "-a always,exit -F path=$file -F perm=x -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k privileged" /etc/audit/audit.rules` -eq 0 ]; then
				if [ $FIRST -eq 1 ]; then
					printfailure "4.1.12 Ensure use of privileged commands is collected"
					FIRST=0
				fi
				$ECHO "$file not monitored"
			fi
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "4.1.12 Ensure use of privileged commands is collected"
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e "-a always,exit -F arch=b64 -S mount -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k mounts" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S mount -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k mounts" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.13 Ensure successful file system mounts are collected'
	else
		printsuccess '4.1.13 Ensure successful file system mounts are collected'
	fi
else
	if [ `$GREP -c -E -e "-a always,exit -F arch=b32 -S mount -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k mounts" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.13 Ensure successful file system mounts are collected'
	else
		printsuccess '4.1.13 Ensure successful file system mounts are collected'
	fi
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k delete" /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k delete" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.14 Ensure file deletion events by users are collected'
	else
		printsuccess '4.1.14 Ensure file deletion events by users are collected'
	fi
else
	if [ `$GREP -c -E -e "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MAX_SYSTEM_UID -F auid!=4294967295 -k delete" /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.14 Ensure file deletion events by users are collected'
	else
		printsuccess '4.1.14 Ensure file deletion events by users are collected'
	fi
fi

if [ `$GREP -c -E -e '-w /etc/sudoers -p wa -k scope' /etc/audit/audit.rules` -eq 0 -o \
     `$GREP -c -E -e '-w /etc/sudoers.d -p wa -k scope' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.15 Ensure changes to system administration scope (sudoers) is collected'
else
	printsuccess '4.1.15 Ensure changes to system administration scope (sudoers) is collected'
fi

if [ `$GREP -c -E -e '-w /var/log/sudo.log -p wa -k actions' /etc/audit/audit.rules` -eq 0 ]; then
	printfailure '4.1.16 Ensure system administrator actions (sudolog) are collected'
else
	printsuccess '4.1.16 Ensure system administrator actions (sudolog) are collected'
fi

if [ `uname -m | $GREP -c 'x86_64'` -eq 1 ]; then
	if [ `$GREP -c -E -e '-w /sbin/insmod -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-w /sbin/rmmod -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-w /sbin/modprobe -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-a always,exit arch=b64 -S init_module -S delete_module -k modules' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.17 Ensure kernel module loading and unloading is collected'
	else
		printsuccess '4.1.17 Ensure kernel module loading and unloading is collected'
	fi
else
	if [ `$GREP -c -E -e '-w /sbin/insmod -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-w /sbin/rmmod -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-w /sbin/modprobe -p x -k modules' /etc/audit/audit.rules` -eq 0 -o \
	     `$GREP -c -E -e '-a always,exit arch=b32 -S init_module -S delete_module -k modules' /etc/audit/audit.rules` -eq 0 ]; then
		printfailure '4.1.17 Ensure kernel module loading and unloading is collected'
	else
		printsuccess '4.1.17 Ensure kernel module loading and unloading is collected'
	fi
fi

if [ `tail -n 1 /etc/audit/audit.rules | $GREP -c -E -e '-e\s+2'` -eq 0 ]; then
	printfailure '4.1.18 Ensure the audit configuration is immutable'
else
	printsuccess '4.1.18 Ensure the audit configuration is immutable'
fi

if [ $VERSION -eq 7 ]; then
	if [ `systemctl is-enabled rsyslog 2>/dev/null | $GREP -c "enabled"` -eq 0 ]; then
		printfailure '4.2.1.1 Ensure rsyslog Service is enabled'
	else
		printsuccess "4.2.1.1 Ensure rsyslog Service is enabled"
	fi
else # $VERSION -eq 6
	if [ `$CHKCONFIG --list rsyslog 2>/dev/null | $GREP -c ":on"` -eq 0 ]; then
		printfailure '4.2.1.1 Ensure rsyslog Service is enabled'
	else
		printsuccess "4.2.1.1 Ensure rsyslog Service is enabled"
	fi
fi

$ECHO "4.2.1.2 Ensure logging is configured - MANUAL CHECK"

if [ `$GREP -E -c "^.FileCreateMode\s+0640" /etc/rsyslog.conf` -eq 0 ]; then
	printfailure '4.2.1.3 Ensure rsyslog default file permissions configured'
else
	printsuccess '4.2.1.3 Ensure rsyslog default file permissions configured'

fi

if [ `$GREP -E -c "^\s*[^#].*@@" /etc/rsyslog.conf` -eq 0 ]; then
	printfailure "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
else
	printsuccess "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
fi

if [ `$GREP -E ".ModLoad\s+imtcp" /etc/rsyslog.conf | $GREP -E -v -c "\s*#"` -gt 0 -o `$GREP -E ".InputTCPServerRun\s+" /etc/rsyslog.conf | $GREP -E -v -c "\s*#"` -gt 0 ]; then
	printfailure "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated hosts"
else
	printsuccess "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated hosts"
fi

$ECHO "TODO!!! Logrotate stuff"

if [ $VERSION -eq 7 ]; then
	if [ `systemctl is-enabled crond | $GREP -c 'enabled'` -eq 0 ]; then
		printfailure '5.1.1 - Enable cron Daemon'
		systemctl is-enabled crond
	else
		printsuccess "5.1.1 - Enable cron Daemon"
	fi
else # $VERSION -eq 6
	if [ `$CHKCONFIG --list crond 2>/dev/null | $GREP -c ":on"` -eq 0 ]; then
		printfailure '5.1.1 - Enable cron Daemon'
	else
		printsuccess '5.1.1 - Enable cron Daemon'
	fi
fi

i=2
for file in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
	if [ -e $file ]; then
		OUTPUT=`$STAT -L -c '%a %u %g' $file | $GREP -E -v '.00 0 0'`
		if [ ! -z "$OUTPUT" ]; then
			printfailure "5.1.$i - Set User/Group Owner and Permission on $file"
			$ECHO $OUTPUT
		else
			printsuccess "5.1.$i - Set User/Group Owner and Permission on $file"
		fi
	fi
	i=$((i+1))
done

i=8
for daemon in at cron; do
	if [ -e /etc/$daemon.deny ]; then
		printfailure "5.1.$i - Restrict $daemon Daemon"
		$ECHO "/etc/$daemon.deny `$STAT -L -c '%a %u %g' /etc/$daemon.deny`"
	else
		printsuccess "5.1.$i - Restrict $daemon Daemon"
	fi
	if [ -e /etc/$daemon.allow ]; then
		OUTPUT=`$STAT -L -c '%a %u %g' /etc/$daemon.allow | $GREP -E -v '.00 0 0'`
		if [ ! -z "$OUTPUT" ]; then
			printfailure '5.1.$i - Restrict $daemon Daemon'
			$ECHO "/etc/$daemon.allow $OUTPUT"
		else
			printsuccess "5.1.$i - Restrict $daemon Daemon"
		fi
	fi
	i=$((i+1))
done

if [ -e /etc/ssh/sshd_config ]; then
	OUTPUT=`$STAT -L -c '%a %u %g' /etc/ssh/sshd_config | $GREP -E -v '600 0 0'`
	if [ ! -z "$OUTPUT" ]; then
		printfailure '5.2.1 - Permissions on /etc/ssh/sshd_config'
		$ECHO $OUTPUT
	else
		printsuccess "5.2.1 - Permissions on /etc/ssh/sshd_config"
	fi

	OUTPUT=`$GREP '^Protocol' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP '^2$'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.2 - Set SSH Protocol to 2'
	else
		printsuccess "5.2.2 - Set SSH Protocol to 2"
	fi

	OUTPUT=`$GREP '^LogLevel' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^(INFO|VERBOSE)$'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.3 - Set LogLevel to INFO'
	else
		printsuccess "5.2.3 - Set LogLevel to INFO"
	fi

	OUTPUT=`$GREP '^X11Forwarding' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP 'no'`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.4 - Disable SSH X11 Forwarding"
	else
		printsuccess "5.2.4 - Disable SSH X11 Forwarding"
	fi

	OUTPUT=`$GREP '^MaxAuthTries' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^[0-4]$'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.5 - Set SSH MaxAuthTries to 4 or Less'
	else
		printsuccess "5.2.5 - Set SSH MaxAuthTries to 4 or Less"
	fi

	OUTPUT=`$GREP '^IgnoreRhosts' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E 'yes'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.6 - Set SSH IgnoreRhosts to Yes'
	else
		printsuccess "5.2.6 - Set SSH IgnoreRhosts to Yes"
	fi

	OUTPUT=`$GREP '^HostbasedAuthentication' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E 'no'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.7 - Set SSH HostbasedAuthentication to No'
	else
		printsuccess "5.2.7 - Set SSH HostbasedAuthentication to No"
	fi

	OUTPUT=`$GREP '^PermitRootLogin' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '(no|without-password|forced-commands-only)'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.8 - Disbale SSH Root Login'
	else
		printsuccess "5.2.8 - Disbale SSH Root Login"
	fi

	OUTPUT=`$GREP '^PermitEmptyPasswords' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E 'no'`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.9 - Set SSH PermitEmptyPasswords to No"
	else
		printsuccess "5.2.9 - Set SSH PermitEmptyPasswords to No"
	fi

	OUTPUT=`$GREP '^PermitUserEnvironment' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E 'no'`
	if [ -z "$OUTPUT" ]; then
		printfailure '5.2.10 - Do Not Allow Users to Set Environment Options'
	else
		printsuccess "5.2.10 - Do Not Allow Users to Set Environment Options"
	fi

	OUTPUT=`$GREP -E '^Ciphers' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^(aes128-ctr((,aes192-ctr)?(,aes256-ctr)?)|((,aes256-ctr)?(,aes192-ctr)?))|(aes192-ctr((,aes128-ctr)?(,aes256-ctr)?)|((,aes256-ctr)?(,aes128-ctr)?))|(aes256-ctr((,aes192-ctr)?(,aes128-ctr)?)|((,aes128-ctr)?(,aes192-ctr)?))$'`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.11 - Use Only Approved Cipher in Counter Mode"
	else
		printsuccess "5.2.11 - Use Only Approved Cipher in Counter Mode"
	fi

	OUTPUT=`$GREP -E '^MACs' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^(?:hmac-sha2-512-etm@openssh.com)?[,]?(?:hmac-sha2-256-etm@openssh.com)?[,]?(?:umac-128-etm@openssh.com)?[,]?(?:hmac-sha2-512)?[,]?(?:hmac-sha2-256)?[,]?(?:umac-128@openssh.com)?[,]?(?:curve25519-sha256@libssh.org)?[,]?(?:diffie-hellman-group-exchange-sha256)?'`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.12 - Ensure only approved MAC algorithms are used"
	else
		printsuccess "5.2.12 - Ensure only approved MAC algorithms are used"
	fi

	OUTPUT=`$GREP '^ClientAliveInterval' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^([6-9][0-9]|^[1-2][0-9][0-9]$|^300$)$'`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.13a - Set Idle Timeout Interval for User Login"
	else
		printsuccess "5.2.13a - Set Idle Timeout Interval for User Login"
	fi

	OUTPUT=`$GREP '^ClientAliveCountMax' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^[0-3]$'`
	if [ -z "$OUTPUT" ];then
		printfailure "5.2.13b - Set Idle Timeout Interval for User Login"
	else
		printsuccess "5.2.13b - Set Idle Timeout Interval for User Login"
	fi

	OUTPUT=`$GREP '^LoginGraceTime' /etc/ssh/sshd_config | $AWK '{print $2}' | $GREP -E '^(60|1m)$'`
	if [ -z "$OUTPUT" ];then
		printfailure "5.2.14 - Ensure SSH LoginGraceTime is set to to one minute or less"
	else
		printsuccess "5.2.14 - Ensure SSH LoginGraceTime is set to to one minute or less"
	fi

	OUTPUT=`$GREP -E '^(AllowUsers|AllowGroups|DenyUsers|DenyGroups)' /etc/ssh/sshd_config`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.15 - Limit Access via SSH"
	else
		printsuccess "5.2.15 - Limit Access via SSH"
	fi

	OUTPUT=`$GREP '^Banner' /etc/ssh/sshd_config`
	if [ -z "$OUTPUT" ]; then
		printfailure "5.2.16 - Set SSH Banner"
	else
		printsuccess "5.2.16 - Set SSH Banner"
	fi
fi

if [ `$GREP -c 'pam_pwquality.so' /etc/pam.d/password-auth` -eq 0 -o \
     `$GREP -c 'pam_pwquality.so' /etc/pam.d/system-auth` -eq 0 -o \
	 `$GREP -E -c '^minlen[[:space:]]*=[[:space:]]*(1[2-9]|[2-9][0-9]|\d{3,})' /etc/security/pwquality.conf` -eq 0 -o \
	 `$GREP -E -c -e '^(d|l|o|u)credit[[:space:]]*=[[:space:]]*-[1-9][0-9]*' /etc/security/pwquality.conf` -lt 4 ]; then
	printfailure "5.3.1 - Ensure password creation requirements are configured"
else
	printsuccess "5.3.1 - Ensure password creation requirements are configured"
fi

if [ `$GREP -c 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/password-auth` -eq 0 -o \
     `$GREP -c 'auth [success=1 default=bad] pam_unix.so' /etc/pam.d/password-auth` -eq 0 -o \
	 `$GREP -c 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/password-auth` -eq 0 -o \
	 `$GREP -c 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900' /etc/pam.d/password-auth` -eq 0 ]; then
	printfailure "5.3.2 - Ensure lockout for failed password attempts is configured"
else
	printsuccess "5.3.2 - Ensure lockout for failed password attempts is configured"
fi

if [ `$GREP -E -c '^password\s+sufficient\s+pam_unix.so.*remember[[:space:]]*=[[:space:]]*([5-9]|[1-9][0-9]*)' /etc/pam.d/password-auth` -eq 0 -o \
     `$GREP -E -c '^password\s+sufficient\s+pam_unix.so.*remember[[:space:]]*=[[:space:]]*([5-9]|[1-9][0-9]*)' /etc/pam.d/system-auth` -eq 0 ]; then
	printfailure "5.3.3 - Ensure password reuse is limited"
else
	printsuccess "5.3.3 - Ensure password reuse is limited"
fi

if [ `authconfig --test | $GREP 'hashing' | $GREP -c 'sha512'` -eq 0 ]; then
	printfailure "5.3.4 - Upgrade Password Hashing Algorithm to SHA-512"
else
	FIRST=1
	$AWK -F: '{ print $1 " " $2 }' /etc/shadow | while read user password_hash; do
		if [ `$ECHO $password_hash | $GREP -E -c "^\$[125]\$"` -eq 1  ]; then
			if [ $FIRST -eq 1 ]; then
				printfailure "5.3.4 - Upgrade Password Hashing Algorithm to SHA-512"
				FIRST=0
			fi
			$ECHO "The password hash for $user was not generated using SHA-512"
		fi
	done
fi
if [ $FIRST -eq 1 ]; then
	printsuccess "5.3.4 - Upgrade Password Hashing Algorithm to SHA-512"
fi

FIRST=1
OUTPUT=`$GREP '^PASS_MAX_DAYS' /etc/login.defs`
if [ `$ECHO $OUTPUT | $AWK '{print $2}' | $GREP -E -c '(^[0-9]$|^[1-8][0-9]$|^90$)'` -eq 0 ]; then
	printfailure "5.4.1.1 - Set Password Expiration Days"
	$ECHO $OUTPUT
	FIRST=0
fi
$AWK -F: '{ print $1 " " $3 }' /etc/passwd | while read user uid; do
	if [ $uid -ge $MAX_SYSTEM_UID -a $user != "nfsnobody" -a `chage --list $user | $GREP '^Maximum number of days between password change' | $AWK -F: '{print $2}' | $AWK '{print $1}' | $GREP -E -c '(^[0-9]$|^[1-8][0-9]$|^90$)'` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "5.4.1.1 - Set Password Expiration Days"
			FIRST=0
		fi
		$ECHO "$user - `chage --list $user | $GREP '^Maximum number of days between password change'`"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "5.4.1.1 - Set Password Expiration Days"
fi

FIRST=1
OUTPUT=`$GREP '^PASS_MIN_DAYS' /etc/login.defs`
if [ `$ECHO $OUTPUT | $AWK '{print $2}' | $GREP -E -v -c '^[0-6]$'` -eq 0 ]; then
	printfailure "5.4.1.2 - Set Password Change Minimum Number of Days"
	$ECHO $OUTPUT
	FIRST=0
fi
$AWK -F: '{ print $1 " " $3 }' /etc/passwd | while read user uid; do
	if [ $uid -ge $MAX_SYSTEM_UID -a $user != "nfsnobody" -a `chage --list $user | $GREP '^Minimum number of days between password change' | $AWK -F: '{print $2}' | $AWK '{print $1}' | $GREP -E -v -c '(\-[0-9]+|[0-6])$'` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "5.4.1.2 - Set Password Change Minimum Number of Days"
			FIRST=0
		fi
		$ECHO "$user - `chage --list $user | $GREP '^Minimum number of days between password change'`"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "5.4.1.2 - Set Password Change Minimum Number of Days"
fi

FIRST=1
OUTPUT=`$GREP '^PASS_WARN_AGE' /etc/login.defs`
if [ `$ECHO $OUTPUT | $AWK '{print $2}' | $GREP -E -v -c '^(\-[0-9]+|[0-6])$'` -eq 0 ]; then
	printfailure "5.4.1.3 - Set Password Expiry Warning Days"
	$ECHO $OUTPUT
	FIRST=0
fi
$AWK -F: '{ print $1 " " $3 }' /etc/passwd | while read user uid; do
	if [ $uid -ge $MAX_SYSTEM_UID -a $user != "nfsnobody" -a `chage --list $user | $GREP '^Number of days of warning before password expires' | $AWK -F: '{print $2}' | $AWK '{print $1}' | $GREP -E -c '^[0-6]$'` -gt 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "5.4.1.3 - Set Password Expiry Warning Days"
			FIRST=0
		fi
	$ECHO "$user - `chage --list $user | $GREP '^Number of days of warning before password expires'`"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "5.4.1.3 - Set Password Expiry Warning Days"
fi

OUTPUT=`$USERADD -D | $GREP INACTIVE`
if [ `$ECHO $OUTPUT | $AWK -F= '{print $2}' | $GREP -E -c '(^[0-9]$|^[1-2][0-9]$|^3[0-5]$)'` -eq 0 ]; then
	printfailure "5.4.1.4 - Lock Inactive User Accounts"
	$ECHO $OUTPUT
else
	printsuccess "5.4.1.4 - Lock Inactive User Accounts"
fi

OUTPUT=`$GREP -E -v '^\+' /etc/passwd | $AWK -F: -v uid="$MAX_SYSTEM_UID" '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<uid && $7!="/sbin/nologin") {print uid}'`
if [ ! -z "$OUTPUT" ]; then
	printfailure "5.4.2 - Disable System Accounts"
	$ECHO $OUTPUT
else
	printsuccess "5.4.2 - Disable System Accounts"
fi

OUTPUT=`$GREP '^root:' /etc/passwd | $AWK -F: '{ print $4 }' | $GREP -v '^0$'`
if [ ! -z "$OUTPUT" ]; then
	printfailure '5.4.3 - Set Default Group for root Account'
	$ECHO $OUTPUT
else
	printsuccess "5.4.3 - Set Default Group for root Account"
fi

if [ `cat /etc/bashrc /etc/profile | $GREP "^[[:space:]]*umask[[:space:]]*[0-7][0-7][0-7]" | $GREP -c -v "027"` -ne 0 ]; then
	printfailure "5.4.4 - Set Default umask for Users"
	cat /etc/bashrc /etc/profile | $GREP "^[[:space:]]*umask[[:space:]]*[0-7][0-7][0-7]"
else
	printsuccess "5.4.4 - Set Default umask for Users"
fi

CHECKS_PASSED=$((CHECKS_PASSED+1))
$ECHO "5.5 - Restrict root Login to System Console - MANUAL CHECK"

OUTPUT=`$GREP -v "^#" /etc/pam.d/su | $GREP pam_wheel.so`
if [ -z "$OUTPUT" ]; then
	printfailure "5.6 - Restrict Access to the su Command"
else
	OUTPUT=`$GREP 'wheel' /etc/group | $AWK -F: '{print $4}'`
	if [ ! $OUTPUT = "root,wilger" ]; then
		printfailure "5.6 - Restrict Access to the su Command"
		$ECHO $OUTPUT
	else
		printsuccess "5.6 - Restrict Access to the su Command"
	fi
fi

FIRST=1
$STAT --format="%n %X" /dev/pts/* | $GREP -v "ptmx" | $AWK -F: '{ print $1 " " $2 }' | while read file mod_time; do
	DATE=`date +%s`
	IDLE_TIME=`expr $DATE - $mod_time`
	if [ $IDLE_TIME -gt 600 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "5.7 - Idle Users Not Disconnected"
			FIRST=0
		fi
		PTS=`$ECHO $file | $AWK -F/ '{print $NF}'`
		w | $GREP "pts/$PTS"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "5.7 - Idle Users Not Disconnected"
fi


OUTPUT=`$RPM -Va --nomtime --nosize --nomd5 --nolinkto | $GREP -E -v "missing.*\/etc\/(at|cron)\.deny" | \
$GREP -E -v ".M.......\s+\/etc\/cron\.(hourly|daily|weekly|monthly|d)" | $GREP -E -v ".M.......\s+\/etc\/crontab"`
if [ ! -z "$OUTPUT" ]; then
	printfailure "6.1.1 - Verify System File Permissions"
	while read -r line; do
		echo "... $line ..."
	done <<< "$OUTPUT"
else
	printsuccess "6.1.1 - Verify System File Permissions"
fi

i=2
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-; do
	if [ $f = "/etc/gshadow" -o $f = "/etc/gshadow-" -o $f = "/etc/shadow" -o $f = "/etc/shadow-" ]; then
		OUTPUT=`$STAT -L -c '%A %u %g' $f | $GREP -E -v '^-[r\-][w\-]------- 0 0$'`
	else
		OUTPUT=`$STAT -L -c '%A %u %g' $f | $GREP -v '^-rw-r--r-- 0 0$'`
	fi
	if [ ! -z "$OUTPUT" ]; then
		printfailure "6.1.$i - Verify Permissions on $f"
		$ECHO "$f - $OUTPUT"
	else
		printsuccess "6.1.$i - Verify Permissions on $f"
	fi
	i=$((i+1))
done

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -type f -perm -002 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.1.10 - Find World Writable Files"
			FIRST=0
		fi
		for file in $OUTPUT; do
			$ECHO $file
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.1.10 - Find World Writable Files"
fi

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -nouser 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.1.11 - Find Un-owned Files and Dirctories"
			FIRST=1
		fi
		for file in $OUTPUT; do
			$ECHO $file
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.1.11 - Find Un-owned Files and Dirctories"
fi

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -nogroup 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		if [ $FIRST -eq 0 ]; then
			printfailure "6.1.12 - Find Un-grouped Files and Dirctories"
			FIRST=1
		fi
		for file in $OUTPUT; do
			$ECHO $file
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.1.12 - Find Un-grouped Files and Dirctories"
fi

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -type f -perm -4000 -perm /u+x,g+x,o+x -print 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		for file in $OUTPUT; do
			PKG=`$RPM -qf $file`
			if [ `$ECHO '$PKG' | $GREP 'not owned by any package'` ]; then
				if [ $FIRST -eq 1 ]; then
					printfailure "6.1.13 - Find SUID System Executables - FAIL"
					FIRST=0
				fi
				$ECHO "$file not owned by any package (unexpected)"
			else
				VERIFY=`$RPM -V $PKG | $GREP $file`
				if [ ! -z "$VERIFY" ]; then
					if [ $FIRST -eq 1 ]; then
						printfailure "6.1.13 - Find SUID System Executables"
						FIRST=0
					fi
					$ECHO $VERIFY
				fi
			fi
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.1.13 - Find SUID System Executables"
fi

FIRST=1
for fs in $LOCAL_FS; do
	OUTPUT=`$FIND $fs -xdev -type f -perm -2000 -perm /u+x,g+x,o+x -print 2>/dev/null`
	if [ ! -z "$OUTPUT" ]; then
		for file in $OUTPUT; do
			PKG=`$RPM -qf $file`
			if [ `$ECHO '$PKG' | $GREP 'not owned by any package'` ]; then
				if [ $FIRST -eq 1 ]; then
					printfailure "6.1.14 - Find SGID System Executables"
					FIRST=0
				fi
				$ECHO "$file not owned by any package (unexpected)"
				else
				VERIFY=`$RPM -V $PKG | $GREP $file`
				if [ ! -z "$VERIFY" ]; then
					if [ $FIRST -eq 1 ]; then
						printfailure "6.1.14 - Find SGID System Executables"
						FIRST=0
					fi
					$ECHO $VERIFY
				fi
			fi
		done
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.1.14 - Find SGID System Executables"
fi

OUTPUT=`$AWK -F: '($2 == "" ) { print $1 " does not have a password"}' /etc/shadow`
if [ ! -z "$OUTPUT" ]; then
	printfailure "6.2.1 - Ensure Password Fields are Not Empty"
	$ECHO $OUTPUT
else
	printsuccess "6.2.1 - Ensure Password Fields are Not Empty"
fi

i=2
for file in /etc/passwd /etc/shadow /etc/gshadow; do
	OUTPUT=`$GREP '^+:' $file`
	if [ ! -z "$OUTPUT" ]; then
		printfailure "6.2.$i - Verify No Legacy \"+\" Exist in $file File"
		$ECHO $OUTPUT
	else
		printsuccess "6.2.$i - Verify No Legacy \"+\" Exist in $file File"
	fi
	i=$((i+1))
done

OUTPUT=`$AWK -F: '($3 == 0) { print $1 }' /etc/passwd | $GREP -v 'root'`
if [ ! -z "$OUTPUT" ]; then
	printfailure "6.2.5 - Verify No UID 0 Accounts Exist Other Than root"
	for user in $OUTPUT; do
		$ECHO $user
	done
else
	printsuccess "6.2.5 - Verify No UID 0 Accounts Exist Other Than root"
fi

FIRST=1
OUTPUT=`$ECHO $PATH | $GREP ::`
if [ ! -z "$OUTPUT" ]; then
	if [ $FIRST -eq 1 ]; then
		printfailure "6.2.6 - Ensure root PATH Integrity"
		FIRST=0
	fi
    $ECHO "Empty Directory in PATH (::)"
fi
OUTPUT=`$ECHO $PATH | $GREP :$`
if [ ! -z "$OUTPUT" ]; then
	if [ $FIRST -eq 1 ]; then
		printfailure "6.2.6 - Ensure root PATH Integrity"
		FIRST=0
	fi
	$ECHO "Trailing : in PATH"
fi
p=`$ECHO $PATH | $SED -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
	if [ "$1" = "." ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.6 - Ensure root PATH Integrity"
			FIRST=0
		fi
		$ECHO "PATH contains ."
		shift
		continue
	fi
	if [ -d $1 ]; then
		OUTPUT=`$STAT -L -c '%A %U' $1`
		if [ `$ECHO $OUTPUT | $GREP -E -c '^(........w.|.....w....)[[:space:]]'` -gt 0 ]; then
			if [ $FIRST -eq 1 ]; then
				printfailure "6.2.6 - Ensure root PATH Integrity"
				FIRST=0
			fi
			$ECHO "Group or Other write permission set on directory $1 - $OUTPUT"
		fi
		if [ `$ECHO $OUTPUT | $GREP -E -v -c '[[:space:]]root$'` -gt 0 ] ; then
			if [ $FIRST -eq 1 ]; then
				printfailure "6.2.6 - Ensure root PATH Integrity"
				FIRST=0
			fi
			$ECHO "$1 is not owned by root - $OUTPUT"
		fi
	else
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.6 - Ensure root PATH Integrity"
			FIRST=0
		fi
		$ECHO $1 is not a directory
	fi
	shift
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.6 - Ensure root PATH Integrity"
fi

FIRST=1
$AWK -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
	if [ $uid -ge $MAX_SYSTEM_UID -a ! -d "$dir" -a $user != "nfsnobody" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.7 - Check That Users Are Assigned Valid Home Directories"
			FIRST=0
		fi
		$ECHO "The home directory ($dir) of user $user does not exist."
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.7 - Check That Users Are Assigned Valid Home Directories"
fi

FIRST=1
for dir in `$GREP -E -v '(root|halt|sync|shutdown)' /etc/passwd | $AWK -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
	OUTPUT=`$STAT -L -c '%A' $dir`
	if [ `$ECHO $OUTPUT | $GREP -E -v -c '.....\-.\-\-\-'` -eq 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.8 - Check Permissions on User Home Directories"
			FIRST=0
		fi
		$ECHO "$dir has incorrect permissions - $OUTPUT"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.8 - Check Permissions on User Home Directories"
fi

FIRST=1
$AWK -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
	if [ $uid -ge $MAX_SYSTEM_UID -a -d "$dir" -a $user != "nfsnobody" ]; then
		owner=$($STAT -L -c "%U" "$dir")
		if [ "$owner" != "$user" ]; then
			if [ $FIRST -eq 1 ]; then
				printfailure "6.2.9 - Check User Home Directory Ownership"
				FIRST=0
			fi
			$ECHO "The home directory ($dir) of user $user is owned by $owner."
		fi
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.9 - Check User Home Directory Ownership"
fi

FIRST=1
for dir in `$GREP -E -v '(root|sync|halt|shutdown)' /etc/passwd | $AWK -F: '($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.[A-Za-z0-9]*; do
		if [ ! -h "$file" -a -f "$file" ]; then
			OUTPUT=`$STAT -L -c '%A' $file`
			if [ `$ECHO $OUTPUT | $GREP -E -c '.....-..-$'` -eq 0 ]; then
				if [ $FIRST -eq 1 ]; then
					printsuccess "6.2.10 - Check User Dot Permissions"
					FIRST=0
				fi
				$ECHO "$file has incorrect permissions - $OUTPUT"
			fi
		fi
	done
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.10 - Check User Dot Permissions"
fi

FIRST=1
for dir in `$AWK -F: '{ print $6 }' /etc/passwd`; do
	if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.11 - Check for Presence of User .forward Files"
			FIRST=0
		fi
		$ECHO ".forward file $dir/.forward exists"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.11 - Check for Presence of User .forward Files"
fi

FIRST=1
for dir in `$AWK -F: '{ print $6 }' /etc/passwd`; do
	if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.12 - Check for Presence of User .netrc Files"
			FIRST=0
		fi
		$ECHO ".netrc file $dir/.netrc exists"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.12 - Check for Presence of User .netrc Files"
fi

FIRST=1
for dir in `$GREP -v '(root|sync|halt|shutdown)' /etc/passwd | $AWK -F: '($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.netrc; do
		if [ ! -h "$file" -a -f "$file" ]; then
			OUTPUT=`$STAT -L -c '%A' $file`
			if [ `$ECHO $OUTPUT | $GREP -E -v -c '....\-\-\-\-\-\-'` -eq 0 ]; then
				if [ $FIRST -eq 1 ]; then
					printfailure "6.2.13 - Check Permissions on User .netrc Files"
					FIRST=0
				fi
				$ECHO '$file has incorrect permissions - $OUTPUT'
			fi
		fi
	done
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.13 - Check Permissions on User .netrc Files"
fi

FIRST=1
for dir in `$GREP -E -v '(root|halt|sync|shutdown)' /etc/passwd | $AWK -F: '($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.rhosts; do
		if [ ! -h "$file" -a -f "$file" ]; then
			if [ $FIRST -eq 1 ]; then
				printfailure "6.2.14 - Check for Presence of User .rhosts Files"
				FIRST=0
			fi
			$ECHO ".rhosts file in $dir"
		fi
	done
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.14 - Check for Presence of User .rhosts Files"
fi

FIRST=1
for i in $($AWK -F: '{ print $4 }' /etc/passwd | sort -u ); do
	$GREP -q -P "^.*?:x:$i:" /etc/group
	if [ $? -ne 0 ]; then
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.15 - Check Groups in /etc/passwd"
			FIRST=0
		fi
		$ECHO "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.15 - Check Groups in /etc/passwd"
fi

FIRST=1
$AWK -F: '{ print $3 }' /etc/passwd | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		users=`$AWK -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | /usr/bin/xargs`
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.16 - Check for Duplicate UIDs"
			FIRST=0
		fi
	$ECHO "Duplicate UID ($2): ${users}"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.16 - Check for Duplicate UIDs"
fi

FIRST=1
$AWK -F: '{ print $3 }' /etc/group | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		grps=`$AWK -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.17 - Check for Duplicate GIDs"
			FIRST=0
		fi
	$ECHO "Duplicate GID ($2): ${grps}"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.17 - Check for Duplicate GIDs"
fi

FIRST=1
$AWK -F: '{ print $1 }' /etc/passwd | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`$AWK -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.18 - Check for Duplicate User Names"
			FIRST=0
		fi
		$ECHO "Duplicate User Name ($2): ${uids}"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.18 - Check for Duplicate User Names"
fi

FIRST=1
$AWK -F: '{ print $1 }' /etc/group | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`$AWK -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
		if [ $FIRST -eq 1 ]; then
			printfailure "6.2.19 - Check for Duplicate Group Names"
			FIRST=0
		fi
		$ECHO "Duplicate Group Name ($2): ${gids}"
	fi
done
if [ $FIRST -eq 1 ]; then
	printsuccess "6.2.19 - Check for Duplicate Group Names"
fi

TOTAL_CHECKS=$((CHECKS_PASSED+$CHECKS_FAILED))
$ECHO "$CHECKS_PASSED / $TOTAL_CHECKS passed."
