#!/bin/sh 
# 
# Ananke v0.06 - "enumeration is a necessity"
# 2012-06-25
#
# Tested on Backtrack 5(Ubuntu 10.04), Ubuntu 7.10, Ubuntu 10.04-12.04, Cent0S5.4, FC4, 
# FBSD7.0, RHEL 9, Gentoo 2008.0
# Debian 4.0, Debian 5.0.4 

# PLEASE NOTE:
# This script is inefficient; multiple seeks exist for the same data - however no temporary flies are left to disk other than the final output file.
# *Obviously* this could be done (and much better) in another language e.g. python, perl... however using "sh" ensures portability; the language is 
# available to run the script.


# Enable to "y" for execution of the intensive searches in the section below
STDOUT="y" 			# echo section progress to stdout(Display)
SYSTEM="y" 			# Perform System extraction
NETWORKING="n" 		# Perform Network parameters extraction
AUTHENTICATION="n" 	# Perform Authentication extraction
SYSTEMCONF="n" 		# Perform system configuration specific extraction
	PROCESSES="n" 	# Perform running processes extraction
APPLICATIONS="n" 	# Perform Servers and Applications extraction
LANGUAGES="n" 		# Perform installed languages extraction
FILESRCH="n" 		# Perform file system directories and permissions extraction
	SUIDLIB="n" 	# SUID library breakdown and permissions extraction
	HOMELIST="n" 	# List files in home directories
PKGMGMT="n" 		# Perform package management extraction
KERNELCONF="n" 		# Perform kernel config extraction
LOGPROC="n" 		# Very Basic logfile analysis extraction
	APACHELOG="n" 	# Do this for Apache
	SSHDLOGS="n" 	# Do this for SSHD in auth.log
	POSTFIXLOGS="n" # Do this for SSHD in auth.log

# Ensure commands referenced below are in the common path environment
PATH="$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"

UNAME=`whereis uname | awk '{print$2}' 2>/dev/null`
HOSTNAME="`whereis hostname | awk '{print$2}' 2>/dev/null`"

DATE=`date +"%Y-%m-%d"`
TIME=`date +"%H:%M:%S"`
OSNAME=`$UNAME -s`
OSREL=`$UNAME -r`
OSVER=`$UNAME -v`
ARCHTYPE=`$UNAME -m`
OSFULL=`$UNAME -a`
UPTIME=`uptime`
ID=`id`
WHO=`whoami`
echo "`$HOSTNAME -f` reconnaissance executed by $WHO"

# Primary IPv4Address
if [ $OSNAME = "FreeBSD" ]; then
	PIP4ADD="`ifconfig | grep "inet " | grep -v 127.0.0.1 | head -n 1 | awk {'print $2}'`"
elif [ $OSNAME = "Linux" ]; then
	PIP4ADD="`/sbin/ifconfig | grep "inet addr" | head -n 1 | cut -d : -f 2 | awk '{ print $1}'`"
fi;

echo $PIP4ADD
FILE="`echo $PIP4ADD`_`$HOSTNAME`_audit_`whoami`_$DATE"
rm $FILE 2>/dev/null;


# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Variables and binary locations section
#PHPCONF=`find /etc -name php.ini 2>/dev/null | grep apache`

SSH=`command -v ssh 2>/dev/null`
SSHVER="$SSH -V"
SSHDCONF=`find /etc -name sshd_config 2>/dev/null | head -n 1 2>/dev/null`

MYSQL="`command -v mysql 2>/dev/null | sed '/^$/d'`"
if [ -r `command -v mysql 2>/dev/null | sed '/^$/d'` ]; then MYSQLVER=`$MYSQL -V 2>/dev/null`; 
fi; 
if [ -r $MYSQL ]; then MYSQLVER=`$MYSQL -V 2>/dev/null`; 
	MYSQLCONF=`find /etc -name my.cnf 2>/dev/null`;
fi;
HTTPD=`command -v httpd 2>/dev/null`
if [ -e "`command -v httpd 2>/dev/null`" ]; then 
	HTTPD=`command -v httpd`
	HTTPDVER="`$HTTPD -v 2>/dev/null`"
	HTTPDCONF=`find /etc -name httpd.conf 2>/dev/null`
	DOCUMENTROOT=`grep -R DocumentRoot /etc/httpd/conf* 2>/dev/null | grep -v "#" | awk '{print $2}' | uniq | sed '/^$/d'`;
fi;

if [ -x "`command -v apache2 2>/dev/null`" ]; then 
	APACHE="`command -v apache2 2>/dev/null`" 
	APACHEVER="$APACHE -v 2>/dev/null"
	APACHECONF=`find /etc -name apache2.conf 2>/dev/null`
	DOCUMENTROOT=`grep -R DocumentRoot /etc/apache2 2>/dev/null | awk '{print $3}' | uniq | sed '/^$/d'`;
fi;

SAMBA="`command -v smbd 2>/dev/null`"
SAMBAVER="$SAMBA -V 2>/dev/null"
SAMBACONF=`find /etc -name smb.conf 2>/dev/null`

GCC="`command -v gcc 2>/dev/null`"
PERL="`command -v perl 2>/dev/null`"
#echo $PERL
RUBY="`command -v ruby 2>/dev/null`"
PHP="`command -v php 2>/dev/null`"


# Expand this if wishing to search outside of the following paths - streamlined to help reduce disk io and time consumption
BINARYDIR="/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin"
WORLDIR="/tmp /var/tmp /var /root /dev /usr"  
HOMEDIR="`cat /etc/passwd | cut -d : -f 6`"

if [ $OSNAME = "Linux" ]; then
LINUXIPv4="net.ipv4.tcp_syncookies \
net.ipv4.conf.all.rp_filter \
net.ipv4.conf.all.accept_source_route \
net.ipv4.conf.all.accept_redirects \
net.ipv4.conf.all.secure_redirects \
net.ipv4.conf.default.rp_filter \
net.ipv4.conf.default.accept_source_route \
net.ipv4.conf.default.accept_redirects \
net.ipv4.conf.default.secure_redirects \
net.ipv4.icmp_echo_ignore_broadcasts \
net.ipv4.ip_forward \
net.ipv4.conf.all.send_redirects \
net.ipv4.conf.default.send_redirects \
net.ipv4.tcp_max_syn_backlog"

LINUXIPv6="net.ipv6.conf.all.forwarding \
net.ipv6.conf.all.accept_redirects \
net.ipv6.conf.all.disable_ipv6 \
net.ipv6.bindv6only"
fi;

if [ $OSNAME = "FreeBSD" ]; then
FBSDIPv4="net.inet.ip.forwarding \
net.inet.ip.redirect \
net.inet.ip.accept_sourceroute \
net.inet.ip.subnets_are_local \
net.inet.ip.maxfragpackets \
net.inet.ip.maxfragsperpacket \
net.inet.ip.fragpackets \
net.inet.ip.check_interface \
net.inet.ip.random_id \
net.inet.ip.sendsourcequench \
net.inet.ip.process_options sysct\
net.inet.icmp.maskrepl \
net.inet.icmp.icmplim \
net.inet.icmp.bmcastecho \
net.inet.icmp.quotelen \
net.inet.icmp.reply_from_interface \
net.inet.icmp.reply_src \
net.inet.icmp.icmplim_output \
net.inet.icmp.log_redirect \
net.inet.icmp.drop_redirect \
net.inet.icmp.maskfake \
net.inet.tcp.rfc1323 \
net.inet.tcp.insecure_rst \
net.inet.tcp.rfc3390 \
net.inet.tcp.rfc3042 \
net.inet.tcp.drop_synfin \
Net.inet.tcp.delayed_ack \
net.inet.tcp.blackhole \
net.inet.tcp.log_in_vain \
net.inet.tcp.icmp_may_rst \
net.inet.tcp.do_tcpdrain \
net.inet.tcp.log_debug \
net.inet.tcp.syncache.rst_on_sock_fail \
net.inet.tcp.syncookies_only \
net.inet.tcp.syncookies \
net.inet.tcp.timer_race \
net.inet.tcp.always_keepalive \
net.inet.udp.checksum \
net.inet.udp.blackhole \
net.inet.udp.log_in_vain \
net.link.ether.ipfw"

FBSDIPv6="net.inet6.ip6.forwarding \
net.inet6.ip6.redirect \
net.inet6.ip6.log_interval \
net.inet6.ip6.use_deprecated \
net.inet6.icmp6.rediraccept \
net.inet6.icmp6.redirtimeout"

FBSDSEC="security.jail.jailed \
security.jail.mount_allowed \
security.jail.chflags_allowed \
security.jail.allow_raw_sockets \
security.jail.enforce_statfs \
security.jail.sysvipc_allowed \
security.jail.socket_unixiproute_only \
security.jail.set_hostname_allowed \
security.bsd.suser_enabled \
security.bsd.unprivileged_proc_debug \
security.bsd.conservative_signals \
security.bsd.see_other_gids \
security.bsd.see_other_uids \
security.bsd.unprivileged_read_msgbuf \
security.bsd.hardlink_check_gid \
security.bsd.hardlink_check_uid \
security.bsd.unprivileged_get_quota"
fi;


# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# System Fingerprinting section - header of the output file

if [ $SYSTEM = "y" ]; then
	echo "######################################################################################################################################################" >> $FILE;
	if [ $STDOUT="y" ]; then echo "${YELLOW}TARGET SYSTEM"; fi;
	echo "TARGET SYSTEM" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "" >> $FILE;
	echo "Hostname: `$HOSTNAME`" >> $FILE;
	if [ $OSNAME = "FreeBSD" ]; then 
		echo "Primary IPv4 addr: `ifconfig | grep "inet " | grep -v 127.0.0.1 | head -n 1 | awk {'print $2}'`" >> $FILE;
	elif [ $OSNAME = "Linux" ]; then 
		echo "Primary IPv4 addr: `/sbin/ifconfig | grep "inet addr" | head -n 1 | cut -d : -f 2 | awk '{ print $1}'`" >> $FILE;
	fi;
	echo "" >> $FILE;
	echo "Operating System: $OSNAME" >> $FILE;
	if [ $OSNAME = "Linux" ]; then
        	if [ -e "/etc/debian_version" ]; then echo "Debian Version: `cat /etc/debian_version | sed '/^$/d'`" >> $FILE && echo "Issue: `cat /etc/issue | sed '/^$/d'`" >> $FILE;
	        elif [ -e "/etc/redhat-release" ]; then echo "RedHat-Release: `cat /etc/redhat-release | sed '/^$/d'`"  >> $FILE && echo "Issue: `cat /etc/issue | sed '/^$/d'`" >> $FILE;
	        elif [ -e "/etc/gentoo-release" ]; then cat /etc/gentoo-release | sed '/^$/d' >> $FILE;
	        fi;
	fi;
	echo "Operating Kernel release: $OSREL" >> $FILE;
	echo "Operating Kerenl compile: $OSVER" >> $FILE;
	echo "Architecture type: $ARCHTYPE" >> $FILE;
	echo "Full Uname: $OSFULL" >> $FILE;
	echo "System Uptime: $UPTIME" >> $FILE;
	echo ""  >> $FILE;
	echo ""  >> $FILE;
	echo "Audit Start Date: $DATE" >> $FILE;
	echo "Audit Start Time: $TIME" >> $FILE;
	echo "Audit Performed by User: $ID" >> $FILE;
	echo "" >> $FILE;
	echo "User Environment:" >> $FILE && env >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo "" >> $FILE;
fi;





# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Network Fingerprinting section 
echo ""  >> $FILE;
if [ $NETWORKING = "y" ]; then
	echo "######################################################################################################################################################" >> $FILE;
	if [ $STDOUT="y" ]; then echo "NETWORKING"; fi
	echo "NETWORKING" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "" >> $FILE;
	# Interface configuration
	echo "Interfaces:" >> $FILE && /sbin/ifconfig -a >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
	# Routing table
	echo "Routing Table:" >> $FILE && netstat -rn >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;

# Listening IPv4/6 sockets
	echo "Listening IPv4/6 sockets" >> $FILE;
	if [ $OSNAME = "FreeBSD" ]; then 
		echo "Listening Sockets:" >> $FILE && sockstat -l >> $FILE; echo "" >> $FILE;
	elif [ $OSNAME = "Linux" ]; then 
		echo "Listening Sockets:" >> $FILE && netstat -lnp --inet 2>/dev/null >> $FILE;
	fi;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
	echo "IPv4 Open Files Sockets:" >> $FILE;
	if [ $OSNAME = "Linux" ]; then lsof -i4 2>/dev/null >> $FILE;
		echo "IPv4 TCP Sockets:" >> $FILE; netstat -ant4 2>/dev/null >> $FILE; echo "" >> $FILE;
		echo "IPv4 UDP Sockets:" >> $FILE; netstat -anu4 2>/dev/null >> $FILE;
	elif [ $OSNAME = "FreeBSD" ]; then sockstat -4 >> $FILE; echo "" >> $FILE;
		echo "IPv4 TCP Sockets:" >> $FILE; /usr/bin/netstat -antf inet -p tcp 2>/dev/null >> $FILE; echo "" >> $FILE;
	echo "IPv4 UDP Sockets:" >> $FILE; /usr/bin/netstat -antf inet -p udp 2>/dev/null >> $FILE; echo "" >> $FILE;
	fi;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE;

	echo "IPv6 Open Files Sockets:" >> $FILE; 
	if [ $OSNAME = "Linux" ]; then lsof -i6 2>/dev/null >> $FILE;
		echo "IPv6 TCP Sockets:" >> $FILE; netstat -ant6 2>/dev/null >> $FILE; echo "" >> $FILE;
		echo "IPv6 UDP Sockets:" >> $FILE; netstat -anu6 2>/dev/null >> $FILE;
	elif [ $OSNAME = "FreeBSD" ]; then sockstat -6 >> $FILE; echo "" >> $FILE;
		echo "IPv6 TCP Sockets:" >> $FILE; /usr/bin/netstat -antf inet6 -p tcp 2>/dev/null >> $FILE; echo "" >> $FILE;
		echo "IPv6 UDP Sockets:" >> $FILE; /usr/bin/netstat -antf inet6 -p udp 2>/dev/null >> $FILE; echo "" >> $FILE;
	fi;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE;

# Accessible network filtering configuration. Firewall.
# TCPWrappers
	if [ -e "/etc/hosts.allow" ]; then echo "TCPWrappers hosts.allow:" >> $FILE; ls -la /etc/hosts.allow >> $FILE && cat /etc/hosts.allow 2>/dev/null | grep -v "#" | sed '/^$/d' >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
	fi;
	if [ -e "/etc/hosts.deny" ]; then echo "TCPWrappers hosts.deny:" >> $FILE; ls -la /etc/hosts.deny >> $FILE && cat /etc/hosts.deny 2>/dev/null | grep -v "#" | sed '/^$/d' >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
	fi;

	if [ $OSNAME = "Linux" ]; then 
		echo "IPTABLES RULESET:" >> $FILE && iptables -L >> $FILE;
	elif [ $OSNAME = "FreeBSD" ]; then 
		echo "IPFW RULESET:" >> $FILE && ipfw -a list >> $FILE; 
	fi;

# hosts file
	if [ -e "/etc/hosts" ]; then echo "Hosts File:" >> $FILE; ls -la /etc/hosts >> $FILE && cat /etc/hosts 2>/dev/null | sed '/^$/d' >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
	fi;


#IPv4 security settings - test with sysctl -n - value is returned
	echo "IPv4 security kernel configuration:" >> $FILE;
#if [ $OSNAME = "FreeBSD" ]; then 
	if [ $OSNAME = "Linux" ]; then 
		for i in $LINUXIPv4; do 
			/sbin/sysctl $i >> $FILE;
			done;
	fi;
	echo "" >> $FILE;
	if [ -e "/etc/sysctl.conf" ]; then echo "Sysctl.conf security permissions:" >> $FILE && ls -la /etc/sysctl.conf >> $FILE && cat /etc/sysctl.conf | sed '/^$/d' >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE;
	fi;	
fi



# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Authentication Fingerprinting section 
if [ $AUTHENTICATION = "y" ]; then
	echo ""  >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	if [ $STDOUT="y" ]; then echo "AUTHENTICATION"; fi
	echo "AUTHENTICATION" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo ""  >> $FILE;
	echo "Users online:" >> $FILE && who >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
	echo "Last logins:" >> $FILE && last >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
	if [ -r "/etc/passwd" ]; then echo "Password file:" >> $FILE && ls -la /etc/passwd >> $FILE && cat /etc/passwd 2>/dev/null | sed '/^$/d' >> $FILE; 
	echo "" >> $FILE && echo "UID 0 accounts" && grep 'x:0:' /etc/passwd >> $FILE;

	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi

	if [ -e "/etc/shadow" ]; then echo "Shadow file:" >> $FILE && ls -la /etc/shadow >> $FILE && cat /etc/shadow 2>/dev/null | sed '/^$/d' >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi
	if [ -e "/etc/group" ]; then echo "Group file:" >> $FILE && ls -la /etc/group >> $FILE && cat /etc/group 2>/dev/null | sed '/^$/d' >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi



	if [ -e /etc/sudoers ]; then echo "SUDOers file:" >> $FILE && ls -la /etc/sudoers >> $FILE && cat /etc/sudoers 2>/dev/null | grep -v "#" | sed '/^$/d' >> $FILE;
	echo ""  >> $FILE; 
	echo "Sudoers wheel group restrictions:" >> $FILE && grep pam_wheel.so /etc/pam.d/su >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; fi
	echo "" >> $FILE;
fi


# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# System configurations and Fingerprinting section 
echo "" >> $FILE;
if [ $SYSTEMCONF = "y" ]; then
	if [ $STDOUT="y" ]; then echo "SYSTEMCONF"; fi
	echo "######################################################################################################################################################" >> $FILE;
	echo "SYSTEMCONF" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "" >> $FILE;

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Running processes section 
	if [ $PROCESSES = "y" ]; then
		echo "-----------------------------------------------------" >> $FILE;
			if [ $STDOUT="y" ]; then echo "PROCESSES"; fi
		echo "PROCESSES" >> $FILE;
		echo "-----------------------------------------------------" >> $FILE;
# Adjust output format here ->
		ps auxgw | grep -v " TIME COMMAND" | sort -n >> $FILE; echo "" >> $FILE;
	fi

# /etc/motd
	if [ -e /etc/motd ]; then echo "MOTD extraction" >> $FILE;
		echo "`ls -la /etc/motd`:" >> $FILE && cat /etc/motd 2>/dev/null >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi

# Sysctl on boot
	if [ -e /etc/sysctl.conf ]; then echo "Sysctl permissions and extraction" >> $FILE && echo `ls -la /etc/sysctl.conf` >> $FILE && grep -v "#" /etc/sysctl.conf 2>/dev/null | sed '/^$/d' >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi

# NFS Exports - add checks for insecure configuration
	if [ -e /etc/exports ]; then echo "NFS Exports extraction" >> $FILE;
		echo "`ls -la /etc/exports`:" >> $FILE && cat /etc/exports 2>/dev/null | sed '/^$/d' >> $FILE;
	echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; fi

# SUID DUMPABLE
# needs to be 1 or 2
# http://www.exploit-db.com/exploits/8369/
	if [ `cat /proc/sys/fs/suid_dumpable` -ne "0" ]; then
		echo "suid_dumpable: `cat /proc/sys/fs/suid_dumpable` << ALERT check exploit 8369: #http://www.exploit-db.com/exploits/8369/" >> $FILE
	fi


# ASLR - sysctl kernel.randomize_va_space = 2
# ../Documentation/sysctl/kernel.txt 
# This option can be used to select the type of process address space randomization that is used in the system, for architectures that support this feature.
# 0 - Turn the process address space randomization off. This is the default for architectures that do not support this feature anyways, and kernels that are booted with the "norandmaps" parameter.
# 1 - Make the addresses of mmap base, stack and VDSO page randomized. This, among other things, implies that shared libraries will be loaded to random addresses. Also for PIE-linked binaries, 
#    the location of code start is randomized. This is the default if the CONFIG_COMPAT_BRK option is enabled.
# 2 - Additionally enable heap randomization. This is the default if CONFIG_COMPAT_BRK is disabled.
	if [ $OSNAME = "Linux" ]; then
		echo "ASLR - Address Space Layout Randomization:" >> $FILE;
		/sbin/sysctl kernel.randomize_va_space >> $FILE;
		if [ `/sbin/sysctl kernel.randomize_va_space | awk '{print $3}'` -eq 0 ]; then echo "WARNING: ASLR set to 0" >> $FILE; 
		fi
		echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE;
	fi

# CRONTAB
	if [ -e /etc/crontab ]; then echo "System Crontab extraction" >> $FILE;
		echo "`ls -la /etc/crontab`:" >> $FILE && grep -v "#" /etc/crontab 2>/dev/null | sed '/^$/d' >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
	fi
fi



if [ $LANGUAGES = "y" ]; then
	if [ $STDOUT="y" ]; then echo "LANGUAGES"; fi	
	echo "" >> $FILE; 
	echo "######################################################################################################################################################" >> $FILE;
	echo "LANGUAGES" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "" >> $FILE; 

# gcc version
	if [ -e "`command -v gcc 2>/dev/null`" ]; then echo "GCC Version:" >> $FILE && echo "$GCC" >> $FILE && $GCC -v >> $FILE 2>&1; 
		echo "-----------------------------------------------------" >> $FILE;
		echo "" >> $FILE; 
	fi

# perl version
	if [ -e `command -v perl 2>/dev/null` ]; then echo "Perl Version:" >> $FILE &&echo $PERL >>$FILE && $PERL -v 2>/dev/null | head -n 2 | sed '/^$/d' >> $FILE;
		echo "-----------------------------------------------------" >> $FILE;
		echo "" >> $FILE; 
	fi

# PHP version
	if [ -e "`command -v php 2>/dev/null`" ]; then echo "PHP extraction" >> $FILE && $PHP -v >> $FILE;
	echo "" >> $FILE;
		for i in `find /etc -name php.ini 2>/dev/null`; 
			do ls -la $i >> $FILE && cat $i | grep -v ";" | sed '/^$/d' >> $FILE && echo "" >> $FILE; 
			done
		echo "-----------------------------------------------------" >> $FILE;
		echo "" >> $FILE; 
	fi

# Ruby version
	if [ -e "`command -v ruby 2>/dev/null`" ]; then echo "RUBY Version:" >> $FILE && $RUBY -v >> $FILE;
		echo "-----------------------------------------------------" >> $FILE;
		echo "" >> $FILE; 
	fi
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
fi

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Application Finger printing section 
##Search for specific config files and extract contents
if [ $APPLICATIONS = "y" ]; then
	if [ $STDOUT="y" ]; then echo "APPLICATIONS"; fi
	echo "" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "APPLICATIONS" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "" >> $FILE;

# HTTPD
#  	- check permissions on DocumentRoot
#	- extract virtual hostnames
	if [ -x "`command -v httpd 2>/dev/null`" ]; then echo "HTTPD Extraction" >>$FILE && echo $HTTPD >> $FILE && echo $HTTPDVER >> $FILE; 
#if [ -r $HTTPDCONF ]; then echo "HTTPD configuration" >> $FILE;
		echo "DocumentRoot:" >> $FILE; echo $DOCUMENTROOT >> $FILE; echo "" >> $FILE;
		echo "$HTTPDCONF:" >> $FILE;
		echo "`ls -la $HTTPDCONF`:" >> $FILE;
		grep -v "#" $HTTPDCONF 2>/dev/null | sed '/^$/d' >> $FILE;
		echo "" >> $FILE;
		echo "-----------------------------------------------------" >> $FILE;
		echo "" >> $FILE; 
	fi; #fi

# APACHE
#  	- check permissions on DocumentRoot
#	- extract virtual hostnames
	if [ -x "`command -v apache2 2>/dev/null`" ]; then echo "Apache2 Extraction" >>$FILE && echo $APACHE >> $FILE && echo $APACHEVER >> $FILE; 
		if [ -r $APACHECONF ]; then echo "Apache2 configuration" >> $FILE;
			echo "DocumentRoot:" >> $FILE; echo $DOCUMENTROOT >> $FILE; echo "" >> $FILE;
			echo "$APACHECONF:" >> $FILE;
			echo "`ls -la $APACHECONF`:" >> $FILE;
			grep -v "#" $APACHECONF 2>/dev/null | sed '/^$/d' >> $FILE;
			echo "" >> $FILE; 
			echo "Enabled Modules:" >> $FILE; ls -la /etc/apache2/mods-enabled/ >> $FILE; echo "" >> $FILE;
			echo "Apache Environment Variables:" >> $FILE;
			grep -v "#" /etc/apache2/envvars 2>/dev/null | sed '/^$/d' >> $FILE;
			echo "-----------------------------------------------------" >> $FILE;
			echo "" >> $FILE; 
		fi;
	fi;


# MYSQL
	if [ -x "`command -v mysql 2>/dev/null`" ]; then echo "MySQL Extraction:" >> $FILE && echo "$MYSQL:" >>$FILE && echo $MYSQLVER >> $FILE; 
		if [ -e $MYSQLCONF ]; then echo "MySQL configuration" >> $FILE;
			echo "`ls -la $MYSQLCONF`:" >> $FILE; grep -v "#" $MYSQLCONF 2>/dev/null | sed '/^$/d' >> $FILE;
			echo "-----------------------------------------------------" >> $FILE; 
			echo "" >> $FILE; 
		fi;
	fi;

# SSHD
	if [ -x "`command -v sshd 2>/dev/null`" ]; then echo "SSHD Extraction:" >> $FILE && echo "$SSH:" >> $FILE && $SSH -V >> $FILE 2>&1; 
		echo "" >> $FILE;
		if [ -e $SSHDCONF ]; then echo "SSHD configuration:" >> $FILE;
			echo "`ls -la $SSHDCONF`:" >> $FILE; grep -v "#" $SSHDCONF 2>/dev/null | sed '/^$/d' >> $FILE; 
			if [ `grep "PermitRootLogin " /etc/ssh/sshd_config | grep -v "#" | awk '{print  $2}'` = "yes" ]; then echo "ALERT: Root login permitted" >> $FILE; fi
			echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
		fi;
	fi;

# Samba config
	if [ -x "`command -v smbd 2>/dev/null`" ]; then echo "Samba Extraction" >> $FILE && echo "$SAMBA:" >> $FILE && $SAMBAVER >> $FILE;
		if [ -e $SAMBACONF ]; then echo "Samba configuration" >> $FILE;
			echo "" >> $FILE; 
			echo "`ls -la $SAMBACONF`:" >> $FILE; grep -v ";" $SAMBACONF 2>/dev/null | sed '/^$/d' >> $FILE; 
			echo "-----------------------------------------------------" >> $FILE; echo "" >> $FILE; 
		fi;
	fi;

# other potential daemons
# snmpd config
# inetd/xinetd.conf
# Snort
# DNS? named?
# Sendmail? Aliases file?
# NFS?	/etc/exports?
# Squid?
# webmin
# Syslogd as a logging server?

fi


if [ $PKGMGMT = "y" ]; then 
	if [ $STDOUT="y" ]; then echo "PACKAGE MANAGEMENT"; fi 
	echo ""  >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo "PACKAGE MANAGEMENT" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo ""  >> $FILE;
	if [ $OSNAME = "Linux" ]; then
		if [ -e "/etc/debian_version" ]; then echo "Debian Version: `cat /etc/debian_version`" 2>/dev/null >> $FILE; 
			DPKG=`whereis dpkg | awk '{print $2}' 2>/dev/null`;
			if [ -x $DPKG ]; then PKGMGR=$DPKG; FLAGS="-l"; 
			fi;
		fi;

		if [ -e "/etc/redhat-release" ]; then echo "Redhat Release: `cat /etc/redhat-release`" 2>/dev/null >> $FILE; 
			RPM=`whereis rpm | awk '{print $2}' 2>/dev/null`;
			if [ -x $RPM ]; then PKGMGR=$RPM; FLAGS="-qa | sort"; 
			fi;
		fi;

		if [ -e "/etc/gentoo-release" ]; 
			then echo "Gentoo Release:: `cat /etc/gentoo-release`" 2>/dev/null >>$FILE;
			ls -la /var/db/pkg/* | awk '{print $9}' | sort -n | uniq 2>/dev/null | sed '/^$/d' >> $FILE;
#EMERGE=`whereis emerge | awk '{print $2}' 2>/dev/null`;
#if [ -x $EMERGE ]; then PKGMGR=$EMERGE; FLAGS="";

#if [ -e "/etc/gentoo-release" ]; then echo "Gentoo Release:: `cat /etc/gentoo-release`" 2>/dev/null >>$FILE;
#EMERGE=`whereis emerge | awk '{print $2}' 2>/dev/null`;
#if [ -x $EMERGE ]; then PKGMGR=$EMERGE; FLAGS="";

# ls -la /var/db/pkg/* | awk '{print $9}' | sort -n | uniq <- gives a "niceish" list of packages installed, bypassing the root/portage-group restrictions of running a portage query
# emerge --info gives nicely formatted system information 
		fi;
	fi;
	if [ $OSNAME = "FreeBSD" ]; then
		PKGINFO=`whereis pkg_info | awk '{print $2}' 2>/dev/null`;
		if [ -x $PKGINFO ]; then PKGMGR=$PKGINFO; FLAGS=""; 
		fi;
	fi;

	if [ -x $PKGMGR ]; then $PKGMGR $FLAGS >> $FILE; 
	echo "-----------------------------------------------------" >> $FILE;
	echo "" >> $FILE;
	fi;

#Pulseaudio
	file `whereis pulseaudio | awk '{print $2}'` 2>/dev/null >> $FILE;
	`whereis pulseaudio | awk '{print $2}'` --version 2>/dev/null >> $FILE;
	ls -al `whereis pulseaudio | awk '{print $2}'` 2>/dev/null >> $FILE;
	echo "ALERT: Pulseaudio exists - investigate further and check pulseaudio exploits" >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;
fi;

#Open Files
# lsof -i
if [ $FILESRCH = "y" ]; then 
	if [ $STDOUT="y" ]; then echo "FILE SYSTEMS and FIND extractions"; fi
	echo "######################################################################################################################################################" >> $FILE;
	echo "FILE SYSTEMS and FIND extractions" >> $FILE;
	echo "######################################################################################################################################################" >> $FILE;
	echo ""  >> $FILE;
	echo ""  >> $FILE;
	echo "Partitions:" >> $FILE && df -h >> $FILE;
	echo ""  >> $FILE;
# /etc/fstab?
	if [ -e /etc/fstab ]; then echo "File System Table file" >>$FILE &&  ls -la /etc/fstab >> $FILE && cat /etc/fstab 2>/dev/null >> $FILE;
		echo "" >> $FILE && echo "Active mounts" >> $FILE && mount >> $FILE
		echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
	fi;

# SUID binaries files
	echo "SUID binaries:"  >> $FILE;
	SUID=`find $BINARYDIR -perm -4000 -print 2>/dev/null`
	for  i in $SUID; 
		do ls -la $i >> $FILE; 
		done;
	echo ""  >> $FILE;

	if [ $SUIDLIB = "y" ]; then 
		for i in $SUID; 
			do echo "<<-- `ls -la $i | awk '{print $1,$3,$4,$8,$9}'`: -->> " >> $FILE && \
				ldd $i | grep / | awk '{print $3}' | sed '/^$/d' | sort | uniq | xargs ls -laH \
				| awk '{print $1,$3,$4,$8,$9}' >> $FILE && echo "" >> $FILE; 
			done
	fi;

# SGID binaries files
	echo "SGID binaries:"  >> $FILE;
	find $BINARYDIR -perm -2000 -print | xargs ls -la 2>/dev/null >> $FILE;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;

# World writeable directories and files
	echo "World Writeable Files and Directories:"  >> $FILE;
	for w in "$WORLDIR"; do 
		find / -path $w -o -perm -2 ! -type l -ls 2>/dev/null >> $FILE;
	done;
	echo "-----------------------------------------------------" >> $FILE;
	echo ""  >> $FILE;

# Known_hosts file and file bruteforcing 
# http://blog.rootshell.be/2010/11/03/bruteforcing-ssh-known_hosts-files/
	echo "Retrieved SSH User and key files:" >> $FILE;
	for p in "$HOMEDIR"; do 
		find / -path $p \( -name "known_hosts" -o -name "id_rsa*" -o -name "authorized_hosts" -o -name "id_dsa*" \
			-o -name "identity" \) -print -exec ls -la {} \; -exec cat {} \; 2>/dev/null >> $FILE;
	done
	echo "" >> $FILE; 

	echo "Retrieved Core dump files:" >> $FILE;
	find / -type f -regex ".*/core\.[0-9][0-9][0-9][0-9]$" -print -exec ls -la {} \; -exec strings {} \; 2> /dev/null

# Temporary directories contents
	if [ -e /tmp ]; then echo "Contents - /tmp" >>$FILE && ls -la /tmp 2>/dev/null >> $FILE && find /tmp -name "*" >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
	fi
	if [ -e /tmp ]; then echo "Contents - /var/tmp" >>$FILE && ls -la /var/tmp 2>/dev/null >> $FILE && find /var/tmp -name "*" >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
	fi
	if [ -e /tmp ]; then echo "Contents - /dev/shm" >>$FILE && ls -la /dev/shm 2>/dev/null >> $FILE && find /dev/shm -name "*" >> $FILE;
		echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
	fi

# Home directory permissions?
	if [ $HOMELIST = "y" ]; then 
		if [ -e /home ]; then echo "Contents - /home" >>$FILE &&  ls -la /home 2>/dev/null >> $FILE #&& find /home -name "*" >> $FILE;
			echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
		fi;
			if [ -e ~/ ]; then echo "Contents - `whoami` ~/" >>$FILE && ls -la ~/ 2>/dev/null >> $FILE && find ~/ -name "*" >> $FILE;
			echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
		fi;
		if [ $WHO != "root" ]; then echo "Contents - /root" >>$FILE &&  ls -la /root 2>/dev/null >> $FILE && find /root -name "*" >> $FILE;
			echo "-----------------------------------------------------" >> $FILE; echo ""  >> $FILE; 
		fi;
	fi;

# End of intensive file system searches
	echo "" >> $FILE; 
fi;
#-----------------------------------------------------------------------------------------------------------------

if [ $KERNELCONF = "y" ]; then 
	if [ $STDOUT="y" ]; then echo "Kernel configurations extractions"; fi
		echo "Kernel Configuration files (check for supported options like CAM support, ReiserFS...:"  >> $FILE;
		echo Kernel Configurations found: >> $FILE;
		ls -la /proc/config.gz 2>/dev/null >> $FILE && `ls -la /boot | grep config` 2>/dev/null >> $FILE;
		echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> $FILE;

		if [ -e "/proc/config.gz" ]; then ls -la /proc/config.gz >> $FILE && zcat /proc/config.gz 2>/dev/null | sed '/^$/d' >> $FILE; fi;
			echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> $FILE;
			echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> $FILE;
			for i in `ls /boot | grep config`; do file /boot/$i >> $FILE && cat /boot/$i | sed '/^$/d' >> $FILE && echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> $FILE && echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> $FILE; done;

fi;

echo "######################################################################################################################################################" >> $FILE;
echo "VERY BASIC LOGFILE PARSING - identify clients of the system" >> $FILE;
echo "######################################################################################################################################################" >> $FILE;
echo >> $FILE;
if [ $LOGPROC = "y" ]; then
	if [ $APACHELOG = "y" ]; then 
		echo "Apache2 client Sources:" >>$FILE;
		for f in `grep access.log -R /etc/apache2/* | grep -v "#" | cut -d : -f 2 | awk '{ print $2}' | sort | uniq`; do echo $f >> $FILE && cat $f 2>/dev/null | awk '{print $1,$7,$8,$9}' | sort | uniq -c | sort -rn | head -n 30 | sed '/^$/d'>> $FILE && echo $f.1 >> $FILE && cat $f.1 2>/dev/null | awk '{print $1,$7,$8,$9}' | sort | uniq -c | sort -rn | head -n 30 | sed '/^$/d' >> $FILE; 
		done;
	fi;
	echo "" >>$FILE;
	if [ $SSHDLOGS = "y" ]; then
		echo "SSHD Login Sources:" >>$FILE; 
		for u in `grep "sshd:session): session opened for user" /var/log/auth.log | awk '{print $11}' | sort | uniq`; do echo $u >> $FILE && grep "publickey for $u from" /var/log/auth.log | awk '{print$6,$7,$8,"user: "$9,$10,$11,$14,$15,$16}' | sort | uniq -c | sed '/^$/d' >> $FILE; 
		done;
	fi;
	echo "" >>$FILE;
	if [ $POSTFIXLOGS = "y" ]; then
		echo "Postfix client Sources:" >> $FILE;
		zgrep status=sent mail.log* 2>/dev/null | awk '{ print $7,$8}' | sort | uniq -c | sed '/^$/d'>> $FILE;
	fi
fi;

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
# end of scripted enumeration
# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
chmod 600 $FILE;
echo >> $FILE;
echo >> $FILE;
echo "EOF -- End of File" >> $FILE; 
echo "Output file is: $FILE"
