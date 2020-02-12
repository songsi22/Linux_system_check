#!/bin/bash

################################################################################################
# Name of the script : Linux_System_check_IBM.sh
# Date               : last update 13/Jan/2020
# Version 			 : v1.1
#
# Written by Uktae Kim of IBM Korea Technical Solutions
#
# This script checks current status of linux server, and compare with now and
# before server status data. This script executes several commands, so there
# may be a little bit system load for a very short time.
#
# This script needs to install some packages (sysstat, pciutils, net-tools, lsscsi)
# If you don't install the packages, it won't execute some commands.
#
# Change History :
# 10/Jan/2020 - v1.0 First created for HANHWA
# 07/Feb/2020 - v1.1 Compatibility, Functional enhancement
#################################################################################################


########## Environment Variables ##########

export LANG=C
HOST=`/bin/hostname`
TODAY=`/bin/date +%Y%m%d-%H%M%S`
LOGRESULT="/IBM_System_check/Result"
tmp_file=$LOGRESULT/$TODAY.$HOST.system_check.log
SCRIPTNAME=$0
LOGRESOURCE=$LOGRESOURCE
CHKDATE_NOW=`date "+%Y%m"`
CHKDATE_BEFORE=`date -d "-1 months" "+%Y%m"`
OSCHK=`uname -r | awk -F '.' '{print $1}'`
CHKID=`id | grep root | wc -l`
CLUSTERCHK=`rpm -qa | egrep "pacemaker|rgmanager" | awk -F '-' '{print $1}' | sed -n '1p'`
CHKNTP=`ps -ef | grep -v grep | grep -c ntp`
CHKCHRONY=`ps -ef | grep -v grep | grep -c chrony`


########### User Check Procedure ##########

if [ $CHKID -eq 0 ]; then
  echo
  echo "You must login as root... Try again."
  echo
  exit
fi

########### IBM_System_check directory create once ##########
# This part prepares system environment to use the script "Linux_system_check.sh"
# This part simply creates and copy some directories, files. so there are no affect to system.

if [ -d '/IBM_System_check' ] ; then
  echo -e "\n"
else
  mkdir -p $LOGRESOURCE
  mkdir -p $LOGRESULT
  mv ./$0 /IBM_System_check/Linux_System_check_IBM.sh
  chmod 700 /IBM_System_check/Linux_System_check_IBM.sh
fi

function logoutput
{
########## Begin executing Script ##########
clear
echo -e "\nBegining The script : $SCRIPTNAME"
echo -e "It may take several minutes..\n"
echo "$SCRIPTNAME" 
echo "Collect Date : "$TODAY  
echo -e "\n"  
mkdir $LOGRESOURCE/$CHKDATE_NOW


########## Basic Information ##########

echo "**************************************************************************"  
echo "BASIC INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== HOSTNAME =="  
hostname  
echo -e "\n"  

echo "== OS VERSION =="  
if [ -f /etc/redhat-release ];
then
  cat /etc/redhat-release  
else
  cat /etc/centos-release  
fi
echo -e "\n"  

echo "== KERNEL VERSION =="  
uname -r  
echo -e "\n"  

echo "== SYSTEM INFORMATION =="  
dmidecode -t system | egrep "Manufacturer|Product|Serial" | sed -e 's/\s//g'  
echo -e "\n"  


########## Hardware Information ##########

echo "**************************************************************************"  
echo "HARDWARE INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== lspci CHANGES =="  
lspci  $LOGRESOURCE/$CHKDATE_NOW/lspci
diff $LOGRESOURCE/$CHKDATE_BEFORE/lspci $LOGRESOURCE/$CHKDATE_NOW/lspci  
echo -e "\n"  

########## CPU Information ##########

echo "**************************************************************************"  
echo "CPU INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== CPU dmidecode CHANGES =="  
dmidecode -t processor | egrep "Version|Core|Thread"  $LOGRESOURCE/$CHKDATE_NOW/dmidecode_cpu
diff $LOGRESOURCE/$CHKDATE_BEFORE/dmidecode_cpu $LOGRESOURCE/$CHKDATE_NOW/dmidecode_cpu  
echo -e "\n"  

echo "== cpuinfo CHANGES =="  
cat /proc/cpuinfo  $LOGRESOURCE/$CHKDATE_NOW/cpuinfo
diff $LOGRESOURCE/$CHKDATE_BEFORE/cpuinfo $LOGRESOURCE/$CHKDATE_NOW/cpuinfo  
echo -e "\n"  


########## MEMORY INFORMATION ##########

echo "**************************************************************************"  
echo "MEMORY INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== MEMORY USAGE =="  
free -m  
echo -e "\n"  

echo "== SWAP CHANGES =="  
swapon -s | awk {'print $1"   "$2"   "$3'}  $LOGRESOURCE/$CHKDATE_NOW/swapons
diff $LOGRESOURCE/$CHKDATE_BEFORE/swapons $LOGRESOURCE/$CHKDATE_NOW/swapons  
echo -e "\n"  

echo "== CORRUPTED MEMORY =="  
cat /proc/meminfo | grep -i "HardwareCorrupted"  
echo -e "\n"  

echo "== MEMORY dmidecode CHANGES =="  
dmidecode -t memory | egrep "Installed|Enabled"  $LOGRESOURCE/$CHKDATE_NOW/dmidecode_mem
diff $LOGRESOURCE/$CHKDATE_BEFORE/dmidecode_mem $LOGRESOURCE/$CHKDATE_NOW/dmidecode_mem  
echo -e "\n"  


########## BOOTING CONFIGURATION ##########

echo "**************************************************************************"  
echo "BOOTING CONFIGURATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== UPTIME =="  
uptime  
echo -e "\n"  

echo "== grub.cfg CHANGES =="  
if [ -f /boot/efi/EFI/redhat/grub.cfg ]; then
  cat /boot/efi/EFI/redhat/grub.cfg  $LOGRESOURCE/$CHKDATE_NOW/grub-cfg
elif [ -d /boot/efi/EFI/centos/grub.cfg ]; then
  cat /boot/efi/EFI/centos/grub.cfg  $LOGRESOURCE/$CHKDATE_NOW/grub-cfg
else
  cat /boot/grub2/grub.cfg  $LOGRESOURCE/$CHKDATE_NOW/grub-cfg
fi
diff $LOGRESOURCE/$CHKDATE_BEFORE/grub-cfg $LOGRESOURCE/$CHKDATE_NOW/grub-cfg  
echo -e "\n"  

echo "== grub Prameter CHANGES =="  
cat /proc/cmdline  $LOGRESOURCE/$CHKDATE_NOW/grub_cmdline
diff $LOGRESOURCE/$CHKDATE_BEFORE/grub_cmdline $LOGRESOURCE/$CHKDATE_NOW/grub_cmdline  
echo -e "\n"  

echo "== Booting Target CHANGES =="  
if [ $OSCHK -eq 3 ];
then
   systemctl get-default  $LOGRESOURCE/$CHKDATE_NOW/get-default
   diff $LOGRESOURCE/$CHKDATE_BEFORE/get-default $LOGRESOURCE/$CHKDATE_NOW/get-default  
else
   who -r  $LOGRESOURCE/$CHKDATE_NOW/who_r
   diff $LOGRESOURCE/$CHKDATE_BEFORE/who_r $LOGRESOURCE/$CHKDATE_NOW/who_r  
fi
echo -e "\n"  

echo "== fstab CHANGES =="  
cat /etc/fstab  $LOGRESOURCE/$CHKDATE_NOW/fstab
diff $LOGRESOURCE/$CHKDATE_BEFORE/fstab $LOGRESOURCE/$CHKDATE_NOW/fstab  
echo -e "\n"  

echo "== rc.local CHANGES =="  
cat /etc/rc.local  $LOGRESOURCE/$CHKDATE_NOW/rc_local
diff $LOGRESOURCE/$CHKDATE_BEFORE/rc_local $LOGRESOURCE/$CHKDATE_NOW/rc_local  
echo -e "\n"  


########## SYSTEM ENVIRONMENT INFORMATION ##########

echo "**************************************************************************"  
echo "SYSTEM ENVIRONMENT INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== selinux CHANGES =="  
cat /etc/selinux/config  $LOGRESOURCE/$CHKDATE_NOW/selinux
diff $LOGRESOURCE/$CHKDATE_BEFORE/selinux $LOGRESOURCE/$CHKDATE_NOW/selinux  
echo -e "\n"  

echo "== sysctl CHANGES =="  
cat /etc/sysctl.conf  $LOGRESOURCE/$CHKDATE_NOW/sysctl_conf
diff $LOGRESOURCE/$CHKDATE_BEFORE/sysctl_conf $LOGRESOURCE/$CHKDATE_NOW/sysctl_conf  
echo -e "\n"  

echo "== GLOBAL ENVIRONMENT CHANGES =="  
echo -e "\n"  
echo "/etc/profile"  
cat /etc/profile  $LOGRESOURCE/$CHKDATE_NOW/profile
diff $LOGRESOURCE/$CHKDATE_BEFORE/profile $LOGRESOURCE/$CHKDATE_NOW/profile  
echo -e "\n"  
echo "/etc/bashrc"  
cat /etc/bashrc  $LOGRESOURCE/$CHKDATE_NOW/bashrc
diff $LOGRESOURCE/$CHKDATE_BEFORE/bashrc $LOGRESOURCE/$CHKDATE_NOW/bashrc  
echo -e "\n"  


########## ACCOUNT INFORMATION ##########

echo "**************************************************************************"  
echo "ACCOUNT INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== SESSIONS NOW CONNECTED =="  
echo "$(last | grep still | wc -l) session connected now."  
echo -e "\n"  

echo "== /etc/passwd CHANGES =="  
cat /etc/passwd  $LOGRESOURCE/$CHKDATE_NOW/account_passwd
diff $LOGRESOURCE/$CHKDATE_BEFORE/account_passwd $LOGRESOURCE/$CHKDATE_NOW/account_passwd  
echo -e "\n"  

echo "== /etc/group CHANGES =="  
cat /etc/group  $LOGRESOURCE/$CHKDATE_NOW/account_group
diff $LOGRESOURCE/$CHKDATE_BEFORE/account_group $LOGRESOURCE/$CHKDATE_NOW/account_group  
echo -e "\n"  


########## STORAGE INFORMATION ##########

echo "**************************************************************************"  
echo "STORAGE INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== FILESYSTEM USAGE OVER 80% =="  
FSTHRESHOLD=80
### Check Filesystem Usage
FS_USE_LISTS=`df -Ph | grep -v Filesystem | awk '{print $6,$5}'`
FSIDX=1
for FSTMP in ${FS_USE_LISTS}; do
        REMNUM=`expr ${FSIDX} % 2`
        if [ ${REMNUM} -ne 0 ]; then
                FS_NAME=${FSTMP}
        else
                FSUSAGESIZE=`echo ${FSTMP} | cut -d ' ' -f 2 | cut -d '%' -f 1`
                #echo ${FSUSAGESIZE}
                if [ ${FSUSAGESIZE} -gt ${FSTHRESHOLD} ]; then
                        echo ''${FS_NAME}' = '${FSUSAGESIZE}'%'  
                fi
        fi
        FSIDX=$((FSIDX+1))
done
echo -e "\n"  

echo "== I-NODE USAGE OVER 80% =="  
INODETHRESHOLD=80
### Check Filesystem Usage
FS_USE_LISTS=`df -Pi | grep -v Filesystem | awk '{print $6,$5}' | grep -v /boot/efi`
INODEIDX=1
for INODETMP in ${FS_USE_LISTS}; do
        REMNUM=`expr ${INODEIDX} % 2`
        if [ ${REMNUM} -ne 0 ]; then
                FS_NAME=${INODETMP}
        else
                INODEUSAGESIZE=`echo ${INODETMP} | cut -d ' ' -f 2 | cut -d '%' -f 1`
                #echo ${INODEUSAGESIZE}
                if [ ${INODEUSAGESIZE} -gt ${INODETHRESHOLD} ]; then
                        echo ''${FS_NAME}' = '${INODEUSAGESIZE}'%'  
                fi
        fi
        INODEIDX=$((INODEIDX+1))
done
echo -e "\n"  

echo "== PV CHANGES =="  
pvs  $LOGRESOURCE/$CHKDATE_NOW/pvs
diff $LOGRESOURCE/$CHKDATE_BEFORE/pvs $LOGRESOURCE/$CHKDATE_NOW/pvs  
echo -e "\n"  

echo "== VG CHANGES =="  
vgs  $LOGRESOURCE/$CHKDATE_NOW/vgs
diff $LOGRESOURCE/$CHKDATE_BEFORE/vgs $LOGRESOURCE/$CHKDATE_NOW/vgs  
echo -e "\n"  

echo "== LV CHANGES =="  
lvs  $LOGRESOURCE/$CHKDATE_NOW/lvs
diff $LOGRESOURCE/$CHKDATE_BEFORE/lvs $LOGRESOURCE/$CHKDATE_NOW/lvs  
echo -e "\n"  

echo "== lvm.conf CHANGES =="  
cat /etc/lvm/lvm.conf  $LOGRESOURCE/$CHKDATE_NOW/lvmconf
diff $LOGRESOURCE/$CHKDATE_BEFORE/lvmconf $LOGRESOURCE/$CHKDATE_NOW/lvmconf  
echo -e "\n"  

echo "== RO mount STATUS =="  
mount | grep ro, | grep -v tmpfs  
echo -e "\n"  

echo "== MULTIPATH STATUS =="  
if [ -f /etc/multipath.conf ];
then
  multipath -ll  
else
  echo "multipath is not installed .."  
fi
echo -e "\n"  

echo "== multipath.conf CHANGES =="  
if [ -f /etc/multipath.conf ];
then
  cat /etc/multipath.conf  $LOGRESOURCE/$CHKDATE_NOW/multipathconf
  diff $LOGRESOURCE/$CHKDATE_BEFORE/multipathconf $LOGRESOURCE/$CHKDATE_NOW/multipathconf  
else
  echo "multipath is not installed .."  
fi
echo -e "\n"  

echo "== multipath WWID CHANGES =="  
if [ -f /etc/multipath.conf ];
then
  cat /etc/multipath/wwids  $LOGRESOURCE/$CHKDATE_NOW/wwids
  diff $LOGRESOURCE/$CHKDATE_BEFORE/wwids $LOGRESOURCE/$CHKDATE_NOW/wwids  
else
  echo "multipath is not installed .."  
fi
echo -e "\n"  

echo "== multipath Bindings CHANGES =="  
if [ -f /etc/multipath.conf ];
then
  cat /etc/multipath/bindings  $LOGRESOURCE/$CHKDATE_NOW/bindings
  diff $LOGRESOURCE/$CHKDATE_BEFORE/bindings $LOGRESOURCE/$CHKDATE_NOW/bindings  
else
  echo "multipath is not installed .."  
fi
echo -e "\n"  

echo "== lsscsi CHANGES =="  
lsscsi --scsi_id  $LOGRESOURCE/$CHKDATE_NOW/lsscsi
diff $LOGRESOURCE/$CHKDATE_BEFORE/lsscsi $LOGRESOURCE/$CHKDATE_NOW/lsscsi  
echo -e "\n"  


########## PACKAGE STATUS ##########
# it marks "#" during test period, because it takes a lot of time.#

echo "**************************************************************************"  
echo "PACKAGE STATUS"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== yum history CHANGES =="  
yum history  $LOGRESOURCE/$CHKDATE_NOW/yumhistory
diff $LOGRESOURCE/$CHKDATE_BEFORE/yumhistory $LOGRESOURCE/$CHKDATE_NOW/yumhistory  
echo -e "\n"  

echo "== last rpm CHANGES =="  
rpm -qa --last  $LOGRESOURCE/$CHKDATE_NOW/rpmlast
diff $LOGRESOURCE/$CHKDATE_BEFORE/rpmlast $LOGRESOURCE/$CHKDATE_NOW/rpmlast  
echo -e "\n"  


########## KDUMP INFORMATION ##########

echo "**************************************************************************"  
echo "KDUMP INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== KDUMP STATUS =="  
if [ $OSCHK -eq 3 ];
then
   systemctl status kdump  
else
   service kdump status  
fi
echo -e "\n"  

echo "== KDUMP FILE CHECK =="  
if [ `ls -artl /boot | grep kdump | wc -l` -eq 0 ];
then
  echo "There is no kdump.img file.."  
else
  ls -artl /boot | grep kdump  
  stat /boot/*kdump.img | grep Modify  
fi
echo -e "\n"  

echo "== crashkernel CHANGES =="  
cat /proc/cmdline | grep crashkernel  $LOGRESOURCE/$CHKDATE_NOW/crashkernel
diff $LOGRESOURCE/$CHKDATE_BEFORE/crashkernel $LOGRESOURCE/$CHKDATE_NOW/crashkernel  
echo -e "\n"  

echo "== KDUMP Configuration CHANGES =="  
cat /etc/kdump.conf  $LOGRESOURCE/$CHKDATE_NOW/kdumpconf
diff $LOGRESOURCE/$CHKDATE_BEFORE/kdumpconf $LOGRESOURCE/$CHKDATE_NOW/kdumpconf  
echo -e "\n"  


########## DAEMON & PROCESS CHECK ##########

echo "**************************************************************************"  
echo "DAEMON & PROCESS CHECK"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== FAILED DAEMON =="  
if [ $OSCHK -eq 3 ];
then
  systemctl --failed  
else
  service --status-all | egrep -i "stop|not|fail|unknown"  
  #the command makes "grep: /proc/fs/nfsd/portlist: No such file or directory" I don't know how to discard this message...
fi
echo -e "\n"  

echo "== ZOMBIE PROCESS CHECK =="  
ps auxw | grep defunct  
echo -e "\n"  


########## NETWORK INFORMATION ##########

echo "**************************************************************************"  
echo "NETWORK INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== PACKET STATUS =="  
ip -s link | grep -v link/ether  
echo -e "\n"  

echo "== NETWORK DEVICE STATUS =="  
ls -artl /etc/sysconfig/network-scripts |grep ifcfg | awk -F 'g-' '{print "ethtool "$2}' | sh | egrep "Setting|Speed|Duplex|detect"  
echo -e "\n"  

echo "== PORT STATUS =="  
if [ `netstat -nap | egrep "CLOSING|FIN-WAIT1|CLOSE-WAIT|FIN-WAIT2|SYN_RECEIVED|SYN-SENT|CLOSED|TIME-WAIT|LAST-ACK|DISCONNECTING" | wc -l` -eq 0 ];
then
  echo "The status of All the ports is optimal."  
else
  netstat -nap | egrep "CLOSING|FIN-WAIT1|CLOSE-WAIT|FIN-WAIT2|SYN_RECEIVED|SYN-SENT|CLOSED|TIME-WAIT|LAST-ACK|DISCONNECTING"  
fi
echo -e "\n"  

echo "== BONDING STATUS =="  
if [ -d /proc/net/bonding ]; then
  IFS=$'\n' ARR=(`ls -artl /etc/sysconfig/network-scripts |grep bond | awk -F 'g-' '{print $2}'`)
  for VALUE in "${ARR[@]}"; do echo "<---- $VALUE ---->"; done &>> /dev/null
  ls -artl /etc/sysconfig/network-scripts |grep bond | awk -F 'g-' '{print $2}' &>> /dev/null
  for value in "${ARR[@]}"; do cat /proc/net/bonding/$value; done | egrep "enp|Status|Speed|Duplex|Bond"  
else
  echo "Bonding isn't configured.."  
fi
echo -e "\n"  

echo "== /etc/hosts CHANGES =="  
cat /etc/hosts  $LOGRESOURCE/$CHKDATE_NOW/hosts
diff $LOGRESOURCE/$CHKDATE_BEFORE/hosts $LOGRESOURCE/$CHKDATE_NOW/hosts  
echo -e "\n"  

echo "== Network device CHANGES =="  
ip a | grep -v valid  $LOGRESOURCE/$CHKDATE_NOW/ipa
diff $LOGRESOURCE/$CHKDATE_BEFORE/ipa $LOGRESOURCE/$CHKDATE_NOW/ipa  
echo -e "\n"  

echo "== route CHANGES =="  
route  $LOGRESOURCE/$CHKDATE_NOW/route
diff $LOGRESOURCE/$CHKDATE_BEFORE/route $LOGRESOURCE/$CHKDATE_NOW/route  
echo -e "\n"  

echo "== DNS CHANGES =="  
cat /etc/resolv.conf  $LOGRESOURCE/$CHKDATE_NOW/resolvconf
diff $LOGRESOURCE/$CHKDATE_BEFORE/resolvconf $LOGRESOURCE/$CHKDATE_NOW/resolvconf  
echo -e "\n"  

echo "== Network script CHANGES =="  
for int in $(ls /etc/sysconfig/network-scripts/ | grep ifcfg)
do
    echo "<-------- $int -------->"  $LOGRESOURCE/$CHKDATE_NOW/netscripts
    cat /etc/sysconfig/network-scripts/$int  $LOGRESOURCE/$CHKDATE_NOW/netscripts
done
diff $LOGRESOURCE/$CHKDATE_BEFORE/netscripts $LOGRESOURCE/$CHKDATE_NOW/netscripts  
echo -e "\n"  


########## TIME SYNC INFORMATION ##########

echo "**************************************************************************"  
echo "TIME SYNC STATUS"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== TIME STATUS =="  
if [ $OSCHK -eq 3 ];
then
   timedatectl  
else
   date  
   cat /etc/sysconfig/clock | grep ZONE  
fi
echo -e "\n"  

echo "== NTP CHANGES =="  
CHKNTP=`ps -ef | grep -v grep | grep -c ntp`
if [ $CHKNTP -eq 1 ];
then
  echo -e "\n"  
  echo -e "/etc/ntp.conf"  
  cat /etc/ntp.conf  $LOGRESOURCE/$CHKDATE_NOW/ntpconf
  diff $LOGRESOURCE/$CHKDATE_BEFORE/ntpconf $LOGRESOURCE/$CHKDATE_NOW/ntpconf  
  echo -e "\n"  
  echo -e "/etc/sysconfig/ntpd"  
  diff $LOGRESOURCE/$CHKDATE_BEFORE/ntpd $LOGRESOURCE/$CHKDATE_NOW/ntpd  
  cat /etc/sysconfig/ntpd  $LOGRESOURCE/$CHKDATE_NOW/ntpd
else
  echo "NTP is not running.."  
fi
echo -e "\n"  

echo "== NTP CHECK =="  
if [ $CHKNTP -eq 1 ];
then
  ntpq -p  
else
  echo "NTP is not running.."  
fi
echo -e "\n"  

echo "== Chrony CHANGES =="  

if [ $CHKCHRONY -eq 1 ];
CHKCHRONY=`ps -ef | grep -v grep | grep -c chrony`
then
  cat /etc/chrony.conf  $LOGRESOURCE/$CHKDATE_NOW/chronyconf
  diff $LOGRESOURCE/$CHKDATE_BEFORE/chronyconf $LOGRESOURCE/$CHKDATE_NOW/chronyconf  
else
  echo "Chrony is not running.."  
fi
echo -e "\n"  

echo "== CHRONY CHECK =="  
if [ $CHKCHRONY -eq 1 ];
then
  chronyc sources -v  
  chronyc tracking  
else
  echo "Chrony is not running.."  
fi
echo -e "\n"  




########## SYSTEM RESOURCE USAGE CHECK##########

echo "**************************************************************************"  
echo "SYSTEM RESOURCE USAGE CHECK"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== SYSTEM RESOURCE USAGE =="  
sar -u -r -d -n DEV 1 5 | grep Average  
echo "NOTE : The check period for average is 10 seconds after execute this script."  
# this NOTE works whether execute sar or not execute. it is problem...
echo -e "\n"  

echo "== CPU USAGE TOP 10 PROCESS =="  
ps -eo user,pid,ppid,rss,size,vsize,pmem,pcpu,time,cmd --sort -pcpu | head -n 10  
echo -e "\n"  

echo "== MEMORY USAGE TOP 10 PROCESS =="  
ps -eo user,pid,ppid,rss,size,vsize,pmem,pcpu,time,cmd --sort -rss | head -n 10  
echo -e "\n"  


########## CLUSTER INFORMATION ##########

echo "**************************************************************************"  
echo "CLUSTER INFORMATION"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== CLUSTER STATUS =="  
case $CLUSTERCHK in
  'rgmanager')
  clustat   2>&1
  ;;
  'pacemaker')
  pcs status   2>&1
  ;;
  *)
  echo "The cluster software is not installed.."  
  ;;
esac
echo -e "\n"  

echo "== Cluster configuration CHANGES =="  
case $CLUSTERCHK in
  'rgmanager')
  cat /etc/cluster/cluster.conf  $LOGRESOURCE/$CHKDATE_NOW/clusterconf
  diff $LOGRESOURCE/$CHKDATE_BEFORE/clusterconf $LOGRESOURCE/$CHKDATE_NOW/clusterconf  
  ;;
  'pacemaker')
  pcs config  $LOGRESOURCE/$CHKDATE_NOW/pcsconfig
  diff $LOGRESOURCE/$CHKDATE_BEFORE/pcsconfig $LOGRESOURCE/$CHKDATE_NOW/pcsconfig  
  ;;
  *)
  echo "The cluster software is not installed.."  
  ;;
esac
echo -e "\n"  


########## SYSTEM LOG ##########

echo "**************************************************************************"  
echo "SYSTEM LOG"  
echo "**************************************************************************"  
echo -e "\n"  

echo "== CRON LOG =="  
if [ `cat /var/log/cron* | egrep -i "fail|error|warning|timeout|imklog" | wc -l` -eq 0 ];
then
  echo "There is no data in /var/log/cron.."  
else
  cat /var/log/cron* | egrep -i "fail|error|warning|timeout|imklog"  
fi
echo -e "\n"  

echo "== MESSAGE LOG =="  
cat /var/log/messages* | egrep -i "fail|error|timeout|imklog|trace:"  
echo -e "\n"  

echo "== DMESG LOG =="  
cat /var/log/dmesg* | egrep -i "fail|error|warning|timeout|bug|imklog|trace:"  
stat /var/log/dmesg | grep Modify   
echo -e "\n"  

echo "== MCELOG =="  
if [ -f /var/log/mcelog ]; then
  stat /var/log/mcelog | grep Modify   
  cat /var/log/mcelog  
else
  echo "There is no mcelog file. (/var/log/mcelog)"  
fi
echo -e "\n"  


########## DONE ##########
}
logoutput > $tmp_file 2> /dev/null
echo -e "\nCollecting date is done.\n"
echo -e "\nATTENTION!"
echo -e "The script file 'IBM_System_check.sh' was moved to /IBM_System_check."
echo -e "When you execute this script later, please enter the /IBM_System_check Directory\n."
echo -e "The Installed script's home directory is '/IBM_System_check'." 
echo -e "The Collected log have been saved to the following path:'$LOGRESULT'\n"
