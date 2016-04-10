#!/bin/bash
#need openvpn and cifs-utils packets
MNTDIR="/media/shvepsy.ru"
OPTDIR="/opt/vpnconf"

if [ $EUID -ne 0 ]; then
  echo "You must be root" 2>&1
  exit 1;
fi

start() {
/bin/mkdir $OPTDIR &>/dev/null

cat << EOF > $OPTDIR/rt.ovpn
remote shvepsy.ru
 dev tun
 ifconfig 10.9.0.2 10.9.0.1
 #ifconfig 192.168.1.11 192.168.1.10
 secret "$OPTDIR/static.key"
 keepalive 10 120
 comp-lzo
 ping-timer-rem
 persist-tun
 persist-key
 route 192.168.1.0 255.255.255.0
EOF

cat << EOF > $OPTDIR/static.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
-----END OpenVPN Static key V1-----
EOF

/usr/bin/killall openvpn &>/dev/null
/usr/sbin/openvpn $OPTDIR/rt.ovpn &>/dev/null &

/bin/mkdir $MNTDIR &>/dev/null
/bin/mount -t cifs //192.168.1.1/disk_a1/ $MNTDIR -o guest &>/dev/null
}

stop() {
/bin/umount -f $MNTDIR &>/dev/null
/bin/rmdir $MNTDIR &>/dev/null
/usr/bin/killall openvpn &>/dev/null
/bin/rm -rf $OPTDIR/ &>/dev/null
}

case "$1" in

"start")
start
;;

"stop")
stop
;;

"restart")
stop
start
;;

"status")
if [ -d $MNTDIR ];
then
	echo "Started"
else
	echo "Stoped"
fi
;;
*)
echo $"Usage: $0 {start|stop|restart|status}"
;;
esac

