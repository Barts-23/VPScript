#!/bin/bash
# Created by https://www.hostingtermurah.net
# Modified by iamBARTX™️

#Requirement
if [ ! -e /usr/bin/curl ]; then
   yum -y update && yum -y upgrade
   yum -y install curl
fi

# initializing var
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd

# setting repo
wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
wget http://rpms.remirepo.net/enterprise/remi-release-7.rpm
rpm -Uvh epel-release-latest-7.noarch.rpm
rpm -Uvh remi-release-7.rpm
wget http://repository.it4i.cz/mirrors/repoforge/redhat/el7/en/x86_64/rpmforge/RPMS/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
rpm -Uvh rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
sed -i 's/enabled = 1/enabled = 0/g' /etc/yum.repos.d/rpmforge.repo
sed -i -e "/^\[remi\]/,/^\[.*\]/ s|^\(enabled[ \t]*=[ \t]*0\\)|enabled=1|" /etc/yum.repos.d/remi.repo
rm -f *.rpm

# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime

# disable se linux
echo 0 > /selinux/enforce
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service sshd restart

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.d/rc.local

#Add DNS Server ipv4
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 1.1.1.1" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 1.0.0.1" >> /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 1.1.1.1" > /etc/resolv.conf' /etc/rc.d/rc.local
sed -i '$ i\echo "nameserver 1.0.0.1" >> /etc/resolv.conf' /etc/rc.d/rc.local

# install wget and curl
yum -y install nano wget curl

# install fail2ban
yum -y install fail2ban
service fail2ban restart
chkconfig fail2ban on

# install dropbear
yum -y install dropbear
echo "OPTIONS=\"-p 109 -p 442\"" > /etc/sysconfig/dropbear
service dropbear restart
chkconfig dropbear on

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
# setting port ssh
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
service sshd restart
chkconfig sshd on

# install ddos deflate
cd
wget http://www6.atomicorp.com/channels/atomic/centos/7/x86_64/RPMS/grepcidr-2.0-1.el7.art.x86_64.rpm
rpm -Uvh grepcidr-2.0-1.el7.art.x86_64.rpm
yum install grepcidr
yum -y install dnsutils bind-utils dsniff unzip net-snmp net-snmp-utils tcpdump
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip
unzip master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/master.zip
cd

# setting banner
rm /etc/issue.net -f
wget -O /etc/issue.net "https://pastebin.com/raw/5S04wFB7"
sed -i '/Banner/a Banner="/etc/banner"' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear
service sshd restart
service dropbear restart

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/shigeno143/OCSPanelCentos6/master/badvpn-udpgw64"
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.d/rc.local
chmod +x /usr/bin/badvpn-udpgw
yum install screen -y
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# Stunnel Ports
Stunnel_Port1='143' # through Dropbear
Stunnel_Port2='440' # through OpenSSH

# OpenVPN Ports
OpenVPN_Port1='110'
OpenVPN_Port2='1194'

# install openvpn
yum -y install openvpn

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# ScriptBartX

port MyOvpnPort1
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.16.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# ScriptBartX

port MyOvpnPort2
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
duplicate-cn
dh none
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 172.17.0.0 255.255.0.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIID0jCCAzugAwIBAgIJALnVZsGmA5VVMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD
VQQGEwJQSDEOMAwGA1UECAwFQklLT0wxDTALBgNVBAcMBE5hZ2ExFDASBgNVBAoM
C1NjcmlwdEJhcnRzMSQwIgYDVQQLDBtodHRwczovL2dpdGh1Yi5jb20vQmFydHMt
MjMxETAPBgNVBAMMCElBTUJBUlRYMSEwHwYJKoZIhvcNAQkBFhJpYW1iYXJ0eEBn
bWFpbC5jb20wHhcNMjAwODE5MTUzNDM3WhcNNDgwMTA0MTUzNDM3WjCBnjELMAkG
A1UEBhMCUEgxDjAMBgNVBAgMBUJJS09MMQ0wCwYDVQQHDAROYWdhMRQwEgYDVQQK
DAtTY3JpcHRCYXJ0czEkMCIGA1UECwwbaHR0cHM6Ly9naXRodWIuY29tL0JhcnRz
LTIzMREwDwYDVQQDDAhJQU1CQVJUWDEhMB8GCSqGSIb3DQEJARYSaWFtYmFydHhA
Z21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbIUbQYcSduz0B
HdaLDGUxByjbdS7R8RQBUmsGbdhZFDSAsqlesgDPfkWO3lUHlUxVf5z3S/aJIvpk
dUeG80p0bHgqJBbkaJWdZzlqS47WPr5N9mkzx7ZxOel5zLTsXGL316SbqKuSXP9K
8FysbxNUOqQw+0PcRR9qRGWFU/d1jQIDAQABo4IBFDCCARAwHQYDVR0OBBYEFKfS
tTje+kKpL1hc2Dt2RaV1yeklMIHTBgNVHSMEgcswgciAFKfStTje+kKpL1hc2Dt2
RaV1yekloYGkpIGhMIGeMQswCQYDVQQGEwJQSDEOMAwGA1UECAwFQklLT0wxDTAL
BgNVBAcMBE5hZ2ExFDASBgNVBAoMC1NjcmlwdEJhcnRzMSQwIgYDVQQLDBtodHRw
czovL2dpdGh1Yi5jb20vQmFydHMtMjMxETAPBgNVBAMMCElBTUJBUlRYMSEwHwYJ
KoZIhvcNAQkBFhJpYW1iYXJ0eEBnbWFpbC5jb22CCQC51WbBpgOVVTAMBgNVHRME
BTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOBgQBwdEQ1WxL+CFnu
TXpxBDxCAdVt0wx/BajZoUTFQNx+ayLvbMZG/u39blTYlZZ/Q2VRFw6wa+VRviDk
qLaAs4jTq/IhomRM5eEZRvcCx7sgs5zu3ggD6HFZqrlrTS7XKxBgASkuJtT/DiT8
u37RrsJDD4VPMq8d+Jc0HqPwdatkKg==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/xbarts.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            77:4a:a5:72:b1:bf:cb:e3:9e:77:75:7d:02:96:eb:e3
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=BIKOL, L=Naga, O=ScriptBarts, OU=https://github.com/Barts-23, CN=IAMBARTX/emailAddress=iambartx@gmail.com
        Validity
            Not Before: Aug 19 15:34:54 2020 GMT
            Not After : Jan  4 15:34:54 2048 GMT
        Subject: C=PH, ST=BIKOL, L=Naga, O=ScriptBarts, OU=https://github.com/Barts-23, CN=server/emailAddress=iambartx@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:a7:b4:a7:d4:25:46:3d:0c:f0:55:9b:32:cb:8b:
                    92:e2:d6:d4:d8:09:c2:60:14:30:1b:27:95:76:87:
                    4e:9e:3e:b1:0c:c9:98:02:77:a1:ec:e8:c3:92:6d:
                    b4:e9:86:19:76:35:71:7d:2b:91:70:c0:9b:f3:b7:
                    30:1a:53:12:e0:d8:5e:7b:0c:65:f0:60:36:22:d3:
                    9e:49:ff:2a:74:04:33:ba:f7:a2:98:02:f4:1f:2c:
                    32:d3:c1:be:af:f1:8a:8b:72:fb:7e:8f:4d:73:30:
                    d3:3b:d3:79:77:14:96:37:e4:45:82:6f:a3:3a:05:
                    a1:db:78:13:d5:f0:31:51:89
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                9C:3B:FA:35:9F:A8:21:33:97:83:2F:E4:82:85:39:7E:B6:36:8B:72
            X509v3 Authority Key Identifier: 
                keyid:A7:D2:B5:38:DE:FA:42:A9:2F:58:5C:D8:3B:76:45:A5:75:C9:E9:25
                DirName:/C=PH/ST=BIKOL/L=Naga/O=ScriptBarts/OU=https://github.com/Barts-23/CN=IAMBARTX/emailAddress=iambartx@gmail.com
                serial:B9:D5:66:C1:A6:03:95:55

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         12:ba:a0:bc:95:0f:29:95:84:48:7c:01:ee:04:e1:8c:57:1b:
         08:8d:08:0e:cd:14:f0:5a:50:59:13:f9:04:64:d0:37:96:b0:
         1d:b7:7f:62:2f:03:78:12:1a:ec:93:bd:9c:0b:15:b8:71:c7:
         2d:75:50:56:3f:13:94:22:0a:e3:de:e3:a1:1e:33:49:e4:76:
         d6:91:ad:e7:10:72:80:c8:38:67:70:90:cb:b7:21:49:32:a3:
         fc:95:ef:d7:0d:97:87:cc:40:72:d5:42:1f:d9:9c:a7:ba:8b:
         5e:f9:69:4f:3d:c6:da:6c:e1:8d:96:cc:ad:66:50:f3:5c:db:
         74:fd
-----BEGIN CERTIFICATE-----
MIID/DCCA2WgAwIBAgIQd0qlcrG/y+Oed3V9Apbr4zANBgkqhkiG9w0BAQsFADCB
njELMAkGA1UEBhMCUEgxDjAMBgNVBAgMBUJJS09MMQ0wCwYDVQQHDAROYWdhMRQw
EgYDVQQKDAtTY3JpcHRCYXJ0czEkMCIGA1UECwwbaHR0cHM6Ly9naXRodWIuY29t
L0JhcnRzLTIzMREwDwYDVQQDDAhJQU1CQVJUWDEhMB8GCSqGSIb3DQEJARYSaWFt
YmFydHhAZ21haWwuY29tMB4XDTIwMDgxOTE1MzQ1NFoXDTQ4MDEwNDE1MzQ1NFow
gZwxCzAJBgNVBAYTAlBIMQ4wDAYDVQQIDAVCSUtPTDENMAsGA1UEBwwETmFnYTEU
MBIGA1UECgwLU2NyaXB0QmFydHMxJDAiBgNVBAsMG2h0dHBzOi8vZ2l0aHViLmNv
bS9CYXJ0cy0yMzEPMA0GA1UEAwwGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJpYW1i
YXJ0eEBnbWFpbC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKe0p9Ql
Rj0M8FWbMsuLkuLW1NgJwmAUMBsnlXaHTp4+sQzJmAJ3oezow5JttOmGGXY1cX0r
kXDAm/O3MBpTEuDYXnsMZfBgNiLTnkn/KnQEM7r3opgC9B8sMtPBvq/xioty+36P
TXMw0zvTeXcUljfkRYJvozoFodt4E9XwMVGJAgMBAAGjggE5MIIBNTAJBgNVHRME
AjAAMB0GA1UdDgQWBBScO/o1n6ghM5eDL+SChTl+tjaLcjCB0wYDVR0jBIHLMIHI
gBSn0rU43vpCqS9YXNg7dkWldcnpJaGBpKSBoTCBnjELMAkGA1UEBhMCUEgxDjAM
BgNVBAgMBUJJS09MMQ0wCwYDVQQHDAROYWdhMRQwEgYDVQQKDAtTY3JpcHRCYXJ0
czEkMCIGA1UECwwbaHR0cHM6Ly9naXRodWIuY29tL0JhcnRzLTIzMREwDwYDVQQD
DAhJQU1CQVJUWDEhMB8GCSqGSIb3DQEJARYSaWFtYmFydHhAZ21haWwuY29tggkA
udVmwaYDlVUwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWgMBEGA1Ud
EQQKMAiCBnNlcnZlcjANBgkqhkiG9w0BAQsFAAOBgQASuqC8lQ8plYRIfAHuBOGM
VxsIjQgOzRTwWlBZE/kEZNA3lrAdt39iLwN4Ehrsk72cCxW4ccctdVBWPxOUIgrj
3uOhHjNJ5HbWka3nEHKAyDhncJDLtyFJMqP8le/XDZeHzEBy1UIf2Zynuote+WlP
PcbabOGNlsytZlDzXNt0/Q==
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/xbarts.key
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKe0p9QlRj0M8FWb
MsuLkuLW1NgJwmAUMBsnlXaHTp4+sQzJmAJ3oezow5JttOmGGXY1cX0rkXDAm/O3
MBpTEuDYXnsMZfBgNiLTnkn/KnQEM7r3opgC9B8sMtPBvq/xioty+36PTXMw0zvT
eXcUljfkRYJvozoFodt4E9XwMVGJAgMBAAECgYBiMSBi0kBB1qWROgGPs/UY4/hT
VcN9RdS00YRtleOuO76mYhKivzEL6W04+wsGAAJAeCIuy6eogN3O4N9FSoauNNq+
Om95WGLY+OWE9H61Y+UioafqMRN6CFiSvy1a0inOclunBljcf68uZIkeKgTPoc0v
osNfuCas7LfO48XPkQJBANFoKHsAqdYvbF+/RZqVfd5sqXMUPNCww9YeQsGz3mBp
yp+Tx7T+wGUKGKZzD9fqwN2+z0kP1QYtkCSF4pRL4ZMCQQDNBTFc0AWBietYonsN
ewllx+D72k5Tt2TdSBOhYsoZFu28ybkiagGLDBsQsAdpsjSc7HiaBsuiyLjS16kK
eOHzAkEAmnLZUIeXvFrz8tavbqmN0YyRmkg15rJJbtaY5CdXAANnKDWmGU+/9YXx
0mqRJ+6EW8jNOBUOSGU4qEd7a2dgMwJABUyjEAEYg1arTKk2gQyzG3xlJl1oNOXC
p62bREqnaqqbDowwSuFulMeFU5MZPfQrQ/sgyupuDREfJeQJLIofXQJBAKpVRR0G
JFriv/ukvYSEiw4bgneXbKtTjvXVE5B518RSPaaLEdz7agCJZ3yGWt8Hw3L1GEHE
1Z9t3f/rftuj+4U=
-----END PRIVATE KEY-----
EOF10

# setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf

#forward ipv4
sysctl -w net.ipv4.ip_forward=1
touch /usr/lib/sysctl.d/sysctl.conf
cat > /usr/lib/sysctl.d/sysctl.conf <<-END
net.ipv4.ip_forward = 1
END
systemctl restart network.service
systemctl -f enable openvpn@server.service
systemctl start openvpn@server.service
systemctl status openvpn@server.service
chkconfig openvpn on


##################squid3.1.23
cd

#dependencies
yum install -y binutils gcc-c++
yum install -y perl gcc autoconf automake make sudo wget
yum install -y libxml2-devel libcap-devel
yum install -y libtool-ltdl-devel
 
#Downloading Squid Source Archive
mkdir /usr/src/squid
cd /usr/src/squid
wget http://www.squid-cache.org/Versions/v3/3.1/squid-3.1.23.tar.gz
tar fxvz squid-3.1.23.tar.gz
cd squid-3.1.23
 
#Compiling Squid Proxy
./configure --prefix=/usr --includedir=/usr/include --datadir=/usr/share --bindir=/usr/sbin --libexecdir=/usr/lib/squid --localstatedir=/var --sysconfdir=/etc/squid --enable-delay-pools --enable-arp-acl --enable-linux-netfilter && echo "Configuration Successful"
make clean
make -j4
make install
 
#create files for squid's default user nobody
touch /var/cache/squid
chown -R nobody:nobody /var/cache/squid
touch /var/logs/cache.log
chown nobody:nobody /var/logs/cache.log
touch /var/logs/access.log
chown -R nobody:nobody /var/logs/access.log
tail -f /var/logs/cache.log &
#Create missing swap directories and other missing cache_dir structures
/usr/sbin/squid -z
#start squid
/usr/sbin/squid
 
#Automatic starting Squid service on start-up using shell script
cat > /etc/rc.d/init.d/squid <<-END
#!/bin/bash
# init script to control Squid server
case "$1" in
start)
/usr/sbin/squid
;;
stop)
/usr/sbin/squid -k shutdown
;;
reload)
/usr/sbin/squid -k reconfigure
;;
restart)
/usr/sbin/squid -k shutdown
sleep 2
/usr/sbin/squid
;;
*)
echo $"Usage: $0 {start|stop|reload|restart}"
exit 2
esac
exit $?
END
 
#command to start squid service
echo /usr/sbin/squid >> /etc/rc.local
chmod +x /etc/rc.local
 
#modify squid.conf
cat > /etc/squid/squid.conf <<-END
# High Anonymous Elite Proxy
# Squid config


cache_mem 6 MB
#cache_swap_low 98%
#cache_swap_high 99%
half_closed_clients off
#maximum_object_size 1024 KB
maximum_object_size 16 MB
minimum_object_size 512 bytes
maximum_object_size_in_memory 1 MB
store_avg_object_size 15 KB

ipcache_size 512
ipcache_low 98
ipcache_high 99

#cache_replacement_policy lru
#memory_replacement_policy lru
cache_replacement_policy heap LFUDA
memory_replacement_policy heap GDSF

cache_log /dev/null
cache_store_log /dev/null

refresh_pattern -i .(class|css|js|gif|jpg)$ 10080 100% 43200
refresh_pattern -i .(jpe|jpeg|png|bmp|tif)$ 10080 100% 43200
refresh_pattern -i .(tiff|mov|avi|qt|mpeg)$ 10080 100% 43200
refresh_pattern -i .(mpg|mpe|wav|au|mid)$ 10080 100% 43200
refresh_pattern -i .(zip|gz|arj|lha|lzh)$ 10080 100% 43200
refresh_pattern -i .(rar|tgz|tar|exe|bin)$ 10080 100% 43200
refresh_pattern -i .(hqx|pdf|rtf|doc|swf)$ 10080 100% 43200
refresh_pattern -i .(inc|cab|ad|txt|dll)$ 10080 100% 43200
refresh_pattern -i .(asp|acgi|pl|shtml|php3|php)$ 2 20% 43200
refresh_pattern ^http://*.facebook.*/.* 720 100% 10080
refresh_pattern ^http://*.friendster.*/.* 720 100% 10080
refresh_pattern ^http://*.google.*/.* 720 100% 10080
refresh_pattern ^http://*.akamai.*/.* 720 100% 10080
refresh_pattern ^http://*.ytimg.*/.* 720 100% 10080
refresh_pattern ^http://*.fbcdn.net/.* 720 100% 10080
refresh_pattern ^http://mail.yahoo.com/.* 720 100% 10080
refresh_pattern ^http://*.yahoo.*/.* 720 100% 7200
refresh_pattern ^http://*.google-analytics.*/.* 720 100% 10080
refresh_pattern ^http://*.googlesyndication.*/.* 720 100% 10080
refresh_pattern ^http://*.wordpress.com/.* 720 80% 10080
refresh_pattern ^http://*.twitter.com/.* 720 80% 10080
refresh_pattern -i .google.co.id$ 1440 100% 10080
refresh_pattern -i \.flv$ 10080 90% 999999
refresh_pattern -i .co.id$ 1440 100% 10080
refresh_pattern -i .mail.yahoo$ 1440 100% 3500
refresh_pattern ^http://i(.*/?%29.photobucket.com%2Falbums%2F%28.%2A%3F%29%2F%28.%2A%3F%29%2F%28.%2A%3F%29\? 43200 90% 999999
refresh_pattern ^http://vid(.*/?%29.photobucket.com%2Falbums%2F%28.%2A%3F%29%2F%28.%2A%3F%29\? 43200 90% 999999
refresh_pattern ^http://*.indowebster.com.*/.* 720 100% 10080
refresh_pattern ^http://*.blogsome.com/.* 720 80% 10080
refresh_pattern ^http://*.gmail.*/.* 720 100% 4320
refresh_pattern ^http://*.blogspot.com/.* 720 100% 4320
refresh_pattern ^http://*.detik.com/.* 720 100% 4320
refresh_pattern ^http://*.detik.*/.* 720 100% 4320
refresh_pattern ^http://*.kompas.com/.* 720 100% 4320
refresh_pattern ^http://*.metrotvnews.com/.* 720 100% 4320
refresh_pattern ^http://*.multiply.*/.* 720 100% 7200
refresh_pattern ^http://*.wikipedia.*/.* 720 80% 10080
refresh_pattern ^http://*.kaskus.*/.* 720 100% 28800
refresh_pattern ^http://*.imperiaonline.org/.* 720 100% 28800
refresh_pattern ^http://*.telkom.*/.* 720 90% 10080
refresh_pattern ^http://*.astaga.*/.* 720 90% 10080
refresh_pattern ^http://*.okezone.*/.* 720 90% 2880
refresh_pattern ^http://*.kapanlagi.*/.* 720 90% 2880
refresh_pattern ^http://*.tvone.*/.* 720 90% 10080
refresh_pattern ^http://*.tribunjabar.*/.* 720 90% 10080

refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern ^ftp: 10080 95% 241920

refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320


forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all
http_access deny all
http_port 0.0.0.0:44355
http_port 0.0.0.0:25222
dns_nameservers 8.8.8.8 1.0.0.1

END
sed -i $MYIP2 /etc/squid/squid.conf;

# install firewalld
yum -y install firewalld
systemctl start firewalld
systemctl enable firewalld
firewall-cmd --quiet --set-default-zone=public
firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
firewall-cmd --quiet --reload
firewall-cmd --quiet --add-masquerade
firewall-cmd --quiet --permanent --add-masquerade
firewall-cmd --quiet --permanent --add-service=ssh
firewall-cmd --quiet --permanent --add-service=openvpn
firewall-cmd --quiet --permanent --add-service=http
firewall-cmd --quiet --permanent --add-service=https
firewall-cmd --quiet --permanent --add-service=privoxy
firewall-cmd --quiet --permanent --add-service=squid
firewall-cmd --quiet --reload

# install nginx
yum install nginx -y

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/bonveio-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/bonveio-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 
cat <<EOF152> /var/www/openvpn/GTMConfig.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Squid_Port1
http-proxy-option CUSTOM-HEADER Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For redirect.googlevideo.com

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152

cat <<EOF16> /var/www/openvpn/SunConfig.ovpn
client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port2
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16

cat <<EOF160> /var/www/openvpn/SunTCPPConfig.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port2
remote-cert-tls server
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
keysize 0
comp-lzo
setenv CLIENT_CERT 0
reneg-sec 0
verb 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF160

cat <<EOF17> /var/www/openvpn/SunNoloadConfig.ovpn
client
dev tun
proto tcp-client
remote $IPADDR $OpenVPN_Port1
remote-cert-tls server
bind
float
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
keysize 0
comp-lzo
reneg-sec 0
verb 0
nice -20
log /dev/null
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- OVPN Download site by iamBARTX -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS</span><br /><small> For EZ/GS Promo with WNP,SNS,FB and IG freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTMConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For TU Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SunConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Modem</span><br /><small> TU Promo TCP</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/SunTCPConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r Configs.zip *.ovpn
 cd
}

 # Setting our startup script to run every machine boots 
 echo "[Unit]
Description=Barts Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/barts/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/barts.service
 chmod +x /etc/systemd/system/barts.service
 systemctl daemon-reload
 systemctl start barts
 systemctl enable barts &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}

function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/Barts-23/menu1/master/menu.zip'
unzip -qq menu.zip
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~

echo 'clear' > /etc/profile.d/barts.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/barts.sh
echo 'screenfetch -p -A Android' >> /etc/profile.d/barts.sh
chmod +x /etc/profile.d/barts.sh
}

function ScriptMessage(){
 echo -e " (｡◕‿◕｡) $MyScriptName Centos VPS Installer"
 echo -e " Open release version"
 echo -e ""
 echo -e " Script created by Bonveio"
 echo -e " Edited by iamBARTX"
}


#############################
#############################
## Installation Process
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/barts.sh
 
 # Showing script's banner message
 ScriptMessage

echo "Application & Port Information
   - OpenVPN     : TCP 1194 
   - OpenSSH     : 22, 143, 90
   - Dropbear    : 109, 110, 442
   - Squid Proxy : 80, 8000, 8080, 8888, 3128 (limit to IP Server)
   - Badvpn      : 7300
Script Compiled By Tacome9 (https://www.phcorner.net/members/228541/)"
END

#clearing history
history -c

#restart squid
/usr/sbin/squid -k shutdown
/usr/sbin/squid

