#!/bin/bash
# Debian 9 and 10 VPS Installer
# Script by Bonveio Abitona
#
# Illegal selling and redistribution of this script is strictly prohibited
# Please respect author's Property
# Binigay sainyo ng libre, ipamahagi nyo rin ng libre.
#
#

#############################
#############################

# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='ScriptBartS'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='225'

# Your SSH Banner
SSH_Banner='https://pastebin.com/raw/5S04wFB7'

# ShadowsocksR Port
Ssr_Port='8443'

# ShadowsocksR Password
Ssr_Pass='xbarts'

# Dropbear Ports
Dropbear_Port1='109'
Dropbear_Port2='442'

# Squid Ports (must be 1024 or higher)
Proxy_Port1='8000'
Proxy_Port2='25222'

# Stunnel Ports
Stunnel_Port1='143' # through Dropbear
Stunnel_Port2='440' # through OpenSSH

# OpenVPN Ports
OpenVPN_Port1='110'
OpenVPN_Port2='1194'
OpenVPN_Port3='465'
OpenVPN_Port4='1987' # take note when you change this port, openvpn sun noload config will not work

# Privoxy Ports (must be 1024 or higher)
Privoxy_Port1='8080'
Privoxy_Port2='8888'
# OpenVPN Config Download Port
OvpnDownload_Port='88' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Manila'
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw -y -f
 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt lsof -y

 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release screenfetch -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl shared-mime-info jq -y -f 2>/dev/null 

 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y -f
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 apt-key del E158C569 &> /dev/null
 wget -qO - https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn-repo.gpg | apt-key add -
 apt update 2>/dev/null
 apt install openvpn git build-essential libssl-dev libnss3-dev cmake python python-dev python-setuptools automake autoconf libtool -y 2>/dev/null

 # L2TP IPSEC SCRIPT DEBUNTU
 wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/l2tp_debuntu.sh' && chmod +x l2tp_debuntu.sh && ./l2tp_debuntu.sh
 rm -f l2tp_debuntu.sh
 wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/add_vpn_user.sh' -O /root/add_vpn_user.sh && chmod +x /root/add_vpn_user.sh
 wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/update_vpn_users.sh' -O ~/update_vpn_users.sh && chmod +x ~/update_vpn_users.sh && ./update_vpn_users.sh
}

function InstWebmin(){
 # Install Webmin
 rm -rf /etc/apt/sources.list.d/webmin*
 echo 'deb https://download.webmin.com/download/repository sarge contrib' > /etc/apt/sources.list.d/webmin.list
 apt-key del 1719003ACE3E5A41E2DE70DFD97A3AE911F63C51 &> /dev/null
 echo -e "Installing Webmin.."
 wget -qO - https://download.webmin.com/jcameron-key.asc | apt-key add - &> /dev/null
 apt update &> /dev/null
 apt install webmin -y 2> /dev/null
 sed -i "s|\(ssl=\).\+|\10|" /etc/webmin/miniserv.conf
 lsof -t -i tcp:10000 -s tcp:listen | xargs kill 2>/dev/null
 systemctl restart webmin &> /dev/null
 systemctl enable webmin &> /dev/null

 # Install BadVPN-udpgw
 curl -4skL "https://github.com/ambrop72/badvpn/archive/4b7070d8973f99e7cfe65e27a808b3963e25efc3.zip" -o /tmp/badvpn.zip
 unzip -qq /tmp/badvpn.zip -d /tmp && rm -f /tmp/badvpn.zip
 cd /tmp/badvpn-4b7070d8973f99e7cfe65e27a808b3963e25efc3
 echo -e "Installing BadVPN-udpgw..."
 cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &> /dev/null
 make install &> /dev/null
 cd ..
 rm -rf /tmp/badvpn-4b7070d8973f99e7cfe65e27a808b3963e25efc3
 cat <<'EOFudpgw' > /lib/systemd/system/badvpn-udpgw.service
[Unit]
Description=BadVPN UDP Gateway Server daemon
Wants=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 4000 --max-connections-for-client 4000 --loglevel info
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFudpgw
 systemctl daemon-reload &>/dev/null
 systemctl restart badvpn-udpgw.service &>/dev/null
 systemctl enable badvpn-udpgw.service &>/dev/null
}

function InstallSSR(){
cat <<'EOFssrinit' > /etc/init.d/shadowsocks
#!/bin/bash

### BEGIN INIT INFO
# Provides:          ShadowsocksR
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Fast tunnel proxy that helps you bypass firewalls
# Description:       Start or stop the ShadowsocksR server
### END INIT INFO

NAME=ShadowsocksR
DAEMON=/usr/local/shadowsocks/server.py
CONF=/etc/shadowsocks.json
RETVAL=0
check_running(){
 PID=$(ps -ef | grep -v grep | grep -i "${DAEMON}" | awk '{print $2}')
 if [ -n "$PID" ]; then
  return 0
 else
  return 1
 fi
}
do_start(){
 check_running
 if [ $? -eq 0 ]; then
  echo "$NAME (pid $PID) is already running..."
  exit 0
 else
  $DAEMON -c $CONF -d start
  RETVAL=$?
  if [ $RETVAL -eq 0 ]; then
   echo "Starting $NAME success"
  else
   echo "Starting $NAME failed"
  fi
 fi
}
do_stop(){
 check_running
 if [ $? -eq 0 ]; then
  $DAEMON -c $CONF -d stop
  RETVAL=$?
  if [ $RETVAL -eq 0 ]; then
   echo "Stopping $NAME success"
  else
   echo "Stopping $NAME failed"
  fi
 else
  echo "$NAME is stopped"
  RETVAL=1
 fi
}
do_status(){
 check_running
 if [ $? -eq 0 ]; then
  echo "$NAME (pid $PID) is running..."
 else
  echo "$NAME is stopped"
  RETVAL=1
 fi
}
do_restart(){
 do_stop
 sleep 0.5
 do_start
}
case "$1" in
 start|stop|restart|status)
 do_$1
 ;;
 *)
 echo "Usage: $0 { start | stop | restart | status }"
 RETVAL=1
 ;;
esac
exit $RETVAL
EOFssrinit
chmod +x /etc/init.d/shadowsocks

libsodium_file="libsodium-1.0.17"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

cd ~
wget --no-check-certificate -qO ${libsodium_file}.tar.gz "${libsodium_url}"
wget --no-check-certificate -qO ${shadowsocks_r_file}.tar.gz "${shadowsocks_r_url}"
if [[ ! -f /usr/lib/libsodium.a ]]; then
 tar xzf "${libsodium_file}.tar.gz"
 rm -f "${libsodium_file}.tar.gz"
 cd "${libsodium_file}"
 ./configure --prefix=/usr
 make -j$(nproc) 2>/dev/null
 make install 2>/dev/null
 cd .. && rm -rf "${libsodium_file}"
fi
tar xzf ${shadowsocks_r_file}.tar.gz
rm -rf ${shadowsocks_r_file}.tar.gz
rm -rf /usr/local/shadowsocks
mv ${shadowsocks_r_file}/shadowsocks /usr/local/
cat > /etc/shadowsocks.json<<-EOF
{
   "server":"0.0.0.0",
   "server_ipv6":"[::]",
   "server_port":${Ssr_Port},
   "local_address":"127.0.0.1",
   "local_port":1080,
   "password":"${Ssr_Pass}",
   "timeout":300,
   "method":"aes-256-cfb",
   "protocol":"origin",
   "protocol_param":"",
   "obfs":"tls1.2_ticket_auth",
   "obfs_param":"",
   "redirect":"",
   "dns_ipv6":false,
   "fast_open":false,
   "workers":1
}
EOF
update-rc.d -f shadowsocks defaults &>/dev/null
/etc/init.d/shadowsocks start
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c
MyStunnelC

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
 mkdir -p /etc/openvpn
 else
 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*
fi
 mkdir -p /etc/openvpn/server
 mkdir -p /etc/openvpn/client

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server/server_tcp.conf
# BartScript

port MyOvpnPort1
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
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
cat <<'myOpenVPNconf2' > /etc/openvpn/server/server_udp.conf
# BartScript

port MyOvpnPort2
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
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
cat <<'myOpenVPNconf3' > /etc/openvpn/server/server_tcp2.conf
# BartScript

port MyOvpnPort3
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
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
server 172.18.0.0 255.255.0.0
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
myOpenVPNconf3
cat <<'myOpenVPNconf4' > /etc/openvpn/server/server_udp2.conf
# BartScript

port MyOvpnPort4
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/xbarts.crt
key /etc/openvpn/xbarts.key
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
server 172.19.0.0 255.255.0.0
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
myOpenVPNconf4
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
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server/server_udp.conf
 sed -i "s|MyOvpnPort3|$OpenVPN_Port3|g" /etc/openvpn/server/server_tcp2.conf
 sed -i "s|MyOvpnPort4|$OpenVPN_Port4|g" /etc/openvpn/server/server_udp2.conf

 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Workaround: Adopting /etc/openvpn/server as config directory (v2.5.0) 
 if [[ ! -e /lib/systemd/system/openvpn-server\@.service ]]; then
  cp /lib/systemd/system/openvpn\@.service /lib/systemd/system/openvpn-server\@.service
 elif [[ "$(grep -Eo '(WorkingDirectory=).+' /lib/systemd/system/openvpn-server\@.service | cut -d"=" -f2)" != '/etc/openvpn/server' ]];  then
  sed -i 's|WorkingDirectory=.*|WorkingDirectory=/etc/openvpn/server|g' /lib/systemd/system/openvpn-server\@.service
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl daemon-reload &>/dev/null
 systemctl start openvpn-server@server_tcp
 systemctl start openvpn-server@server_udp
 systemctl enable openvpn-server@server_tcp
 systemctl enable openvpn-server@server_udp
 systemctl restart openvpn-server@server_tcp
 systemctl restart openvpn-server@server_udp
 systemctl start openvpn-server@server_tcp2
 systemctl start openvpn-server@server_udp2
 systemctl enable openvpn-server@server_tcp2
 systemctl enable openvpn-server@server_udp2
 systemctl restart openvpn-server@server_tcp2
 systemctl restart openvpn-server@server_udp2
}

function InsProxy(){
 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 
 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port1
http_port 0.0.0.0:$Proxy_Port2
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|$Privoxy_Port1|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server.."
 systemctl restart privoxy
 systemctl restart squid
}

 # Installing Firewalld
 apt install firewalld -y
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
# Credits to iamBARTX

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
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option CUSTOM-HEADER Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For redirect.googlevideo.com

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152

cat <<EOF16> /var/www/openvpn/Default.ovpn
# Credits to iamBARTX

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

cat <<EOF160> /var/www/openvpn/GStories.ovpn
# Credits to iamBARTX

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
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER Host tiktoktreats.onelink.me
http-proxy-option CUSTOM-HEADER X-Online-Host tiktoktreats.onelink.me
http-proxy-option CUSTOM-HEADER X-Forward-Host tiktoktreats.onelink.me
http-proxy-option CUSTOM-HEADER Connection:Keep-Alive

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF160

cat <<EOF17> /var/www/openvpn/GGames.ovpn
# Credit to iamBARTX™️

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
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port2
http-proxy-option CUSTOM-HEADER "Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "X-Online-Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "X-Forward-Host: c3cdn.ml.youngjoygame.com"
http-proxy-option CUSTOM-HEADER "Connection: Keep-Alive"

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- OVPN Download site by iamBARTX -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://breakoutvpn.com/img/log.png" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Globe/TM <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For EZ/GS Promo with WNP freebies</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GTMConfig.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For Sun <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> For Default Config</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/Default.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>For TRINET <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Trinet GIGASTORIES Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GStories.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> For TRINET <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> Trinet GIGAGAMES Promos</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/GGames.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
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

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/barts
 mkdir -p /etc/barts
 chmod -R 755 /etc/barts
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/barts/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
EOFSH
 chmod +x /etc/barts/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/barts/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

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
 echo -e " (｡◕‿◕｡) $MyScriptName Debian VPS Installer"
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

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin

 # Install ShadowsocksR
 echo -e "Installing ShadowsocksR..."
 InstallSSR
 
 # Configure Privoxy and Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/barts.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 echo -e ""
 echo -e " Success Installation"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " OpenSSH: $SSH_Port1, $SSH_Port2"
 echo -e " Stunnel: $Stunnel_Port1, $Stunnel_Port2"
 echo -e " DropbearSSH: $Dropbear_Port1, $Dropbear_Port2"
 echo -e " Privoxy: $Privoxy_Port1, $Privoxy_Port2"
 echo -e " Squid: $Proxy_Port1,$Proxy_Port2"
 echo -e " OpenVPN: $OpenVPN_Port1, $OpenVPN_Port3, $OpenVPN_Port2, $OpenVPN_Port4"
 echo -e " NGiNX: $OvpnDownload_Port"
 echo -e " Webmin: 10000"
 echo -e " Badvpn Port: 7300"
 echo -e " SSR Port: 8443"
 echo -e " SSR Password: xbarts"
 echo -e " L2tp IPSec Key: iambartx"
 echo -e ""
 echo -e ""
 echo -e " OpenVPN Configs Download site"
 echo -e " http://$IPADDR:$OvpnDownload_Port"
 echo -e ""
 echo -e " All OpenVPN Configs Archive"
 echo -e " http://$IPADDR:$OvpnDownload_Port/Configs.zip"
 echo -e ""
 echo -e ""
 echo -e " [Note] DO NOT RESELL THIS SCRIPT"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

rm -f ScriptBartX*
exit 1