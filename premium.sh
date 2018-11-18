r
echo -e "\e[1;32m-----------------------------------------------------"
echo -e "\e[1;32m        All in One Installer by Bidek Franz          "
echo -e "\e[1;32m-----------------------------------------------------"
sleep 2
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
radius=""
secret=""
clear
echo -----------------------------------------------------
echo Updating System Files
echo -----------------------------------------------------
sleep 2
apt-get update
apt-get install sudo -y
apt-get -y upgrade 
apt-get install unzip -y
apt-get install make libpam0g-dev build-essential -y
apt-get install mysql-client chkconfig nano fail2ban unzip apache2 squid3 build-essential curl -y
sudo cp /etc/squid3/squid.conf /etc/squid3/squid.conf.orig
clear
echo -----------------------------------------------------
echo Installing Openvpn
echo -----------------------------------------------------
sleep 2
apt-get install openvpn easy-rsa -y
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /var/www/html/status
clear
echo -----------------------------------------------------
echo Configuring Sysctl
echo -----------------------------------------------------
sleep 2
sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf
clear 
echo -----------------------------------------------------
echo Configuring SSHD Port
echo -----------------------------------------------------
sleep 2
sed -i 's/22/2121/g' /etc/ssh/sshd_config
echo "SSHD Port Running on port: 2121"
sleep 1
clear
echo -----------------------------------------------------
echo Disabled Selinux!
echo -----------------------------------------------------
sleep 2
SELINUX=disabled 
clear
echo -----------------------------------------------------
echo Checking Configuration
echo -----------------------------------------------------
sleep 2
chkconfig apache2 on
chkconfig squid on
chkconfig openvpn on
chkconfig fail2ban on
clear
echo -----------------------------------------------------
echo Configuring IP Tables
echo -----------------------------------------------------
sleep 2
sysctl -p
iptables -F; iptables -X; iptables -Z
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -j SNAT --to `curl icanhazip.com`
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
clear
echo -----------------------------------------------------
echo Configuring Server and Squid conf
echo -----------------------------------------------------
sleep 2
touch /etc/openvpn/server.conf
sleep 1
echo 'http_port 8080
http_port 3128
http_port 8888
http_port 9999
http_port 7777
http_port 6666
http_port 5555
http_port 4444
http_port 3333
http_port 2222
http_port 1111
acl to_vpn dst xxx.xxx.xxx.xxx
http_access allow to_vpn 
via off
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
http_access deny all' > /etc/squid3/squid.conf
sleep 2
echo 'local xxx.xxx.xxx.xxx
mode server 
tls-server 
port 1194 
proto tcp 
dev tun
keepalive 1 180
resolv-retry infinite 
max-clients 200
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh4096.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn.sh" via-file # 
tmp-dir "/etc/openvpn/" # 
server 172.20.0.0 255.255.255.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
cipher AES-128-CBC
tcp-nodelay
tun-mtu 1400 
mssfix 1360
verb 2
script-security 2
status /var/www/html/status/tcp1.txt 1
client-connect /etc/openvpn/script/connect.sh
client-disconnect /etc/openvpn/script/disconnect.sh' > /etc/openvpn/server.conf
sleep 1
cd /etc/openvpn/
chmod 755 server.conf
sleep 1
wget https://raw.githubusercontent.com/xFranz04/tae/master/Premium.zip
unzip Premium.zip
sleep 1
wget https://vps-setup.000webhostapp.com/single/1.zip
unzip 1.zip
sleep 1
cd /etc/openvpn/login/
chmod 755 /etc/openvpn/login/auth_vpn.sh
sleep 1
cd /etc/openvpn/script/
chmod 755 /etc/openvpn/script/connect.sh
chmod 755 /etc/openvpn/script/disconnect.sh
sleep 1
cd /etc/openvpn/easy-rsa/keys
wget https://vps-setup.000webhostapp.com/emikeys.zip
unzip emikeys.zip
sleep 1
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/openvpn/server.conf
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/openvpn/login/auth_vpn.sh
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/openvpn/script/connect.sh
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/openvpn/script/disconnect.sh
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/squid3/squid.conf
sed -i 's/xxx.xxx.xxx.xxx/'`curl icanhazip.com`'/g' /etc/stunnel/stunnel.conf
sleep 2
clear
echo -----------------------------------------------------
echo Saving Setup Rules
echo -----------------------------------------------------
sleep 2
sudo apt-get install iptables-persistent -y
iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6
sudo invoke-rc.d iptables-persistent save
clear
echo -----------------------------------------------------
echo Starting Services
echo -----------------------------------------------------
sleep 2
service openvpn start
service squid3 start
service apache2 start
service fail2ban start
clear
echo -----------------------------------------------------
echo "Installation is finish! Please reboot your vps!"
echo ------------------------------------------------------
history -c
echo "Application & Port Information"
echo "   - Putty		: 2121"
echo "   - SSL  		: 443"
echo "   - Openvpn		: 1194" 

