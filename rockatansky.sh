#!/bin/bash

#detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available\nYou need to enable TUN before running this script."
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported."
	exit 4
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit 5
fi

print_header() {
    echo " ______  _____  _______ _     _ _______ _______ _______ __   _ _______ _     _ __   __"
    echo "|_____/ |     | |       |____/  |_____|    |    |_____| | \  | |______ |____/    \_/  "
    echo "|    \_ |_____| |_____  |    \_ |     |    |    |     | |  \_| ______| |    \_    |"
    echo "============================================================ OPENVPN SERVER SCRIPT"
}

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

#if the openvpn/server.conf file exists, we've done this before
if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
        print_header
		echo "Looks like OpenVPN is already installed."
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) Revoke an existing user"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [4]: " option
        #cast to default value
        option=${option:-4}
		case $option in
			1) 
			echo ""
			echo "Tell me a name for the client certificate"
			echo "Please, use one word only, no special characters"
            read -p "Client name [client]: " -e client
            #cast to default value
            client=${client:-1}

			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $client nopass
            #generates the custom client.ovpn
			newclient "$client"
			echo ""
			echo "Client $client added, configuration is available at" ~/"$client.ovpn"
			exit
			;;

			2)
			#this option could be documented a bit better and maybe even be simplified
			number_of_clients=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 6
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$number_of_clients" = '1' ]]; then
				read -p "Select one client [1]: " client_number
			else
				read -p "Select one client [1-$number_of_clients]: " client_number
			fi
			client=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $client
			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
			rm -rf pki/reqs/$client.req
			rm -rf pki/private/$client.key
			rm -rf pki/issued/$client.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo ""
			echo "Certificate for client $client revoked"
			exit
			;;

			3) 
			echo ""
            read -p "Do you really want to remove OpenVPN? [Y/n]: " -e remove
            remove=${remove:-'y'}
			if [[ "$remove" = 'y' ]]; then
				port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$port/$protocol
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$port/$protocol
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
				else
					ip=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $protocol --dport $port -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $protocol --dport $port -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$port" != '1194' || "$protocol" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $protocol $port
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
    print_header
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are OK with them."
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN listening to."

    #get the server ip, credits to https://github.com/mpolden/ipd
    ip_detected=$(curl -s ifconfig.co)
    read -p "IP address [$ip_detected]: " ip
    ip=${ip:-$ip_detected}

	echo ""
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Choose protocol [1]: " -e protocol
    protocol=${protocol:-1}

	case $protocol in
		1) 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac

	echo ""
	echo "Which port do you want OpenVPN listening to?"
	read -p "Port [1194]: " -e port
    port=${port:-1194}
	echo ""
	echo "Which DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) OpenDNS"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Verisign"
	read -p "DNS [1]: " -e dns
    dns=${dns:-1}
	echo ""
	echo "Finally, tell me your name for the client certificate."
	echo "Please, use one word only, no special characters."
	read -p "Client name [client]: " -e client
    client=${client:-'client'}
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	read -n1 -r -p "Press any key to continue..."

	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install dnsmasq openvpn iptables openssl ca-certificates -y
	else
		#else, the distro is CentOS
		yum install epel-release -y
		yum install dnsmasq openvpn iptables openssl wget ca-certificates -y
	fi

	#an old version of easy-rsa was available by default in some openvpn packages, so remove it
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	#get easy-rsa
	wget -O ~/EasyRSA-3.0.3.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.3/EasyRSA-3.0.3.tgz"
	tar xzf ~/EasyRSA-3.0.3.tgz -C ~/
    
	#temporary fix for issue #353, which is caused by OpenVPN/easy-rsa#135
	# Will be removed as soon as a new release of easy-rsa is available
	sed -i 's/\[\[/\[/g;s/\]\]/\]/g;s/==/=/g' ~/EasyRSA-3.0.3/easyrsa

	mv ~/EasyRSA-3.0.3/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.3/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.3.tgz

	cd /etc/openvpn/easy-rsa/
	#create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $client nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	#move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn

	#CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem

	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key

	# Generate server.conf
	echo "port $port
proto $protocol
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf

	#enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	#avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		#using both permanent and not permanent rules to avoid a firewalld reload.
		#we don't use --add-service=openvpn because that would only work wih the default port and protocol.
		firewall-cmd --zone=public --add-port=$port/$protocol
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$port/$protocol
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		#set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	else
		#needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		#set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			#if iptables has at least one REJECT rule, we asume this is needed.
			#not the best approach but I can't think of other and this shouldn't cause problems.
			iptables -I INPUT -p $protocol --dport $port -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $protocol --dport $port -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	#if SELinux is enabled and a custom port or TCP was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$port" != '1194' || "$protocol" = 'tcp' ]]; then
				#semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $protocol $port
			fi
		fi
	fi
	#and finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		#little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	#try to detect a NATed connection and ask about it to potential LowEndSpirit users
	external_ip=$(curl -s ifconfig.co)
	if [[ "$ip" != "$external_ip" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external ip"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External ip: " -e user_external_ip
		if [[ "$user_external_ip" != "" ]]; then
			ip=$user_external_ip
		fi
	fi
	#client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
sndbuf 0
rcvbuf 0
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "$client"

    #set up the dnsmasq delegations
    printf "domain-needed\nbogus-priv\n" >> /etc/dnsmasq.conf
    printf "server=8.8.8.8\nserver=8.8.4.4\n" >> /etc/dnsmasq.conf    

	#DNS
	case $dns in
        #default dns
		1) 
		#obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "server=$line\"" >> /etc/dnsmasq.conf
		done
		;;

        #Google
		2) 
		echo 'server=8.8.8.8"' >> /etc/dnsmasq.conf
		echo 'server=8.8.4.4"' >> /etc/dnsmasq.conf
		;;

        #OpenDNS
		3)
		echo 'server=208.67.222.222"' >> /etc/dnsmasq.conf
		echo 'server=208.67.220.220"' >> /etc/dnsmasq.conf
		;;
        
        #NTT
		4) 
		echo 'server=129.250.35.250"' >> /etc/dnsmasq.conf
		echo 'server=129.250.35.251"' >> /etc/dnsmasq.conf
		;;
        
        #Hurricane Electric
		5) 
		echo 'server=74.82.42.42"' >> /etc/dnsmasq.conf
		;;

        #VeriSign
		6) 
		echo 'server=64.6.64.6"' >> /etc/dnsmasq.conf
		echo 'server=64.6.65.6"' >> /etc/dnsmasq.conf
		;;
	esac

    printf "listen-address=127.0.0.1\nlisten-address=10.8.0.1\n" >> /etc/dnsmasq.conf
    printf "push \"dhcp-option DNS 10.8.0.1\"\n" >> /etc/openvpn/server.conf

    #fetch the blacklist from StevenBlack/hosts
    #the list is filtered so that only delegations beginning with "0.0.0.0" is added to the host
    #file. there's 2 reasons for this:
    #1. we are relying blindly on a third party list for protection, by filtering all
    #non-0.0.0.0 hosts we make sure that no malicious re-delegations sneak their way into the list.
    #2. since all added hosts start with "0.0.0.0" we can easily re-use the hosts file (before we
    #concatenate the new hosts, we remove all lines starting with "0.0.0.0"),
    #making it possible for users to maintain their own host delegations (provided that they do not
    #begin with "0.0.0.0", that is).
    sed -i '/^0\.0\.0\.0/ d' /etc/hosts && curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep -e '^0\.0\.0\.0' >> /etc/hosts

    #add the command above the crontab
    echo "crontab \"0 0 * * * sed -i '/^0\.0\.0\.0/ d' /etc/hosts && curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep -e '^0\.0\.0\.0' >> /etc/hosts && service dnsmasq restart\"" > cronjob
    crontab cronjob && rm cronjob

	echo ""
	echo "Finished!"
	echo ""
	echo "Your client configuration is available at" ~/"$client.ovpn"
	echo "If you want to add more clients, you simply need to run this script again!"

    service dnsmasq restart
fi
