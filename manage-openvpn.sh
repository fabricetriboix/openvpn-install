#!/bin/bash
#
# Copyright (c) 2013 Nyr. Released under the MIT License.
# Copyright (c) 2019, 2020, 2023, 2024, 2025 Fabrice Triboix

set -eu -o pipefail


###################
# Parse arguments #
###################

HELP=no
OPERATION=none
PROTOCOL=udp
STUNNELPORT=443
OPENVPNPORT=1194
# NB: Try different services to get the public IP address, because some may be down
PUBLICIP=$(curl -sf -m 3 ifconfig.co || curl -sf -m 3 ifconfig.me || curl -sf -m 3 whatismyip.cc | grep 'Your IP' | awk '{ print $3 }')
DNS=cloudflare
STUNNEL=no
CLIENT=
NOPASS=no

ARGS=$(getopt -o hiuRa:r:tp:P:d:sS:n -- "$@")
eval set -- "$ARGS"
set +u  # Avoid unbound $1 at the end of the parsing
while true; do
    case "$1" in
        -h) HELP=yes; shift;;
        -i) OPERATION=install; shift;;
        -u) OPERATION=uninstall; shift;;
        -R) OPERATION=refresh; shift;;
        -a) OPERATION=adduser; CLIENT="$2"; shift; shift;;
        -r) OPERATION=rmuser; CLIENT="$2"; shift; shift;;
        -t) PROTOCOL=tcp; shift;;
        -p) OPENVPNPORT="$2"; shift; shift;;
        -P) PUBLICIP="$2"; shift; shift;;
        -d) DNS="$2"; shift; shift;;
        -s) STUNNEL=yes; PROTOCOL=tcp; shift;;
        -S) STUNNELPORT="$2"; shift; shift;;
        -n) NOPASS=yes; shift;;
        --) shift; break;;
        *) break;;
    esac
done
set -u

if [[ $HELP == yes ]]; then
    echo "Install, configure and manage an OpenVPN server and its users"
    echo
    echo "This script automatically detects whether the OS is Debian-based"
    echo "or RedHat-based and acts accordingly. Other OSs are not supported."
    echo
    echo "Please note this script must be run as root. It does not touch"
    echo "the firewall or the routes, we have to do this yourself."
    echo
    echo "The available arguments are:"
    echo "  -h       Print this help message"
    echo "  -i       Install and configure an OpenVPN server"
    echo "  -u       Uninstall OpenVPN"
    echo "  -R       Refresh OpenVPN (re-install the OS packages, but leave"
    echo "           the existing data untouched)"
    echo "  -a USER  Add a user"
    echo "  -r       Remove a user"
    echo
    echo "The following arguments are only available in conjuction with -i:"
    echo "  -t         Use TCP instead of UDP"
    echo "  -p PORT    OpenVPN port (default: $OPENVPNPORT)"
    echo "  -P IP      Public IP address (i.e. NAT address, if applicable)"
    echo "             (default: $PUBLICIP)"
    echo "  -d CHOICE  DNS servers to use (default: $DNS)"
    echo "             allowed choices: current (use the current system"
    echo "             resolvers), cloudflare, google, opendns, verisign,"
    echo "             special (quad9 backed by cloudflare)."
    echo "  -s         Configure stunnel to pass VPN traffic into an SSL"
    echo "             tunnel (implies -t)"
    echo "  -S PORT    Stunnel port (default: $STUNNELPORT); ignored unless"
    echo "             -s is set"
    echo
    echo "The following arguments are only available in conjuction with -a:"
    echo "  -n         Do not set a password for the private key"
    exit 1
fi

case "$DNS" in
    current|cloudflare|google|opendns|verisign|special) ;;
    *) echo "ERROR: Invalid DNS selection: $DNS"; exit 1;;
esac

if [[ $OPERATION == none ]]; then
    echo "ERROR: You must specify an operation"
    exit 1
fi

if [[ $OPERATION == adduser ]]; then
    if [[ -z $CLIENT ]]; then
        echo "ERROR: User name is empty"
        exit 1
    fi
fi

if [[ $STUNNEL == yes ]]; then
    EXTERNALPORT="$STUNNELPORT"
else
    EXTERNALPORT="$OPENVPNPORT"
fi

log() {
    echo SCRIPT "$@"
}


######################
# Run various checks #
######################

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo "ERROR: This script needs to be run with bash, not sh"
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: Sorry, you need to run this as root"
    exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
    echo "ERROR: The TUN device is not available"
    echo "You need to enable TUN before running this script"
    exit 1
fi

if [[ -e /etc/debian_version ]]; then
    OS=debian
    GROUPNAME=nogroup
    export DEBIAN_FRONTEND=noninteractive

elif [[ -e /etc/centos-release || -e /etc/redhat-release || -e /etc/system-release ]]; then
    OS=centos
    GROUPNAME=nobody

else
    echo "ERROR: Only Debian-based and RedHat-based OSs are supported"
    exit 1
fi

log "Detected OS: $OS"


#################################
# Function to create a new user #
#################################

newclient () {
    # Generates the custom client.ovpn
    file="/etc/openvpn/$1.ovpn"
    cp /etc/openvpn/client-common.txt "$file"
    echo "<ca>" >> "$file"
    cat /etc/openvpn/easy-rsa/pki/ca.crt >> "$file"
    echo "</ca>" >> "$file"
    echo "<cert>" >> "$file"
    sed -ne '/BEGIN CERTIFICATE/,$ p' \
        "/etc/openvpn/easy-rsa/pki/issued/$1.crt" >> "$file"
    echo "</cert>" >> "$file"
    echo "<key>" >> "$file"
    cat "/etc/openvpn/easy-rsa/pki/private/$1.key" >> "$file"
    echo "</key>" >> "$file"
    echo "<tls-auth>" >> "$file"
    sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/ta.key >> "$file"
    echo "</tls-auth>" >> "$file"
}


###################
# Refresh OpenVPN #
###################

if [[ $OPERATION == refresh ]]; then
    extrapkg=
    if [[ "$STUNNEL" == yes ]]; then
        extrapkg=stunnel4
    fi

    if [[ $OS == debian ]]; then
        apt-get -q -y update
        apt-get -q -y install openvpn openssl ca-certificates $extrapkg

    else
        yum -q -y install epel-release
        yum -q -y install openvpn openssl ca-certificates $extrapkg
    fi

    # Enable net.ipv4.ip_forward for the system
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf

    # Enable without waiting for a reboot or service restart
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # If SELinux is enabled and a custom port was selected, we need this
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$OPENVPNPORT" != '1194' ]]; then
        # Install semanage if not already present
        if ! hash semanage 2>/dev/null; then
            yum install policycoreutils-python -y
        fi
        semanage port -a -t openvpn_port_t -p $PROTOCOL $OPENVPNPORT
    fi

    # And finally, restart OpenVPN and stunnel
    #   Little hack to check for systemd
    if pgrep systemd-journal; then
        if [[ "$STUNNEL" == yes ]]; then
            # TODO: I can't manage stunnel using `systemctl stop stunnel@stunnel`...
            systemctl stop stunnel4
            killall stunnel4 || true
            systemctl start stunnel4
        fi
        systemctl restart openvpn@server.service
    else
        if [[ "$OS" = 'debian' ]]; then
            if [[ "$STUNNEL" == yes ]]; then
                /etc/init.d/stunnel4 restart
            fi
            /etc/init.d/openvpn restart
        else
            if [[ "$STUNNEL" == yes ]]; then
                service stunnel4 restart
                chkconfig stunnel4 on
            fi
            service openvpn restart
            chkconfig openvpn on
        fi
    fi

    echo "$STUNNEL" > /etc/openvpn/is-stunnel-enabled
    log "OpenVPN successfully refreshed"
    exit 0
fi


#################################
# Install and configure OpenVPN #
#################################

if [[ $OPERATION == install ]]; then
    extrapkg=
    if [[ "$STUNNEL" == yes ]]; then
        extrapkg=stunnel4
    fi

    if [[ $OS == debian ]]; then
        apt-get -q -y update
        apt-get -q -y install openvpn openssl ca-certificates $extrapkg

    else
        yum -q -y install epel-release
        yum -q -y install openvpn openssl ca-certificates $extrapkg
    fi

    # Get easy-rsa
    EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.4/EasyRSA-3.1.4.tgz'
    wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null \
        || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
    tar xzf ~/easyrsa.tgz -C ~/
    mv ~/EasyRSA-3.1.4/ /etc/openvpn/easy-rsa
    chown -R root:root /etc/openvpn/easy-rsa/
    rm -f ~/easyrsa.tgz
    cd /etc/openvpn/easy-rsa/

    # Create the PKI, set up the CA and the server and client certificates
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full server nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

    # Move the stuff we need
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt \
        pki/private/server.key pki/crl.pem /etc/openvpn

    # CRL is read with each client connection, when OpenVPN is dropped to nobody
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem

    # Generate key for tls-auth
    openvpn --genkey --secret /etc/openvpn/ta.key

    # Create the DH parameters file using the predefined ffdhe2048 group
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/dh.pem

    # Generate server.conf
    echo "port $OPENVPNPORT
proto $PROTOCOL
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
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
    echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf

    if [[ "$STUNNEL" == yes ]]; then
        echo "local 127.0.0.1" >> /etc/openvpn/server.conf
    fi

    # DNS
    case $DNS in
        current)
            # Locate the proper resolv.conf
            # Needed for systems running systemd-resolved
            if grep -q "127.0.0.53" "/etc/resolv.conf"; then
                RESOLVCONF='/run/systemd/resolve/resolv.conf'
            else
                RESOLVCONF='/etc/resolv.conf'
            fi
            # Obtain the resolvers from resolv.conf and use them for OpenVPN
            grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
                echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
            done
            ;;

        cloudflare)
            echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
            ;;

        google)
            echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
            ;;

        opendns)
            echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
            ;;

        verisign)
            echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
            ;;

	special)
            echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
            echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
    esac

    echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf

    # Enable net.ipv4.ip_forward for the system
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf

    # Enable without waiting for a reboot or service restart
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # If SELinux is enabled and a custom port was selected, we need this
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$OPENVPNPORT" != '1194' ]]; then
        # Install semanage if not already present
        if ! hash semanage 2>/dev/null; then
            yum install policycoreutils-python -y
        fi
        semanage port -a -t openvpn_port_t -p $PROTOCOL $OPENVPNPORT
    fi

    # Configure stunnel
    if [[ "$STUNNEL" == yes ]]; then
        openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -sha256 -subj '/CN=127.0.0.1/O=localhost/C=US' -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem

        STUNNELCONF=/etc/stunnel/stunnel.conf
        echo "[openvpn]" > "$STUNNELCONF"
        echo "client = no" >> "$STUNNELCONF"
        echo "accept = $STUNNELPORT" >> "$STUNNELCONF"
        echo "cert = /etc/stunnel/stunnel.pem" >> "$STUNNELCONF"
        echo "connect = 127.0.0.1:$OPENVPNPORT" >> "$STUNNELCONF"
    fi

    # And finally, restart OpenVPN and stunnel
    #   Little hack to check for systemd
    if pgrep systemd-journal; then
        if [[ "$STUNNEL" == yes ]]; then
            # TODO: I can't manage stunnel using `systemctl stop stunnel@stunnel`...
            systemctl stop stunnel4
            killall stunnel4 || true
            systemctl start stunnel4
        fi
        systemctl restart openvpn@server.service
    else
        if [[ "$OS" = 'debian' ]]; then
            if [[ "$STUNNEL" == yes ]]; then
                /etc/init.d/stunnel4 restart
            fi
            /etc/init.d/openvpn restart
        else
            if [[ "$STUNNEL" == yes ]]; then
                service stunnel4 restart
                chkconfig stunnel4 on
            fi
            service openvpn restart
            chkconfig openvpn on
        fi
    fi

    # client-common.txt is created so we have a template to add further users later
    if [[ "$STUNNEL" == yes ]]; then
        # When using stunnel, the client will connect to its local stunnel
        CNXIP=127.0.0.1
    else
        CNXIP="$PUBLICIP"
    fi
    echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $CNXIP $OPENVPNPORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt

    echo "$STUNNEL" > /etc/openvpn/is-stunnel-enabled
    log "OpenVPN successfully installed and configured"

    if [[ "$STUNNEL" == yes ]]; then
        echo "You now need to install and configure stunnel on your clients."
        echo
        echo "To install, run the following on your client (or equivalent"
        echo "for your OS):"
        echo
        echo "sudo apt install stunnel4"
        echo
        echo "To configure stunnel, write the following into"
        echo "/etc/stunnel/stunnel.conf in your client OS:"
        echo
        echo "[openvpn]"
        echo "client = yes"
        echo "accept = 127.0.0.1:1194"
        echo "connect = $PUBLICIP:$STUNNELPORT"
        echo "cert = /etc/stunnel/stunnel.pem"
        echo
        echo "You will also need to copy /etc/stunnel/stunnel.pem from this"
        echo "server to your client OS and place it at /etc/stunnel/stunnel.pem."
    fi

    exit 0
fi


#####################
# Uninstall OpenVPN #
#####################

if [[ $OPERATION == uninstall ]]; then
    PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
    PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

    STUNNEL=no
    if [ -e /etc/openvpn/is-stunnel-enabled ]; then
        STUNNEL=$(cat /etc/openvpn/is-stunnel-enabled)
    fi

    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
        semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
    fi

    extrapkg=
    if [[ "$STUNNEL" == yes ]]; then
        extrapkg=stunnel4
    fi

    if [[ "$OS" = 'debian' ]]; then
        apt-get -q -y remove --purge openvpn $extrapkg
    else
        yum -q -y remove openvpn $extrapkg
    fi

    rm -rf /etc/openvpn
    rm -f /etc/sysctl.d/30-openvpn-forward.conf

    if [[ "$STUNNEL" == yes ]]; then
        rm -rf /etc/stunnel
    fi

    log "OpenVPN uninstalled"
    exit 0
fi


##################
# Add a new user #
##################

if [[ $OPERATION == adduser ]]; then
    cd /etc/openvpn/easy-rsa/
    if [ "$NOPASS" == yes ]; then
        EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
    else
        EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT"
    fi
    newclient "$CLIENT"
    echo "User $CLIENT added"
    echo "Configuration is available at: /etc/openvpn/$CLIENT.ovpn"
    exit 0
fi


#################
# Remove a user #
#################

if [[ $OPERATION == rmuser ]]; then
    if grep -sI "^R.*CN=$CLIENT" /etc/openvpn/easy-rsa/pki/index.txt > /dev/null; then
        echo "User already removed: $CLIENT"
        exit 1
    fi
    if ! grep -sI "^V.*CN=$CLIENT" /etc/openvpn/easy-rsa/pki/index.txt > /dev/null; then
        echo "User does not exist: $CLIENT"
        exit 1
    fi
    cd /etc/openvpn/easy-rsa/
    ./easyrsa --batch revoke $CLIENT
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    rm -f /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    # CRL is read with each client connection, when OpenVPN is dropped to nobody
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem
    echo
    echo "Certificate for client $CLIENT revoked!"

    log "User revoked"
    exit 0
fi

log "ERROR: Invalid operation: $OPERATION"
exit 1
