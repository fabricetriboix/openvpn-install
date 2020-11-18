manage-openvpn
==============

This is a simple script to install an OpenVPN server and add/remove
users (using mutual certificate authentication only). This is a fork
from [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install),
which removes all user interactions, in order to be able to install it
in batch (please note adding users still requires some interactions).

Don't forget to enable NAT! Example on a Linux box:

    $ sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
