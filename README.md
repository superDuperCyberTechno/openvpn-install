![Rockatansky](https://raw.githubusercontent.com/superDuperCyberTechno/rockatansky/master/header.png)

#STILL IN DEVELOPMENT - NOT READY FOR DEPLOYMENT

OpenVPN server installation script, suitable for tech savvy [road warrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29)s. Compatible with Debian, Ubuntu and CentOS.

This script will let you setup your own VPN server in no more than a minute, even if you haven't used OpenVPN before. It has been designed to be as unobtrusive and universal as possible.

In addition, it automatically maintains an internal malware blocklist based on the [StevenBlack/hosts](https://github.com/StevenBlack/hosts) project, isolating you from a constantly tweaked list of potential threats.

If you want to show your appreciation, you can donate via [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VBAYDL34Z7J6L) or [Bitcoin](https://pastebin.com/raw/M2JJpQpC). Thanks!

### Installation
Run the script and follow the assistant:

`wget https://raw.githubusercontent.com/superDuperCyberTechno/rockatansky/master/rockatansky.sh -O openvpn-install.sh && bash openvpn-install.sh`

Once it ends, you can run it again to add more users, remove some of them or even completely uninstall OpenVPN.

###Client
Please be aware, this is only 50% of a VPN connection. You need a local client to hook up your machine to the server. A good example could be the [Pritunl Client](https://client.pritunl.com/).
