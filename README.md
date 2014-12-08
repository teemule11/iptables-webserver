# Solowall is an iptables ruleset for Webservers and Proxies
Boilerplate firewall rules for a standalone webserver or reverse proxy. Tested on Debian and Ubuntu. Deploy ready, customize if you wish. Completely based on configuration files, making it a breeze to use with CM tools like ansible, salt, puppet or chef. Can be used either as a call-when-needed bash script or as an init script. 

## Targets: standalone hosts
Solowall is intended for a standalone Webserver or HTTP Proxy. NOT Routers, not gateways, not your local PC

## Features
* Secure host setup by denying anything that is not explicitly allowed
* Lots of choices to whitelist IPs, Ranges, Ports etc.
* Traffic rate limiting on a per-port / per-Source basis
* Runs completely off config files: No need to fiddle around in iptables code
* Easy to integrate in CM systems (Ansible, Puppet etc.): they need to build the configs only
* Run as shell script manually or via crontab or as an init script, both provided by this package

## Platforms
Solowall-iptables has been tested to work on all recent and current versions of Debian and Ubuntu Server.
* Debian 6.0 / Squeeze
* Debian 7.0 / Wheezy
* Debian 8.0 / Jessie
* Ubuntu 10.04 LTS 
* Ubuntu 12.04 LTS 
* Ubuntu 13.10 
* Ubuntu 14.04 LTS 
* Ubuntu 14.10

## Installation
1. Unpack all files to /usr/local/bin/firewall . 
2. Make sure fw-lamp.sh is executable.
3. Make sure the firewall is configured to your needs. See sections "configuration".
4. Decide whether you want to execute the firewall script as an init script or via crontab. 
	* 4a) If you want to use the init.d script, put the file "firewall" to /etc/init.d. Then type: chmod 755 /etc/init.d/firewall [enter] and update-rc.d firewall defaults [enter]  
	* 4b) To execute the firewall using crontab, enter the following: to you crontab: @reboot /usr/local/bin/firewall/fw-lamp.sh
5. Feel a bit safer than before :-)


## Configuration
Before you delve into how to configure solowall, please read a few lines about how it works - in the order the rules are being processed
* all Input needs to be explicitly allowed by a rule; any output is allowed.
* all established connections will be allowed - thus, if a connection has been establed from the host itself, all incoming traffic flowing back on this connection will be accepted.
* you can whitelist IP numbers as a whole - so if you know someone you trust, you may add his IP to conf/ip-whitelisted.conf.
* next, all kind of - generally spoken - invalid/unwanted packages are being dropped. You can adjust a lot here through configs in conf/options.conf. Theres some reading for you to do here. Or stick with the defaults.
* now rate limits (number of access attempts per second/minute/hour) will be applied on dedicated ports. Limits can be configured port-wise in conf/limits.conf
* finally, port whitelisting is applied on a per port-to-IP/Range/anyone basis. Any packet that has made it this far will need to be destined to a port that is explicitly whitelisted in conf/port-whitelist.conf

So, to configure the firewall to your needs, you should:
- add whitelisted IPs to conf/ip-whitelist.conf 
- add whitelisted ports to conf/port-whitelist.conf ; see instructions there to understand how to allow certain ips or ranges
- add rate limits on certain ports to avoid some traffic
- do some reading in options.conf; the default values there should be fine, but you may be interested in some further blocking possibilities.

All config files are heavily commented, if anything is unclear, please contact me.

## DDoS Protection
In Short: No.

In Long: While some iptables rulesets will promise this, you should understand this can't work. A standalone server, processing incoming traffic by itself, will never fend off a serious DDoS attack.
But if you use rate limiting, you will push the barriers for the bad guys a bit further. That's all you can do.

## License
Solowall is MIT licensed, see LICENSE.