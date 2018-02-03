# simple-tcp-vpn-over-ssh-socks
Poor-man's VPN for TCP traffic over SSH dynamic socks tunnel, uses Linux/iptables

Taken some TCP tunneling code from Christophe Devine, and turned it into a transparent socks proxy.
This serves as a lightweight / poor-man's VPN connection, to combine firewalled networks into one.
Requirements; use linux on your end, and you need to be able to connect to an SSH server on the
network you want to reach. And the local and remote network IP-ranges should NOT overlap ;-)
Note: this proxy ONLY works with TCP packets, not with UDP. So your DNS server won't work accross it.

Created somewhere between 2002 and 2014. Feel free to use and modify to suit your needs.
Thijs Kaper, 3 feb 2018.

Compile using gcc (c-compiler):
```sh
gcc myproxy.c -o myproxy
```

Use linux iptables to send traffic for certain network ranges to this proxy code.
You can choose to send specific ranges to the proxy, and leave the rest of your traffic default:

```sh
# send single IP 172.29.29.20 to the proxy
sudo iptables -t nat -A OUTPUT -p tcp -d 172.29.29.20 -j DNAT --to-destination 127.0.0.1:6021

# send IP range 172.30.*.* to the proxy
sudo iptables -t nat -A OUTPUT -p tcp -d 172.30.0.0/16 -j DNAT --to-destination 127.0.0.1:6021
```

Or you can send ALL traffic, except some ranges to the proxy like this:
Note: make sure you add an exclude line for the ip address to which you are tunneling ;-)
Or better; make sure your complete local network is excluded (DNS+gateway will be on there).

```sh
# Exclude ranges (10.*, localhost, and virtualbox 192.168.3.*, tunnel-host):
sudo iptables -t nat -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.3.0/24 -j ACCEPT
sudo iptables -t nat -A OUTPUT -p tcp -d <TUNNELHOSTIP> -j ACCEPT

# default other traffic to proxy:
sudo iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:6021
```

```sh
# start SSH socks tunnel to your tunnelhost:
ssh -fN -D6020 youruser@TUNNELHOSTIP

# start tunnel software (port 6021 listens for iptables traffic, and 127.0.0.1 6020 is ssh socks tunnel):
myproxy 6021 127.0.0.1 6020
```

Note: before you start messing with iptables, you could make a backup of your current rules using:

```sh
sudo iptables-save >iptables-backup.rules
```

This can be restored using:

```sh
sudo iptales-restore <iptables-backup.rules
```

Or if you want to clear all rules (not recommended when you are using iptables rules, for example when
running docker locally, or when using some sort of firewall package):

```sh
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t nat -L
```

Knowledge about networking, ssh-keys, and c-programming helps a lot in understanding this tunnel ;-)

If you are in the unlucky situation where local and remote networks overlap, you can try just using single
IP numbers in the connect and forwards, or... you can modify this C-code to change the network range
just before sending the data on. For example, if both local and remote use ```10.0.*.*```, you can translate
a virtual address of ```192.168.*.*``` to the remote's ```10.0.*.*```, and then forward all ```192.168.*.*``` using this
proxy. Of course any DNS entries won't work anymore, so you should add entries to your /etc/hosts file in
that case.

DISCLAIMER: I have not tried writing beautiful code ;-) It's just a hacked together M.V.P. (Minimal
Viable Product). It works quite nicely, but possibly can be improved much. I do use it in this form quite
regularly (many years already), and have not seen the need for more functionality/fixes yet.

You might also want to take a look at SSHUTTLE https://github.com/sshuttle/sshuttle it's sort of similar,
but is more developed, and has more features. It can be started quite simple, for example like this:

```sh
# tunnel ALL traffic using sshuttle (just change the 0.0.0.0/0 into a smaller range if needed):
sshuttle -r youruser@TUNNELHOSTIP 0.0.0.0/0 -v
```

It handles setting up your iptables rules for you.

