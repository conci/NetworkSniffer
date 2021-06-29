# NetworkSniffer

A basic network sniffer made in WPF using MVVM architectural pattern.

<a href="">
<img src="https://raw.githubusercontent.com/gcupko00/NetworkSniffer/master/NetworkSniffer_demo1.gif" height="450" width="780" border="black"/>
</a>

---

## Features
- Capturing and analyzing IP packets
- Captured packets statistics tracking
- Analyzing transport layer packets
- Filtering incoming and outgoing packets by transport protocol, IP address, port and length

### Supported protocols
- TCP
- UDP
- ICMP
- IGMP
- DNS

Most common application protocols are identified (but not parsed) - FTP, SSH, SMTP, HTTP, HTTPS and more.

---

## About
This application is made in WPF as a seminar project for a college course using an open source MVVM library <a href="https://mvvmlight.codeplex.com/">MVVM Light Toolkit</a>.

### Made by
<a href="https://github.com/gcupko00">gcupko00</a></br>
<a href="https://github.com/bolkonksy/">bolkonksy</a>

##### Special thanks to
Tester: <a href="https://github.com/athnix">athnix</a>

<a href="http://sol-myr.deviantart.com/">
<img src="https://raw.githubusercontent.com/gcupko00/NetworkSniffer/master/NetworkSniffer/Resources/korlo.png" height="auto" width="auto" />
</a>

---

## New feature - 06/2021
NetworkSniffer now supports IPv6 through Npcap, we've added an option that when enabled will capture IPv6 packets. If disabled, it will continue using raw sockets and support only IPv4 as does the original version.

![image](https://user-images.githubusercontent.com/10501788/123847298-d279a100-d8ec-11eb-88d0-31fa568f3a05.png)
### Made by
<a href="https://github.com/conci/">conci</a></br>
<a href="https://github.com/twieds/">twieds</a>
