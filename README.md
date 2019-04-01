# Ghost Tunnel - Go

Golang version of [Ghost Tunnel](https://github.com/360PegasusTeam/GhostTunnel), or called Wifi Covert Channel.

Hide backdoor payload in 802.11 Probe-req and Beacon Frame.

No actual WiFi connection is required.

## Usage

### Server

`# ./server-linux64 -iface your-monitor-mode-adapter`

Compile requirements: [gopacket](https://github.com/google/gopacket/), libpcap or winpcap

### Client

Client uses system native WiFi api, so we don't need privilege and additional dependency.

Simply run the `client.exe`. But I strongly recommend to use [P4wnP1](https://github.com/mame82/P4wnP1_aloa) to ship it!

>Tips:
>
>Maybe the fastest way is running a HID script to download the malware from P4wnP1's HTTP Server :-)

## Demo

![](./demo.gif)