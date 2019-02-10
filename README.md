# Ghost Tunnel - Go

Golang version of [Ghost Tunnel](https://github.com/360PegasusTeam/GhostTunnel), or called Wifi Covert Channel.

Hide backdoor payload in 802.11 probe-req and beacon frame.

No actual WiFi connection is required.

## Usage

### Server

`# ./server-linux64 -iface your-monitor-mode-adapter`

Compile requirements: [gopacket](https://github.com/google/gopacket/), libpcap or winpcap

### Client

Clients use system native WiFi api, so we don't need privilege and additional dependency.

#### Windows

Simply run the client_win.exe. But I strongly recommend to use [P4wnP1](https://github.com/mame82/P4wnP1_aloa) to ship it!

## Demo

![](./ghserver-demo.gif)

## Status

Server side done.

Windows client almost done(I am stuck in extracting Information Elements, not as simple as using C++, which means the client cannot receive command longer than 26 bytes)

## Todo

Linux and Mac clients.