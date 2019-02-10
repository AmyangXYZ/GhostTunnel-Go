package main

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
