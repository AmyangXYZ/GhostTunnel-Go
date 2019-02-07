package main

// TunnelData is the secret data hidden in probe-req and beacon.
type TunnelData struct {
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
