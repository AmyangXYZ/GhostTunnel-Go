package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	ERROR_SUCCESS = 0x0
	MAX_INDEX     = 1000
)

var e syscall.Errno

var (
	hWlanOpenHandle        *syscall.LazyProc
	hWlanCloseHandle       *syscall.LazyProc
	hWlanFreeMemory        *syscall.LazyProc
	hWlanEnumInterfaces    *syscall.LazyProc
	hWlanScan              *syscall.LazyProc
	hWlanGetNetworkBssList *syscall.LazyProc
)

// windows native wifi api types.
type (
	DOT11_SSID struct {
		uSSIDLength uint32
		ucSSID      [32]byte
	}

	GUID struct {
		Data1 uint
		Data2 uint16
		Data3 uint16
		Data4 [8]byte
	}

	WLAN_INTERFACE_INFO_LIST struct {
		dwNumberOfItems uint32
		dwIndex         uint32
		InterfaceInfo   [MAX_INDEX + 1]WLAN_INTERFACE_INFO
	}

	WLAN_INTERFACE_INFO struct {
		InterfaceGuid           GUID
		strInterfaceDescription [256]uint16
		isState                 uint32
	}

	WLAN_RAW_DATA struct {
		dwDataSize uint32
		DataBlob   [257]byte
	}

	WLAN_BSS_LIST struct {
		dwTotalSize     uint32
		dwNumberOfItems uint32
		wlanBssEntries  [MAX_INDEX + 1]WLAN_BSS_ENTRY
	}

	WLAN_BSS_ENTRY struct {
		dot11Ssid               DOT11_SSID
		uPhyID                  uint32
		dot11Bssid              [6]byte
		dot11BssType            uint32
		dot11BssPhyType         uint32
		lRssi                   int32
		uLinkQuality            uint32
		bInRegDomain            int32
		usBeaconPeriod          uint16
		ullTimestamp            uint64
		ullHostTimestamp        uint64
		usCapabilityInformation uint16
		ulChCenterFrequency     uint32
		wlanRateSet             WLAN_RATE_SET
		ulIeOffset              uint32
		ulIeSize                uint32
	}

	WLAN_RATE_SET struct {
		uRateSetLength uint32
		usRateSet      [126]uint16
	}
)

func WlanOpenHandle(dwClientVersion uint32,
	pReserved uintptr,
	pdwNegotiatedVersion *uint32,
	phClientHandle *uintptr) syscall.Errno {
	e, _, _ := hWlanOpenHandle.Call(uintptr(dwClientVersion),
		pReserved,
		uintptr(unsafe.Pointer(pdwNegotiatedVersion)),
		uintptr(unsafe.Pointer(phClientHandle)))

	return syscall.Errno(e)
}

func WlanCloseHandle(hClientHandle uintptr,
	pReserved uintptr) syscall.Errno {
	e, _, _ := hWlanCloseHandle.Call(hClientHandle,
		pReserved)

	return syscall.Errno(e)
}

func WlanFreeMemory(pMemory uintptr) {
	_, _, _ = hWlanFreeMemory.Call(pMemory)
}

func WlanEnumInterfaces(hClientHandle uintptr,
	pReserved uintptr,
	ppInterfaceList **WLAN_INTERFACE_INFO_LIST) syscall.Errno {
	e, _, _ := hWlanEnumInterfaces.Call(hClientHandle,
		pReserved,
		uintptr(unsafe.Pointer(ppInterfaceList)))

	return syscall.Errno(e)
}

func WlanScan(hClientHandle uintptr,
	pInterfaceGuid *GUID,
	pDot11Ssid *DOT11_SSID,
	pIeData *WLAN_RAW_DATA,
	pReserved uintptr) syscall.Errno {
	e, _, _ := hWlanScan.Call(hClientHandle,
		uintptr(unsafe.Pointer(pInterfaceGuid)),
		uintptr(unsafe.Pointer(pDot11Ssid)),
		uintptr(unsafe.Pointer(pIeData)),
		pReserved)
	return syscall.Errno(e)
}

func WlanGetNetworkBssList(hClientHandle uintptr,
	pInterfaceGuid *GUID,
	pDot11Ssid *DOT11_SSID,
	dot11BssType uint32,
	bSecurityEnabled int32,
	pReserved uintptr,
	ppWlanBssList **WLAN_BSS_LIST) syscall.Errno {
	e, _, _ := hWlanGetNetworkBssList.Call(hClientHandle,
		uintptr(unsafe.Pointer(pInterfaceGuid)),
		uintptr(unsafe.Pointer(pDot11Ssid)),
		uintptr(dot11BssType),
		uintptr(bSecurityEnabled),
		pReserved,
		uintptr(unsafe.Pointer(ppWlanBssList)))
	return syscall.Errno(e)
}

func GetOEMCP() []byte {
	k := syscall.NewLazyDLL("kernel32.dll")
	acp, _, _ := k.NewProc("GetOEMCP").Call()
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(acp))
	return b
}

func init() {
	hapi := syscall.NewLazyDLL("wlanapi.dll")
	hWlanOpenHandle = hapi.NewProc("WlanOpenHandle")
	hWlanCloseHandle = hapi.NewProc("WlanCloseHandle")
	hWlanFreeMemory = hapi.NewProc("WlanFreeMemory")
	hWlanEnumInterfaces = hapi.NewProc("WlanEnumInterfaces")
	hWlanScan = hapi.NewProc("WlanScan")
	hWlanGetNetworkBssList = hapi.NewProc("WlanGetNetworkBssList")
}

type WinAPI struct {
	guid   GUID
	handle uintptr
	rSeq   uint8
	wSeq   uint8
}

// InitWinAPI setup windows wlanapi handler.
func InitWinAPI() *WinAPI {
	w := new(WinAPI)
	var ilist *WLAN_INTERFACE_INFO_LIST

	e = WlanOpenHandle(apiVersion, 0, &apiVersion, &w.handle)
	if e != ERROR_SUCCESS {
		fmt.Println(e.Error())
		os.Exit(int(e))
	}

	e = WlanEnumInterfaces(w.handle, 0, &ilist)
	if e != ERROR_SUCCESS {
		fmt.Println(e.Error())
		os.Exit(int(e))
	}
	if ilist.dwNumberOfItems == 0 {
		fmt.Println("No interface found")
		os.Exit(int(e))
	}
	defer WlanFreeMemory(uintptr(unsafe.Pointer(ilist)))

	w.guid = ilist.InterfaceInfo[0].InterfaceGuid

	return w
}

// Close wlanapi handler
func (w *WinAPI) Close() {
	e = WlanCloseHandle(w.handle, 0)
	if e != ERROR_SUCCESS {
		if e != ERROR_SUCCESS {
			fmt.Fprintln(os.Stderr, "WlanCloseHandle: ", e.Error())
			os.Exit(int(e))
		}
	}
}

// Send call WlanScan to send probe-req
func (w *WinAPI) Send(t *TunnelData) {
	var p1, p2 []byte
	var pIeData *WLAN_RAW_DATA

	// send simple probe-req to refresh bssid list
	if t == nil {
		e = WlanScan(w.handle, &w.guid, nil, nil, 0)

		if e != ERROR_SUCCESS {
			fmt.Println(1, e.Error())
		}
		return
	}

	t.flag = 0xFE
	w.wSeq++
	t.seq = w.wSeq
	t.length = uint8(len(t.payload))

	p1 = []byte(t.payload)

	if len(t.payload) > 26 {
		t.dataType |= DataInVendor
		t.length = 26
		p1 = []byte(t.payload)[0:26]
		p2 = []byte(t.payload)[26:]
		pIeData = &WLAN_RAW_DATA{
			dwDataSize: uint32(len(p2) + 2),
			DataBlob:   [257]byte{0xDD, uint8(len(p2))},
		}
		for i := 0; i < len(p2); i++ {
			pIeData.DataBlob[i+2] = p2[i]
		}
	}
	ssid := &DOT11_SSID{
		uSSIDLength: uint32(6 + t.length),
		ucSSID:      [32]byte{t.flag, t.dataType, t.seq, t.clientID, t.serverID, t.length},
	}
	for i := 0; i < len(p1); i++ {
		ssid.ucSSID[i+6] = p1[i]
	}

	// maybe the handler is busy now, try again and again
	for {
		e = WlanScan(w.handle, &w.guid, ssid, pIeData, 0)
		if e == ERROR_SUCCESS {
			break
		}
	}
	fmt.Printf("[*] Sent %d bytes\n", len(t.payload)+6)
}

// Receive call WlanGetNetworkBssList to scan ssid.
func (w *WinAPI) Receive() *TunnelData {
	var blist *WLAN_BSS_LIST
	var ssid *[32]byte
	e = WlanGetNetworkBssList(w.handle, &w.guid, nil, 0, 0, 0, &blist)
	if e != ERROR_SUCCESS {
		fmt.Println(e.Error())
		return nil
	}
	for i := uint32(0); i < blist.dwNumberOfItems; i++ {
		if blist.wlanBssEntries[i].dot11Ssid.ucSSID[0] == 0xFE {
			ssid = &blist.wlanBssEntries[i].dot11Ssid.ucSSID
			break
		}
	}
	WlanFreeMemory(uintptr(unsafe.Pointer(blist)))
	if ssid == nil {
		return nil
	}

	// this packet has been received
	if w.rSeq >= ssid[2] {
		return nil
	}
	if w.rSeq < ssid[2] {
		w.rSeq = ssid[2]
	}

	t := &TunnelData{
		flag:     ssid[0],
		dataType: ssid[1],
		seq:      ssid[2],
		clientID: ssid[3],
		serverID: ssid[4],
		length:   ssid[5],
		payload:  ssid[6 : 6+ssid[5]],
	}

	if (t.dataType & DataInVendor) != 0 {
		t.dataType &= ^DataInVendor

	}
	return t
}
