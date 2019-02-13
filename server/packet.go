package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

	vendor := len(t.payload) > 26 // 32-6
	if vendor {
		t.length = 0x1A
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
