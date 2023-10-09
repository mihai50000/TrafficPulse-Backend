package processors

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"packet-sniffer/model"
)

func ExtractMetadata(packet gopacket.Packet) model.PacketMetadata {
	timestamp := packet.Metadata().CaptureInfo.Timestamp
	sizeInBytes := packet.Metadata().Length
	senderIp, receiverIp, _ := extractIPAddresses(packet)
	protocol, _ := extractProtocol(packet)

	return model.PacketMetadata{
		Timestamp:  timestamp,
		Size:       int32(sizeInBytes),
		SenderIp:   senderIp,
		ReceiverIp: receiverIp,
		Protocol:   protocol,
	}
}

func extractIPAddresses(packet gopacket.Packet) (string, string, error) {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		childLayer := packet.Layer(networkLayer.LayerType())
		if childLayer != nil && childLayer.LayerType() == layers.LayerTypeIPv4 {
			ipv4Layer := childLayer.(*layers.IPv4)

			srcIP, err1 := ipv4Layer.SrcIP.MarshalText()
			dstIP, err2 := ipv4Layer.DstIP.MarshalText()

			if err1 != nil {
				return "", "", err1
			}
			if err2 != nil {
				return "", "", err2
			}

			return string(srcIP), string(dstIP), nil
		}
	}
	return "", "", fmt.Errorf("unable to extract IP addresses from packet")
}

func extractProtocol(packet gopacket.Packet) (string, error) {
	transportLayer := packet.TransportLayer()

	if transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			return "TCP", nil
		case layers.LayerTypeUDP:
			return "UDP", nil
		case layers.LayerTypeICMPv4:
			return "ICMPv4", nil
		case layers.LayerTypeICMPv6:
			return "ICMPv6", nil
		default:
			return "unknown", nil
		}
	}

	return "", fmt.Errorf("no transport layer found in packet")
}
