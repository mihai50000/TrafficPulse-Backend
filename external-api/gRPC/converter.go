package proto

import (
	"packet-sniffer/model"
	"time"
)

func MetadataToProto(metadata model.PacketMetadata) PacketMetadata {
	return PacketMetadata{
		Timestamp:  metadata.Timestamp.Format(time.RFC3339),
		Size:       metadata.Size,
		SenderIp:   metadata.SenderIp,
		ReceiverIp: metadata.ReceiverIp,
		Protocol:   metadata.Protocol,
	}
}

func ProtoToMetadata(protoMetadata *PacketMetadata) model.PacketMetadata {

	timestamp, _ := time.Parse(time.RFC3339, protoMetadata.Timestamp)

	return model.PacketMetadata{
		Timestamp:  timestamp,
		Size:       protoMetadata.Size,
		SenderIp:   protoMetadata.SenderIp,
		ReceiverIp: protoMetadata.ReceiverIp,
		Protocol:   protoMetadata.Protocol,
	}
}

func ProtoSliceToMetadataSlice(protoMetadataList *PacketMetadataList) *[]model.PacketMetadata {
	var packetsList []model.PacketMetadata

	for _, protoPacket := range protoMetadataList.GetMetadata() {
		packetsList = append(packetsList, ProtoToMetadata(protoPacket))
	}

	return &packetsList
}
