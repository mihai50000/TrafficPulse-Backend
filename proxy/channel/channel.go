package channel

import (
	"packet-sniffer/model"
	"packet-sniffer/proxy/config"
	"packet-sniffer/proxy/domain"
)

var protoToProcessorsChannel chan *[]model.PacketMetadata

func Init() {
	protoToProcessorsChannel = make(chan *[]model.PacketMetadata, config.Configuration.Channels.Size)
}

func GetProtoToProcessorsChannel() chan *[]model.PacketMetadata {
	return protoToProcessorsChannel
}

func GetNewPacketsManagerChannel() chan *domain.PackTimeWindow {
	return make(chan *domain.PackTimeWindow, config.Configuration.Channels.Size)
}
