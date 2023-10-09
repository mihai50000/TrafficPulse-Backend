package packets_service

import (
	"packet-sniffer/model"
	"packet-sniffer/proxy/channel"
	"packet-sniffer/proxy/repository"
)

var packetsChannel chan *[]model.PacketMetadata
var dbRepo repository.DbRepo

func Init() {
	packetsChannel = channel.GetProtoToProcessorsChannel()
	dbRepo = *repository.GetRepo()
}

func StartNewProcessor() {
	go func() {
		for {
			packetsList, ok := <-packetsChannel
			if !ok {
				continue
			}

			go dbRepo.StorePackets(packetsList)
		}
	}()
}
