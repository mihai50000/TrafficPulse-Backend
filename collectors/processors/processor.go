package processors

import (
	"context"
	"github.com/google/gopacket"
	"github.com/procyon-projects/chrono"
	"packet-sniffer/collectors/config"
	externalApi "packet-sniffer/collectors/external-api"
	pb "packet-sniffer/external-api/gRPC"
	"sync"
	"time"
)

func HandlePackets(dataChannel chan gopacket.Packet) {
	packetsList := &[]pb.PacketMetadata{}
	var packagesMutex sync.Mutex

	startSendingPackagesPeriodically(&packetsList, &packagesMutex)

	for {
		packet, ok := <-dataChannel

		if !ok {
			continue
		}

		metadata := pb.MetadataToProto(ExtractMetadata(packet))
		packagesMutex.Lock()
		*packetsList = append(*packetsList, metadata)
		packagesMutex.Unlock()
	}
}

func startSendingPackagesPeriodically(packages **[]pb.PacketMetadata, mutex *sync.Mutex) {
	taskScheduler := chrono.NewDefaultTaskScheduler()

	_, _ = taskScheduler.ScheduleAtFixedRate(func(ctx context.Context) {
		sendPackages(packages, mutex)
	}, time.Second*time.Duration(config.Configuration.Processor.DataSendingWindowLengthSec))
}

func sendPackages(packets **[]pb.PacketMetadata, mutex *sync.Mutex) {
	client := externalApi.GetNewClient()

	var packetsToSend *[]pb.PacketMetadata
	mutex.Lock()
	packetsToSend = *packets
	*packets = &[]pb.PacketMetadata{}
	mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	var pointersToMetadata []*pb.PacketMetadata

	var size int32
	for i := 0; i < len(*packetsToSend); i++ {
		pointersToMetadata = append(pointersToMetadata, &((*packetsToSend)[i]))
		size += ((*packetsToSend)[i]).Size
	}

	_, err := client.SendPacketMetadataList(ctx, &pb.PacketMetadataList{Metadata: pointersToMetadata})
	if err != nil {
		return
	}
}