package sniffers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"packet-sniffer/logger"
)

const (
	defaultSnapLen = 262144
)

var handle *pcap.Handle

func sniff(sniffer *DeviceSniffingInfo) {
	log := logger.GetLogger()

	log.InfoLogger.Printf("Starting sniffing on device: %s ", sniffer.Device().Name)
	defer log.InfoLogger.Printf("Stopped sniffing on device: %s ", sniffer.Device().Name)

	sniffer.IsRunning().Store(true)

	generatedHandle, err := pcap.OpenLive(sniffer.Device().Name, defaultSnapLen, true, pcap.BlockForever)
	handle = generatedHandle

	if err != nil {
		sniffer.IsRunning().Store(false)
		log.ErrorLogger.Println(err)
		return
	}

	defer sniffer.IsRunning().Store(false)
	defer handle.Close()

	err = handle.SetBPFFilter(sniffer.Filters().Load().(string))

	if err != nil {
		log.ErrorLogger.Println(err)
	}

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for pkt := range packets {
		if !sniffer.IsRunning().Load() {
			return
		}
		*sniffer.DataChannel() <- pkt
	}
}
