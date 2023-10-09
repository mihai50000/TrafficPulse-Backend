package sniffers

import (
	"github.com/google/gopacket/pcap"
	"packet-sniffer/collectors/config"
	"packet-sniffer/logger"
)

func GetDevices() []pcap.Interface {
	log := logger.GetLogger()
	availableDevices, err := pcap.FindAllDevs()

	if err != nil {
		log.ErrorLogger.Fatalf("errors retrieving availableDevices - %v", err)
	}

	allowedDevices := config.Configuration.AllowedDevices
	var usedDevices []pcap.Interface

	for _, aDevice := range availableDevices {
		for _, device := range allowedDevices {
			if device == aDevice.Name || device == "*" {
				usedDevices = append(usedDevices, aDevice)
				break
			}
		}
	}

	return usedDevices
}
