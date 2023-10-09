package sniffers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"os"
	"packet-sniffer/collectors/config"
	"sync/atomic"
)

type DeviceSniffingInfo struct {
	device      pcap.Interface
	dataChannel chan gopacket.Packet
	filters     *atomic.Value
	isRunning   *atomic.Bool
}

func (sniffer *DeviceSniffingInfo) DataChannel() *chan gopacket.Packet {
	return &sniffer.dataChannel
}

func (sniffer *DeviceSniffingInfo) Filters() *atomic.Value {
	return sniffer.filters
}

func (sniffer *DeviceSniffingInfo) IsRunning() *atomic.Bool {
	return sniffer.isRunning
}

func (sniffer *DeviceSniffingInfo) Device() *pcap.Interface {
	return &sniffer.device
}

var sniffers []*DeviceSniffingInfo
var dataChannel chan gopacket.Packet

func init() {
	dataChannel = make(chan gopacket.Packet, config.Configuration.ChannelsSize)
}

var bpfFilters string

func Init() error {
	filtersLocation := config.Configuration.Sniffer.BPFiltersPath

	filters, err := os.ReadFile(filtersLocation)

	if err != nil {
		return err
	}

	bpfFilters = string(filters)
	return nil
}

func StartSniffers() {
	devices := GetDevices()

	for _, device := range devices {
		filters := atomic.Value{}
		filters.Store(bpfFilters)

		isRunning := atomic.Bool{}
		isRunning.Store(false)

		dev := DeviceSniffingInfo{device, dataChannel, &filters, &isRunning}

		sniffers = append(sniffers, &dev)
		go sniff(&dev)
	}
}

func GetDataChannel() chan gopacket.Packet {
	return dataChannel
}
