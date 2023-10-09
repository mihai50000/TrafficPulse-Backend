package filters

import (
	"fmt"
	"packet-sniffer/model"
	"packet-sniffer/proxy/utils"
	"time"
)

type PacketFilters struct {
	StartTime      *time.Time
	EndTime        *time.Time
	SourceIps      []string
	DestinationIps []string
	Protocols      []string
}

func (filters PacketFilters) matches(packet model.PacketMetadata) bool {
	if filters.StartTime != nil {
		if packet.Timestamp.Before(*filters.StartTime) == true {
			return false
		}

		if filters.EndTime != nil && packet.Timestamp.After(*filters.EndTime) == true {
			return false
		}
	}

	if !utils.ArrayEmptyOrNil(filters.SourceIps) && utils.ArrayContainsString(filters.SourceIps, &packet.SenderIp) == false {
		return false
	}

	if !utils.ArrayEmptyOrNil(filters.DestinationIps) && utils.ArrayContainsString(filters.DestinationIps, &packet.ReceiverIp) == false {
		return false
	}

	if !utils.ArrayEmptyOrNil(filters.Protocols) && utils.ArrayContainsString(filters.Protocols, &packet.Protocol) == false {
		return false
	}

	return true
}

func AllAllowed() *PacketFilters {
	return &PacketFilters{
		StartTime:      nil,
		EndTime:        nil,
		SourceIps:      nil,
		DestinationIps: nil,
		Protocols:      nil,
	}
}

func AllAllowedFromNow() *PacketFilters {
	now := time.Now()
	start := now.Add(-5 * time.Minute)

	return &PacketFilters{
		StartTime:      &start,
		EndTime:        nil,
		SourceIps:      nil,
		DestinationIps: nil,
		Protocols:      nil,
	}
}

func (filters PacketFilters) String() string {
	return fmt.Sprintf("PacketFilters(startTime=%v, endTime=%v, sourceIps=%v, destinationIps=%v, protocols=%v)",
		filters.StartTime, filters.EndTime, filters.SourceIps, filters.DestinationIps, filters.Protocols)
}
