package domain

import (
	"packet-sniffer/proxy/filters"
	"time"
)

type PackTimeWindow struct {
	Size    int32
	Start   *time.Time
	End     *time.Time
	Filters *filters.PacketFilters
}

func NewPackTimeWindow(size int32, start *time.Time, end *time.Time, filters *filters.PacketFilters) *PackTimeWindow {
	return &PackTimeWindow{
		Size:    size,
		Start:   start,
		End:     end,
		Filters: filters,
	}
}
