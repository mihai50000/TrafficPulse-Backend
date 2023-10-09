package model

import "time"

type PacketMetadata struct {
	Timestamp  time.Time
	Size       int32
	SenderIp   string
	ReceiverIp string
	Protocol   string
}
