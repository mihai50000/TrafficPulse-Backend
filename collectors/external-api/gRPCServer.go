package external_api

import (
	_ "flag"
	"google.golang.org/grpc"
	_ "log"
	_ "math/rand"
	"packet-sniffer/collectors/config"
	pb "packet-sniffer/external-api/gRPC"
	"packet-sniffer/logger"
)

var serverAddr string
var conn *grpc.ClientConn

func Init() {
	serverAddr = config.Configuration.GRPC.ServerAddress
}

func StartServer() error {
	log := logger.GetLogger()

	var err error

	conn, err = grpc.Dial(serverAddr, grpc.WithInsecure())
	if err != nil {
		log.ErrorLogger.Println(err)
		log.ErrorLogger.Println("Failed to connect to server!")
		return err
	}

	return nil
}

func GetNewClient() pb.PacketCaptureClient {
	return pb.NewPacketCaptureClient(conn)
}
