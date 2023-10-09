package gRPC

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"log"
	"net"
	"os"
	pb "packet-sniffer/external-api/gRPC"
	"packet-sniffer/logger"
	"packet-sniffer/model"
	"packet-sniffer/proxy/channel"
	"packet-sniffer/proxy/config"
	"strconv"
	"time"
)

type Server struct {
	pb.UnimplementedPacketCaptureServer
	bpfFiltersChan chan string
}

var packetsChannel chan *[]model.PacketMetadata
var servers map[string]*Server

func (s *Server) SendPacketMetadataList(_ context.Context, in *pb.PacketMetadataList) (*pb.Empty, error) {
	metadataSlice := pb.ProtoSliceToMetadataSlice(in)
	packetsChannel <- metadataSlice
	return &pb.Empty{}, nil
}

func (s *Server) SetBPFFilters(id *pb.ID, server pb.PacketCapture_SetBPFFiltersServer) error {
	servers[id.Ip] = s
	s.bpfFiltersChan = make(chan string, config.Configuration.Channels.Size)

	for {
		filters, ok := <-s.bpfFiltersChan

		if !ok {
			break
		}

		protoFilters := pb.BPFFilters{Filters: filters}
		err := server.Send(&protoFilters)
		if err != nil {
			return err
		}
	}

	defer delete(servers, id.Ip)
	return nil
}

func StartServer(port int) error {
	packetsChannel = channel.GetProtoToProcessorsChannel()
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(port))

	if err != nil {
		log.Fatal(err)
		return err
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveParams(
		keepalive.ServerParameters{
			Time:    time.Duration(config.Configuration.GRPC.PingTimeSec) * time.Second, // Ping the client every 10 seconds
			Timeout: time.Duration(config.Configuration.GRPC.TimeoutSec) * time.Second,  // Consider the client disconnected if no ping received for 5 seconds
		},
	))
	pb.RegisterPacketCaptureServer(grpcServer, &Server{})

	servers = make(map[string]*Server)

	go func() {
		err := grpcServer.Serve(lis)
		if err != nil {
			logger.GetLogger().ErrorLogger.Println(err)
			os.Exit(1)
		}
	}()

	return nil
}
