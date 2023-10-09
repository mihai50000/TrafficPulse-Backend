package main

import (
	"fmt"
	"os"
	"packet-sniffer/logger"
	"packet-sniffer/proxy/channel"
	"packet-sniffer/proxy/config"
	"packet-sniffer/proxy/external-api/gRPC"
	"packet-sniffer/proxy/packets-service"
	"packet-sniffer/proxy/web"
)

func init() {
	err := config.InitConfiguration("proxy/config.yml")

	if err != nil {
		fmt.Println("Error: ")
		fmt.Println(err)
		os.Exit(1)
	}

	logger.Init(config.Configuration.LogFile)

	channel.Init()
}

func main() {
	log := logger.GetLogger()
	err := gRPC.StartServer(config.Configuration.GRPC.ServerPort)

	if err != nil {
		log.ErrorLogger.Println(err)
		return
	}

	log.InfoLogger.Printf("Started gRPC server on port %d\n", config.Configuration.GRPC.ServerPort)

	web.StartServer()

	log.InfoLogger.Printf("Started web server on port %d\n", config.Configuration.WSS.Port)

	packets_service.Init()
	packets_service.StartNewProcessor()
	packets_service.StartNewProcessor()
	packets_service.StartNewProcessor()

	log.InfoLogger.Println("Started processors")

	select {}
}
