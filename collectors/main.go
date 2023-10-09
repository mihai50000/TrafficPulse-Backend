package main

import (
	"fmt"
	"os"
	"packet-sniffer/collectors/config"
	"packet-sniffer/collectors/external-api"
	"packet-sniffer/collectors/processors"
	"packet-sniffer/collectors/sniffers"
	"packet-sniffer/logger"
)

func init() {
	err := config.InitConfiguration("collectors/config.yml")

	if err != nil {
		fmt.Println("Error: ")
		fmt.Println(err)
		os.Exit(1)
	}

	external_api.Init()
	err = sniffers.Init()

	if err != nil {
		fmt.Println("Error: ")
		fmt.Println(err)
		os.Exit(1)
	}

	logger.Init(config.Configuration.LogFile)
}

func main() {
	err := external_api.StartServer()

	if err != nil {
		logger.GetLogger().ErrorLogger.Printf("Error %s\n", err)
		os.Exit(1)
	}

	go processors.HandlePackets(sniffers.GetDataChannel())
	go processors.HandlePackets(sniffers.GetDataChannel())
	go processors.HandlePackets(sniffers.GetDataChannel())

	sniffers.StartSniffers()

	select {}
}
