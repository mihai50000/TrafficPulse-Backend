package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	ChannelsSize   int      `yaml:"channelsSize"`
	LogFile        string   `yaml:"logFile"`
	AllowedDevices []string `yaml:"allowedDevices"`
	Sniffer        struct {
		BPFiltersPath string `yaml:"BPFFiltersPath"`
	} `yaml:"sniffer"`
	Processor struct {
		DataSendingWindowLengthSec int `yaml:"dataSendingWindowLengthSec"`
	} `yaml:"processor"`
	GRPC struct {
		ServerAddress string `yaml:"serverAddress"`
	} `yaml:"gRPC"`
}

var Configuration Config

func InitConfiguration(configLocation string) error {
	file, err := os.Open(configLocation)

	if err != nil {
		return err
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&Configuration)

	if err != nil {
		return err
	}

	return nil
}
