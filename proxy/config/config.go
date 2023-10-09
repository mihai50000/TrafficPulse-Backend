package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	GRPC struct {
		ServerPort  int `yaml:"server-port"`
		PingTimeSec int `yaml:"pingTimeSec"`
		TimeoutSec  int `yaml:"timeoutSec"`
	} `yaml:"gRPC"`
	Channels struct {
		Size int `yaml:"size"`
	} `yaml:"channels"`
	Client struct {
		WindowCount        int `yaml:"windowCount"`
		MinWindowLengthSec int `yaml:"minWindowLengthSec"`
	} `yaml:"client"`
	Database struct {
		Connection struct {
			ServerURL    string `yaml:"serverUrl"`
			Organization string `yaml:"org"`
			Bucket       string `yaml:"bucket"`
			Token        string `yaml:"token"`
		} `yaml:"connection"`
		Query struct {
			BatchSize  uint `yaml:"batchSize"`
			TimeoutSec int  `yaml:"timeoutSec"`
		} `yaml:"query"`
	} `yaml:"db"`
	WSS struct {
		ReadBufferSize  int `yaml:"readBufferSize"`
		WriteBufferSize int `yaml:"writeBufferSize"`
		Port            int `yaml:"port"`
	} `yaml:"wss"`
	LogFile string `yaml:"logFile"`
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
