package logger

import (
	"log"
	"os"
)

type GLogger struct {
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
}

var logger *GLogger

func Init(logLocation string) {
	file, err := os.OpenFile(logLocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	InfoLogger := log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger := log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger := log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	logger = &GLogger{InfoLogger: InfoLogger, WarningLogger: WarningLogger, ErrorLogger: ErrorLogger}
}

func GetLogger() *GLogger {
	return logger
}
