package web

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"packet-sniffer/logger"
	"packet-sniffer/proxy/config"
	"packet-sniffer/proxy/domain"
	"packet-sniffer/proxy/filters"
	packetsService "packet-sniffer/proxy/packets-service"
	"sync"
	"time"
)

type connectionSettings struct {
	dataChannel chan *domain.PackTimeWindow
	filters     *filters.PacketFilters
	manager     *packetsService.PacketWindowManager
}

func (settings *connectionSettings) setNewFilters(newFilters *filters.PacketFilters) {
	settings.filters = newFilters
	(*settings.manager).StopManager()
	newManager := packetsService.NewManagerWithFilters(newFilters)
	settings.manager = &newManager
	newManager.StartManager()
}

var upgrader websocket.Upgrader
var clients *sync.Map

func Init() {
	upgrader = websocket.Upgrader{
		ReadBufferSize:  config.Configuration.WSS.ReadBufferSize,
		WriteBufferSize: config.Configuration.WSS.WriteBufferSize,

		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
}

func StartServer() {
	Init()
	clients = &sync.Map{}

	go func() {
		http.HandleFunc("/data/ws", wsEndpoint)

		port := config.Configuration.WSS.Port
		addr := fmt.Sprintf(":%d", port)
		err := http.ListenAndServe(addr, nil)

		if err != nil {
			os.Exit(1)
		}
	}()
}

func wsEndpoint(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.ErrorLogger.Println(err)
		return
	}

	defer func(conn *websocket.Conn) {
		err := conn.Close()

		for err != nil {

			log.ErrorLogger.Println("Error occurred while closing the ws connection! Retrying ...")
			err = conn.Close()
		}

		log.ErrorLogger.Printf("WSS Connection closed %s\n", r.RemoteAddr)
	}(conn)

	defaultFilters := filters.AllAllowedFromNow()
	manager := packetsService.NewManagerWithFilters(defaultFilters)
	manager.StartManager()
	clients.Store(conn, &connectionSettings{filters: defaultFilters, dataChannel: manager.GetChannel(), manager: &manager})

	go handleWSSRequests(conn)
	go handleReceivedNewPackets(&manager, conn)

	select {}
}

func handleReceivedNewPackets(manager *packetsService.PacketWindowManager, conn *websocket.Conn) {
	log := logger.GetLogger()

	for {
		packetsWindow, ok := <-manager.GetChannel()

		if !ok {
			rawSettings, _ := clients.Load(conn)
			settings := (rawSettings).(*connectionSettings)
			manager = settings.manager
			continue
		}

		jsonData := struct {
			Size    int32
			Start   string
			End     string
			Filters *filters.PacketFilters
		}{
			Size:    packetsWindow.Size,
			Start:   packetsWindow.Start.Format("2006-01-02T15:04:05.000"),
			End:     packetsWindow.End.Format("2006-01-02T15:04:05.000"),
			Filters: packetsWindow.Filters,
		}

		// Marshal the new struct to JSON
		result, err := json.Marshal(jsonData)

		if err != nil {
			log.ErrorLogger.Println(err)
			return
		}

		err = conn.WriteMessage(websocket.TextMessage, result)

		if err != nil {
			manager.StopManager()
			log.ErrorLogger.Println(err)
			return
		}
	}
}

func handleWSSRequests(conn *websocket.Conn) {
	for {
		messageType, message, err := conn.ReadMessage()

		if err != nil {
			if closeErr, ok := err.(*websocket.CloseError); ok {
				rawSettings, _ := clients.Load(conn)
				settings := (rawSettings).(*connectionSettings)
				manager := settings.manager
				manager.StopManager()
				logger.GetLogger().ErrorLogger.Printf("Connection closed with code %d: %s", closeErr.Code, closeErr.Text)
			}
			return
		}

		handleMessage(conn, messageType, message)
	}
}

func handleMessage(conn *websocket.Conn, messageType int, messageBytes []byte) {
	log := logger.GetLogger()

	if messageType != websocket.TextMessage {
		return
	}
	var rawFilters struct {
		StartTime      *string
		EndTime        *string
		Protocols      []string
		SourceIps      []string
		DestinationIps []string
	}

	err := json.Unmarshal(messageBytes, &rawFilters)

	if err != nil {
		log.ErrorLogger.Println(err)
		return
	}

	startTime, err := time.Parse("2006-01-02T15:04", *rawFilters.StartTime)

	if err != nil {
		log.ErrorLogger.Println(err)
		return
	}

	var endTime *time.Time

	if rawFilters.EndTime == nil {
		endTime = nil
	} else {
		rawEndTime, err := time.Parse("2006-01-02T15:04", *rawFilters.EndTime)
		endTime = &rawEndTime
		if err != nil {
			log.ErrorLogger.Println(err)
			return
		}
	}

	newFilters := filters.PacketFilters{
		StartTime:      &startTime,
		EndTime:        endTime,
		Protocols:      rawFilters.Protocols,
		SourceIps:      rawFilters.SourceIps,
		DestinationIps: rawFilters.DestinationIps,
	}

	settingsRaw, _ := clients.Load(conn)
	settings := settingsRaw.(*connectionSettings)
	settings.setNewFilters(&newFilters)
}
