package repository

import (
	"context"
	"fmt"
	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api/http"
	"math/rand"
	net "net/http"
	"packet-sniffer/logger"
	"packet-sniffer/model"
	"packet-sniffer/proxy/config"
	"packet-sniffer/proxy/domain"
	"packet-sniffer/proxy/filters"
	"strconv"
	"sync"
	"time"
)

type DbRepo struct {
	client influxdb2.Client
}

var repoInstance *DbRepo
var clientLock sync.Mutex

func newRepo() *DbRepo {
	serverUrl := config.Configuration.Database.Connection.ServerURL
	token := config.Configuration.Database.Connection.Token
	batchSize := config.Configuration.Database.Query.BatchSize
	return &DbRepo{client: influxdb2.NewClientWithOptions(serverUrl, token, influxdb2.DefaultOptions().SetBatchSize(batchSize).SetUseGZip(true).SetHTTPClient(&net.Client{
		Timeout: 5 * time.Minute,
	}))}
}

func GetRepo() *DbRepo {
	clientLock.Lock()
	if repoInstance == nil {
		repoInstance = newRepo()
	}
	clientLock.Unlock()

	return repoInstance
}

func (repo *DbRepo) StorePackets(packets *[]model.PacketMetadata) {
	org := config.Configuration.Database.Connection.Organization
	bucket := config.Configuration.Database.Connection.Bucket
	writeAPI := repo.client.WriteAPI(org, bucket)
	writeAPI.SetWriteFailedCallback(func(batch string, error http.Error, retryAttempts uint) bool {
		logger.GetLogger().ErrorLogger.Println(error)
		return true
	})

	for _, packet := range *packets {
		point := influxdb2.NewPointWithMeasurement("packets").
			AddTag("sender_ip", packet.SenderIp).
			AddTag("receiver_ip", packet.ReceiverIp).
			AddTag("protocol", packet.Protocol).
			AddTag("uniqId", strconv.FormatFloat(float64(rand.Intn(100000000))*rand.Float64(), 'f', -1, 64)).
			AddField("size", packet.Size).
			SetTime(packet.Timestamp)

		writeAPI.WritePoint(point)
	}

	writeAPI.Flush()

	errors := writeAPI.Errors()
	if errors != nil {
		for err := range errors {
			logger.GetLogger().ErrorLogger.Println("DB Write error:", err.Error())
		}
	}
}

func (repo *DbRepo) GetAggregatedPackets(start time.Time, end time.Time, filters *filters.PacketFilters) *domain.PackTimeWindow {
	org := config.Configuration.Database.Connection.Organization
	bucket := config.Configuration.Database.Connection.Bucket
	queryAPI := repo.client.QueryAPI(org)
	fluxQuery := fmt.Sprintf(`
	from(bucket: "%s")
		|> range(start: %s, stop: %s)
		|> filter(fn: (r) => r._measurement == "packets")`,
		bucket, start.UTC().Format("2006-01-02T15:04:05.999999999Z"), end.UTC().Format("2006-01-02T15:04:05.999999999Z"))

	if filters.SourceIps != nil && len(filters.SourceIps) > 0 {
		fluxQuery += fmt.Sprintf("\n	|> filter(fn: (r) => contains(set: %q, value: r.sender_ip))", filters.SourceIps)
	}

	if filters.DestinationIps != nil && len(filters.DestinationIps) > 0 {
		fluxQuery += fmt.Sprintf("\n	|> filter(fn: (r) => contains(set: %q, value: r.receiver_ip))", filters.DestinationIps)
	}

	if filters.Protocols != nil && len(filters.Protocols) > 0 {
		fluxQuery += fmt.Sprintf("\n	|> filter(fn: (r) => contains(set: %q, value: r.protocol))", filters.Protocols)
	}

	fluxQuery += fmt.Sprintln("\n	|> filter(fn: (r) => r[\"_field\"] == \"size\")")
	fluxQuery += fmt.Sprintln(`	|> group()`)
	fluxQuery += fmt.Sprintln(`	|> sum()`)

	result, err := queryAPI.Query(context.Background(), fluxQuery)
	if err != nil {
		logger.GetLogger().ErrorLogger.Println(err)
		return domain.NewPackTimeWindow(0, &start, &end, filters)
	}

	fmt.Println(fluxQuery)

	if result.Next() {
		record := result.Record()

		value := record.Value()
		if value != nil {
			sum := int32(value.(int64))
			fmt.Println(sum)
			return domain.NewPackTimeWindow(sum, &start, &end, filters)
		}
	}

	fmt.Println("ZERO")
	return domain.NewPackTimeWindow(0, &start, &end, filters)
}
