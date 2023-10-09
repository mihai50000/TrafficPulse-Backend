package packets_service

import (
	"context"
	"github.com/procyon-projects/chrono"
	"packet-sniffer/logger"
	"packet-sniffer/proxy/channel"
	"packet-sniffer/proxy/config"
	"packet-sniffer/proxy/domain"
	"packet-sniffer/proxy/filters"
	"packet-sniffer/proxy/repository"
	"sync"
	"time"
)

var managerId int

type PacketWindowManager struct {
	start          *time.Time
	end            *time.Time
	dbRepo         *repository.DbRepo
	outputChannel  chan *domain.PackTimeWindow
	taskScheduler  *chrono.TaskScheduler
	delayTaskTimer *time.Timer
	filters        *filters.PacketFilters
	id             int
	isRunning      bool
	lock           sync.Mutex
}

func NewManagerWithFilters(filters *filters.PacketFilters) PacketWindowManager {
	managerId++
	if filters.EndTime == nil {
		return NewLiveWindowManager(*filters.StartTime, *repository.GetRepo(), filters)
	} else {
		return NewFixedWindowManager(*filters.StartTime, *filters.EndTime, *repository.GetRepo(), filters)
	}
}

func NewLiveWindowManager(start time.Time, repo repository.DbRepo, filters *filters.PacketFilters) PacketWindowManager {
	scheduler := chrono.NewDefaultTaskScheduler()

	return PacketWindowManager{
		start:         &start,
		end:           nil,
		dbRepo:        &repo,
		outputChannel: channel.GetNewPacketsManagerChannel(),
		taskScheduler: &scheduler,
		filters:       filters,
		id:            managerId,
		isRunning:     false,
	}
}

func NewFixedWindowManager(start time.Time, end time.Time, repo repository.DbRepo, filters *filters.PacketFilters) PacketWindowManager {
	return PacketWindowManager{
		start:         &start,
		end:           &end,
		dbRepo:        &repo,
		outputChannel: channel.GetNewPacketsManagerChannel(),
		taskScheduler: nil,
		filters:       filters,
		id:            managerId,
		isRunning:     false,
	}
}

func (manager *PacketWindowManager) GetChannel() chan *domain.PackTimeWindow {
	return manager.outputChannel
}

func (manager *PacketWindowManager) StopManager() {
	logger.GetLogger().InfoLogger.Printf("Manager %d closed\n", manager.id)

	if manager.delayTaskTimer != nil {
		manager.delayTaskTimer.Stop()
	}

	if manager.taskScheduler != nil {
		scheduler := *manager.taskScheduler

		for scheduler.IsShutdown() == false {
			scheduler.Shutdown()
		}
	}

	manager.lock.Lock()
	manager.isRunning = false
	close(manager.outputChannel)
	manager.lock.Unlock()
}

func (manager *PacketWindowManager) StartManager() {
	log := logger.GetLogger()
	start := *manager.start

	var end time.Time

	if manager.end == nil {
		log.InfoLogger.Printf("Started live manager %d\n", manager.id)
		end = time.Now()
		windowCount := time.Duration(config.Configuration.Client.WindowCount)
		log.InfoLogger.Printf("Window length: %s\n", end.Sub(start)/windowCount)
		go manager.periodicDispatch(end.Add(time.Nanosecond), end.Sub(start)/windowCount)
	} else {
		log.InfoLogger.Println("Started static manager")
		end = *manager.end
	}

	manager.isRunning = true

	for _, window := range *getWindows(start, end) {
		manager.outputChannel <- dbRepo.GetAggregatedPackets(window.Start, window.End, manager.filters)
	}
}

type timeWindow struct {
	Start time.Time
	End   time.Time //excluded
}

func getWindows(start time.Time, end time.Time) *[]timeWindow {
	var windows []timeWindow

	timeWindowLength, cntWindows := getWindowsLengthAndCount(start, end)

	for windowId := 1; windowId <= cntWindows; windowId++ {
		windows = append(windows, timeWindow{
			Start: start,
			End:   start.Add(timeWindowLength - 1),
		})
		start = start.Add(timeWindowLength)
	}

	return &windows
}

func (manager *PacketWindowManager) periodicDispatch(windowStart time.Time, windowLength time.Duration) {
	log := logger.GetLogger()
	taskScheduler := chrono.NewDefaultTaskScheduler()
	minimumWindowLength := time.Duration(config.Configuration.Client.MinWindowLengthSec) * time.Second
	manager.delayTaskTimer = time.AfterFunc(windowLength*2+2*minimumWindowLength, func() {
		log.InfoLogger.Printf("Manager %d. start schedule: time: %s start: %s  length: %s\n", manager.id, time.Now(), windowStart, windowLength)
		_, _ = taskScheduler.ScheduleAtFixedRate(func(ctx context.Context) {
			windowEnd := windowStart.Add(windowLength - 1)
			start := windowStart
			windowStart = windowStart.Add(windowLength)
			manager.lock.Lock()
			if manager.isRunning == true {
				manager.outputChannel <- manager.dbRepo.GetAggregatedPackets(start, windowEnd, manager.filters)
			} else {
				return
			}
			manager.lock.Unlock()
		}, windowLength)
	})
}

func getWindowsLengthAndCount(start time.Time, end time.Time) (time.Duration, int) {
	timeDifference := end.Sub(start)
	windowCount := config.Configuration.Client.WindowCount
	timeWindowLength := timeDifference / time.Duration(windowCount)
	minimumWindowLength := time.Duration(config.Configuration.Client.MinWindowLengthSec) * time.Second

	if timeWindowLength >= minimumWindowLength {
		return timeWindowLength, windowCount
	}

	cnt := int(timeDifference / minimumWindowLength)
	timeWindowLength = timeDifference / time.Duration(cnt)
	return timeWindowLength, cnt
}
