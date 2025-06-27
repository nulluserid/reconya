package lifecycle

import (
	"context"
	"log"
	"reconya-ai/internal/device"
	"time"
)

// DeviceUpdaterService wraps the device update functionality for lifecycle management
type DeviceUpdaterService struct {
	deviceService *device.DeviceService
	interval      time.Duration
	running       bool
}

// NewDeviceUpdaterService creates a new device updater service
func NewDeviceUpdaterService(deviceService *device.DeviceService, interval time.Duration) *DeviceUpdaterService {
	return &DeviceUpdaterService{
		deviceService: deviceService,
		interval:      interval,
	}
}

// Name returns the service name
func (d *DeviceUpdaterService) Name() string {
	return "DeviceUpdaterService"
}

// Start starts the device updater service
func (d *DeviceUpdaterService) Start(ctx context.Context) error {
	d.running = true
	log.Printf("Starting device updater service with %v interval", d.interval)
	
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Device updater service received shutdown signal")
			return ctx.Err()
		case <-ticker.C:
			if d.running {
				err := d.deviceService.UpdateDeviceStatuses()
				if err != nil {
					log.Printf("Failed to update device statuses: %v", err)
					// Add a delay after an error to allow other operations to complete
					time.Sleep(1 * time.Second)
				}
			}
		}
	}
}

// Stop stops the device updater service
func (d *DeviceUpdaterService) Stop() error {
	log.Println("Stopping device updater service...")
	d.running = false
	return nil
}