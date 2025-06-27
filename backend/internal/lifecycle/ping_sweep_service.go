package lifecycle

import (
	"context"
	"log"
	"reconya-ai/internal/pingsweep"
	"time"
)

// PingSweepService wraps the ping sweep service for lifecycle management
type PingSweepServiceWrapper struct {
	service  *pingsweep.PingSweepService
	interval time.Duration
	running  bool
}

// NewPingSweepServiceWrapper creates a new wrapper for the ping sweep service
func NewPingSweepServiceWrapper(service *pingsweep.PingSweepService, interval time.Duration) *PingSweepServiceWrapper {
	return &PingSweepServiceWrapper{
		service:  service,
		interval: interval,
	}
}

// Name returns the service name
func (w *PingSweepServiceWrapper) Name() string {
	return "PingSweepService"
}

// Start starts the ping sweep service with periodic execution
func (w *PingSweepServiceWrapper) Start(ctx context.Context) error {
	w.running = true
	log.Printf("Starting ping sweep service with %v interval", w.interval)
	
	// Run initial scan
	w.service.Run()
	
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Ping sweep service received shutdown signal")
			return ctx.Err()
		case <-ticker.C:
			if w.running {
				log.Println("Running scheduled ping sweep...")
				w.service.Run()
			}
		}
	}
}

// Stop stops the ping sweep service
func (w *PingSweepServiceWrapper) Stop() error {
	log.Println("Stopping ping sweep service...")
	w.running = false
	return nil
}