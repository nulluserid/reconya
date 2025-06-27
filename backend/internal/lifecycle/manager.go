package lifecycle

import (
	"context"
	"log"
	"sync"
	"time"
)

// Manager handles the lifecycle of background services and ensures proper cleanup
type Manager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	services   []Service
	wg         sync.WaitGroup
	mu         sync.RWMutex
	shutdown   chan struct{}
	terminated bool
}

// Service represents a background service that can be started and stopped
type Service interface {
	Start(ctx context.Context) error
	Stop() error
	Name() string
}

// NewManager creates a new lifecycle manager
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		ctx:      ctx,
		cancel:   cancel,
		services: make([]Service, 0),
		shutdown: make(chan struct{}),
	}
}

// Register adds a service to be managed
func (m *Manager) Register(service Service) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.terminated {
		log.Printf("Cannot register service %s: manager is terminated", service.Name())
		return
	}
	
	m.services = append(m.services, service)
	log.Printf("Registered service: %s", service.Name())
}

// StartAll starts all registered services
func (m *Manager) StartAll() error {
	m.mu.RLock()
	services := make([]Service, len(m.services))
	copy(services, m.services)
	m.mu.RUnlock()
	
	for _, service := range services {
		if err := m.startService(service); err != nil {
			log.Printf("Failed to start service %s: %v", service.Name(), err)
			// Continue starting other services
		}
	}
	
	return nil
}

// startService starts a single service in a goroutine
func (m *Manager) startService(service Service) error {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Service %s panicked: %v", service.Name(), r)
			}
		}()
		
		log.Printf("Starting service: %s", service.Name())
		if err := service.Start(m.ctx); err != nil && err != context.Canceled {
			log.Printf("Service %s stopped with error: %v", service.Name(), err)
		} else {
			log.Printf("Service %s stopped gracefully", service.Name())
		}
	}()
	
	return nil
}

// Shutdown gracefully stops all services with a timeout
func (m *Manager) Shutdown(timeout time.Duration) error {
	m.mu.Lock()
	if m.terminated {
		m.mu.Unlock()
		return nil
	}
	m.terminated = true
	services := make([]Service, len(m.services))
	copy(services, m.services)
	m.mu.Unlock()
	
	log.Printf("Shutting down %d services...", len(services))
	
	// Cancel context to signal all services to stop
	m.cancel()
	
	// Stop services in reverse order (LIFO)
	for i := len(services) - 1; i >= 0; i-- {
		service := services[i]
		go func(s Service) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Service %s panicked during shutdown: %v", s.Name(), r)
				}
			}()
			
			log.Printf("Stopping service: %s", s.Name())
			if err := s.Stop(); err != nil {
				log.Printf("Error stopping service %s: %v", s.Name(), err)
			}
		}(service)
	}
	
	// Wait for all services to stop with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("All services stopped gracefully")
		close(m.shutdown)
		return nil
	case <-time.After(timeout):
		log.Printf("Shutdown timeout exceeded (%v), forcing exit", timeout)
		close(m.shutdown)
		return context.DeadlineExceeded
	}
}

// Wait blocks until shutdown is complete
func (m *Manager) Wait() {
	<-m.shutdown
}

// Context returns the manager's context
func (m *Manager) Context() context.Context {
	return m.ctx
}