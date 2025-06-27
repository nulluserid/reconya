package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockService implements the Service interface for testing
type MockService struct {
	name     string
	started  bool
	stopped  bool
	startErr error
	stopErr  error
	startDuration time.Duration
	stopDuration  time.Duration
	mu       sync.RWMutex
}

func NewMockService(name string) *MockService {
	return &MockService{
		name: name,
	}
}

func (m *MockService) Name() string {
	return m.name
}

func (m *MockService) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.startErr != nil {
		return m.startErr
	}
	
	m.started = true
	
	if m.startDuration > 0 {
		time.Sleep(m.startDuration)
	}
	
	// Simulate service running until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (m *MockService) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.stopErr != nil {
		return m.stopErr
	}
	
	m.stopped = true
	
	if m.stopDuration > 0 {
		time.Sleep(m.stopDuration)
	}
	
	return nil
}

func (m *MockService) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

func (m *MockService) IsStopped() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopped
}

func (m *MockService) SetStartError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startErr = err
}

func (m *MockService) SetStopError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopErr = err
}

func (m *MockService) SetStartDuration(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startDuration = d
}

func (m *MockService) SetStopDuration(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopDuration = d
}

func TestManager_NewManager(t *testing.T) {
	manager := NewManager()
	
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.ctx)
	assert.NotNil(t, manager.cancel)
	assert.NotNil(t, manager.services)
	assert.NotNil(t, manager.shutdown)
	assert.False(t, manager.terminated)
}

func TestManager_Register(t *testing.T) {
	manager := NewManager()
	service := NewMockService("test-service")
	
	manager.Register(service)
	
	assert.Len(t, manager.services, 1)
	assert.Equal(t, service, manager.services[0])
}

func TestManager_RegisterAfterTermination(t *testing.T) {
	manager := NewManager()
	manager.terminated = true
	
	service := NewMockService("test-service")
	manager.Register(service)
	
	// Service should not be registered after termination
	assert.Len(t, manager.services, 0)
}

func TestManager_StartAll(t *testing.T) {
	manager := NewManager()
	
	service1 := NewMockService("service-1")
	service2 := NewMockService("service-2")
	
	manager.Register(service1)
	manager.Register(service2)
	
	err := manager.StartAll()
	assert.NoError(t, err)
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	assert.True(t, service1.IsStarted())
	assert.True(t, service2.IsStarted())
	
	// Clean up
	manager.Shutdown(5 * time.Second)
}

func TestManager_StartAllWithError(t *testing.T) {
	manager := NewManager()
	
	service1 := NewMockService("service-1")
	service2 := NewMockService("service-2")
	service2.SetStartError(errors.New("start error"))
	
	manager.Register(service1)
	manager.Register(service2)
	
	err := manager.StartAll()
	assert.NoError(t, err) // StartAll continues even if individual services fail
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	assert.True(t, service1.IsStarted())
	assert.False(t, service2.IsStarted()) // Service 2 should fail to start
	
	// Clean up
	manager.Shutdown(5 * time.Second)
}

func TestManager_Shutdown(t *testing.T) {
	manager := NewManager()
	
	service1 := NewMockService("service-1")
	service2 := NewMockService("service-2")
	
	manager.Register(service1)
	manager.Register(service2)
	
	// Start services
	err := manager.StartAll()
	assert.NoError(t, err)
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	// Shutdown
	err = manager.Shutdown(5 * time.Second)
	assert.NoError(t, err)
	
	assert.True(t, service1.IsStopped())
	assert.True(t, service2.IsStopped())
	assert.True(t, manager.terminated)
}

func TestManager_ShutdownTimeout(t *testing.T) {
	manager := NewManager()
	
	service := NewMockService("slow-service")
	service.SetStopDuration(2 * time.Second) // Longer than timeout
	
	manager.Register(service)
	
	// Start service
	err := manager.StartAll()
	assert.NoError(t, err)
	
	// Give service time to start
	time.Sleep(100 * time.Millisecond)
	
	// Shutdown with short timeout
	start := time.Now()
	err = manager.Shutdown(500 * time.Millisecond)
	duration := time.Since(start)
	
	assert.Equal(t, context.DeadlineExceeded, err)
	assert.True(t, duration < time.Second) // Should timeout quickly
	assert.True(t, manager.terminated)
}

func TestManager_ShutdownAlreadyTerminated(t *testing.T) {
	manager := NewManager()
	manager.terminated = true
	
	err := manager.Shutdown(5 * time.Second)
	assert.NoError(t, err) // Should return immediately
}

func TestManager_Context(t *testing.T) {
	manager := NewManager()
	
	ctx := manager.Context()
	assert.NotNil(t, ctx)
	
	// Context should be cancelled after shutdown
	select {
	case <-ctx.Done():
		t.Fatal("Context should not be cancelled yet")
	default:
		// Expected
	}
	
	manager.Shutdown(5 * time.Second)
	
	select {
	case <-ctx.Done():
		// Expected after shutdown
	case <-time.After(time.Second):
		t.Fatal("Context should be cancelled after shutdown")
	}
}

func TestManager_Wait(t *testing.T) {
	manager := NewManager()
	
	// Start shutdown in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		manager.Shutdown(5 * time.Second)
	}()
	
	// Wait should block until shutdown completes
	start := time.Now()
	manager.Wait()
	duration := time.Since(start)
	
	assert.True(t, duration >= 100*time.Millisecond)
	assert.True(t, duration < time.Second)
}

func TestManager_ConcurrentOperations(t *testing.T) {
	manager := NewManager()
	
	// Register services concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			service := NewMockService(fmt.Sprintf("service-%d", id))
			manager.Register(service)
		}(i)
	}
	
	wg.Wait()
	
	assert.Len(t, manager.services, 10)
	
	// Start all services
	err := manager.StartAll()
	assert.NoError(t, err)
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	// Shutdown
	err = manager.Shutdown(5 * time.Second)
	assert.NoError(t, err)
}

func TestManager_ServicePanic(t *testing.T) {
	manager := NewManager()
	
	// Create a service that panics
	panicService := &MockService{name: "panic-service"}
	panicService.Start = func(ctx context.Context) error {
		panic("service panic")
	}
	
	normalService := NewMockService("normal-service")
	
	manager.Register(panicService)
	manager.Register(normalService)
	
	// Start services - should handle panic gracefully
	err := manager.StartAll()
	assert.NoError(t, err)
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	// Normal service should still work
	assert.True(t, normalService.IsStarted())
	
	// Clean up
	manager.Shutdown(5 * time.Second)
}