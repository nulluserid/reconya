package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"reconya-ai/models"
	"sync"
	"time"
)

// DBManager manages database connections with proper pooling
// SQLite with WAL mode supports concurrent reads, so we remove the serialization bottleneck
type DBManager struct {
	db       *sql.DB
	mutex    sync.RWMutex // Only for critical sections that need coordination
	closed   bool
}

// NewDBManager creates a new database manager with connection pooling
func NewDBManager(db *sql.DB) *DBManager {
	m := &DBManager{
		db: db,
	}

	log.Println("Database manager initialized with connection pooling")
	return m
}

// GetDB returns the database connection for direct use
func (m *DBManager) GetDB() *sql.DB {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if m.closed {
		return nil
	}
	return m.db
}

// ExecuteWithRetry executes a database operation with retry logic for SQLITE_BUSY errors
func (m *DBManager) ExecuteWithRetry(operation func(*sql.DB) error) error {
	db := m.GetDB()
	if db == nil {
		return fmt.Errorf("database connection is closed")
	}

	// Retry logic for SQLITE_BUSY errors
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 10ms, 100ms, 1s
			time.Sleep(time.Duration(10*(1<<uint(attempt-1))) * time.Millisecond)
		}

		err := operation(db)
		if err == nil {
			return nil
		}

		lastErr = err
		// Check if it's a busy error that we should retry
		if !isBusyError(err) {
			break
		}
	}

	return lastErr
}

// ExecuteWithRetryAndResult executes a database operation with retry logic and returns a result
func (m *DBManager) ExecuteWithRetryAndResult(operation func(*sql.DB) (interface{}, error)) (interface{}, error) {
	db := m.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection is closed")
	}

	// Retry logic for SQLITE_BUSY errors
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 10ms, 100ms, 1s
			time.Sleep(time.Duration(10*(1<<uint(attempt-1))) * time.Millisecond)
		}

		result, err := operation(db)
		if err == nil {
			return result, nil
		}

		lastErr = err
		// Check if it's a busy error that we should retry
		if !isBusyError(err) {
			break
		}
	}

	return nil, lastErr
}

// isBusyError checks if an error is a SQLite busy error that should be retried
func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	errorStr := err.Error()
	return errorStr == "database is locked" || errorStr == "database is busy"
}

// Close closes the database manager
func (m *DBManager) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if m.closed {
		return nil
	}
	
	m.closed = true
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// Helper methods for common repository operations (now using direct DB access)

// CreateOrUpdateDevice creates or updates a device using direct DB access
func (m *DBManager) CreateOrUpdateDevice(repo DeviceRepository, ctx context.Context, device *models.Device) (*models.Device, error) {
	result, err := m.ExecuteWithRetryAndResult(func(db *sql.DB) (interface{}, error) {
		return repo.CreateOrUpdate(ctx, device)
	})
	if err != nil {
		return nil, err
	}
	return result.(*models.Device), nil
}

// UpdateDeviceStatuses updates device statuses using direct DB access
func (m *DBManager) UpdateDeviceStatuses(repo DeviceRepository, ctx context.Context, timeout time.Duration) error {
	return m.ExecuteWithRetry(func(db *sql.DB) error {
		return repo.UpdateDeviceStatuses(ctx, timeout)
	})
}

// CreateEventLog creates an event log using direct DB access
func (m *DBManager) CreateEventLog(repo EventLogRepository, ctx context.Context, eventLog *models.EventLog) error {
	return m.ExecuteWithRetry(func(db *sql.DB) error {
		return repo.Create(ctx, eventLog)
	})
}

// CreateOrUpdateNetwork creates or updates a network using direct DB access
func (m *DBManager) CreateOrUpdateNetwork(repo NetworkRepository, ctx context.Context, network *models.Network) (*models.Network, error) {
	result, err := m.ExecuteWithRetryAndResult(func(db *sql.DB) (interface{}, error) {
		return repo.CreateOrUpdate(ctx, network)
	})
	if err != nil {
		return nil, err
	}
	return result.(*models.Network), nil
}

