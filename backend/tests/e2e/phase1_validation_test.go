package e2e

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"reconya-ai/db"
	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/lifecycle"
	"reconya-ai/internal/network"
	"reconya-ai/internal/tls"
	"reconya-ai/internal/validation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPhase1_SecurityFoundations validates that Phase 1 security improvements work correctly
func TestPhase1_SecurityFoundations(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping Phase 1 validation in short mode")
	}

	t.Run("InputValidation", testInputValidation)
	t.Run("TLSCertificateHandling", testTLSCertificateHandling)
	t.Run("DatabaseConnectionPooling", testDatabaseConnectionPooling)
	t.Run("ResourceManagement", testResourceManagement)
}

func testInputValidation(t *testing.T) {
	t.Log("Testing input validation security...")
	
	validator := validation.NewNetworkValidator()
	
	// Test network range validation
	validNetwork := "192.168.1.0/24"
	err := validator.ValidateNetworkRange(validNetwork)
	assert.NoError(t, err, "Valid network should pass validation")
	
	// Test command injection prevention
	maliciousNetwork := "192.168.1.0/24; rm -rf /"
	err = validator.ValidateNetworkRange(maliciousNetwork)
	assert.Error(t, err, "Malicious network should be rejected")
	
	// Test command argument sanitization
	validArgs := []string{"nmap", "-sn", "192.168.1.0/24"}
	err = validator.SanitizeCommandArgs(validArgs)
	assert.NoError(t, err, "Valid command args should pass")
	
	maliciousArgs := []string{"nmap", "-sn", "192.168.1.0/24; rm -rf /"}
	err = validator.SanitizeCommandArgs(maliciousArgs)
	assert.Error(t, err, "Malicious command args should be rejected")
	
	t.Log("✓ Input validation working correctly")
}

func testTLSCertificateHandling(t *testing.T) {
	t.Log("Testing TLS certificate validation...")
	
	validator := tls.NewCertificateValidator(10 * time.Second)
	
	// Test with a known good certificate
	result := validator.ValidateAndExtractCertificate("google.com", 443)
	if result != nil {
		assert.True(t, result.IsValid || len(result.ValidationErrors) > 0, "Should get validation result")
		assert.NotEmpty(t, result.CertificateChain, "Should extract certificate chain")
		
		if len(result.CertificateChain) > 0 {
			cert := result.CertificateChain[0]
			assert.NotEmpty(t, cert.Subject, "Should extract certificate subject")
			assert.NotEmpty(t, cert.Thumbprint, "Should calculate certificate thumbprint")
		}
		
		t.Log("✓ TLS certificate validation working correctly")
	} else {
		t.Skip("Unable to connect to test server - skipping TLS validation test")
	}
}

func testDatabaseConnectionPooling(t *testing.T) {
	t.Log("Testing database connection pooling...")
	
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	// Connect with our optimized settings
	testDB, err := db.ConnectToSQLite(dbPath)
	require.NoError(t, err)
	defer testDB.Close()
	
	// Initialize schema
	err = db.InitializeSchema(testDB)
	require.NoError(t, err)
	
	// Create database manager
	dbManager := db.NewDBManager(testDB)
	
	// Test concurrent operations
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			err := dbManager.ExecuteWithRetry(func(db *sql.DB) error {
				_, err := db.Exec("SELECT 1")
				return err
			})
			assert.NoError(t, err, "Concurrent database operation should succeed")
		}(i)
	}
	
	// Wait for all operations to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	t.Log("✓ Database connection pooling working correctly")
}

func testResourceManagement(t *testing.T) {
	t.Log("Testing resource management and lifecycle...")
	
	// Create lifecycle manager
	manager := lifecycle.NewManager()
	
	// Create mock services that respond to shutdown
	service1 := &mockLifecycleService{name: "test-service-1"}
	service2 := &mockLifecycleService{name: "test-service-2"}
	
	manager.Register(service1)
	manager.Register(service2)
	
	// Start services
	err := manager.StartAll()
	assert.NoError(t, err, "Should start all services")
	
	// Give services time to start
	time.Sleep(100 * time.Millisecond)
	
	// Verify services are running
	assert.True(t, service1.isStarted, "Service 1 should be started")
	assert.True(t, service2.isStarted, "Service 2 should be started")
	
	// Shutdown services
	err = manager.Shutdown(5 * time.Second)
	assert.NoError(t, err, "Should shutdown gracefully")
	
	// Verify services are stopped
	assert.True(t, service1.isStopped, "Service 1 should be stopped")
	assert.True(t, service2.isStopped, "Service 2 should be stopped")
	
	t.Log("✓ Resource management working correctly")
}

// mockLifecycleService implements the lifecycle.Service interface for testing
type mockLifecycleService struct {
	name      string
	isStarted bool
	isStopped bool
}

func (m *mockLifecycleService) Name() string {
	return m.name
}

func (m *mockLifecycleService) Start(ctx context.Context) error {
	m.isStarted = true
	// Block until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (m *mockLifecycleService) Stop() error {
	m.isStopped = true
	return nil
}

// TestPhase1_Integration validates that all Phase 1 components work together
func TestPhase1_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Phase 1 integration test in short mode")
	}
	
	t.Log("Running Phase 1 integration test...")
	
	// Create test configuration
	cfg := &config.Config{
		DatabaseType: config.SQLite,
		SQLitePath:   filepath.Join(t.TempDir(), "integration_test.db"),
		DatabaseName: "reconya_integration_test",
		NetworkCIDR:  "192.168.1.0/24",
	}
	
	// Setup database
	testDB, err := db.ConnectToSQLite(cfg.SQLitePath)
	require.NoError(t, err)
	defer testDB.Close()
	
	err = db.InitializeSchema(testDB)
	require.NoError(t, err)
	
	// Create repository factory and database manager
	repoFactory := db.NewRepositoryFactory(testDB, cfg.DatabaseName)
	dbManager := db.NewDBManager(testDB)
	
	// Create services
	networkRepo := repoFactory.NewNetworkRepository()
	deviceRepo := repoFactory.NewDeviceRepository()
	
	networkService := network.NewNetworkService(networkRepo, cfg, dbManager)
	deviceService := device.NewDeviceService(deviceRepo, networkService, cfg, dbManager, nil)
	
	// Test service creation and basic operations
	assert.NotNil(t, networkService, "Network service should be created")
	assert.NotNil(t, deviceService, "Device service should be created")
	
	// Test that services can perform basic operations without errors
	ctx := context.Background()
	devices, err := deviceService.FindAll(ctx)
	assert.NoError(t, err, "Should be able to query devices")
	assert.NotNil(t, devices, "Should return device list (even if empty)")
	
	t.Log("✓ Phase 1 integration test completed successfully")
}