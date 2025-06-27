package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"reconya-ai/db"
	"reconya-ai/internal/auth"
	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/eventlog"
	"reconya-ai/internal/lifecycle"
	"reconya-ai/internal/network"
	"reconya-ai/internal/nicidentifier"
	"reconya-ai/internal/oui"
	"reconya-ai/internal/pingsweep"
	"reconya-ai/internal/portscan"
	"reconya-ai/internal/systemstatus"
	"reconya-ai/middleware"
)


func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create repositories factory
	var repoFactory *db.RepositoryFactory
	var sqliteDB *sql.DB

	log.Println("Using SQLite database")
	sqliteDB, err = db.ConnectToSQLite(cfg.SQLitePath)
	if err != nil {
		log.Fatalf("Failed to connect to SQLite: %v", err)
	}
	
	// Initialize database schema
	if err := db.InitializeSchema(sqliteDB); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Reset port scan cooldowns for development
	log.Println("Resetting port scan cooldowns for development...")
	if err := db.ResetPortScanCooldowns(sqliteDB); err != nil {
		log.Printf("Warning: Failed to reset port scan cooldowns: %v", err)
	}

	repoFactory = db.NewRepositoryFactory(sqliteDB, cfg.DatabaseName)

	// Create repositories
	networkRepo := repoFactory.NewNetworkRepository()
	deviceRepo := repoFactory.NewDeviceRepository()
	eventLogRepo := repoFactory.NewEventLogRepository()
	systemStatusRepo := repoFactory.NewSystemStatusRepository()

	// Create database manager for concurrent access control with connection pooling
	dbManager := db.NewDBManager(sqliteDB)

	// Initialize OUI service for MAC address vendor lookup
	ouiDataPath := filepath.Join(filepath.Dir(cfg.SQLitePath), "oui")
	ouiService := oui.NewOUIService(ouiDataPath)
	log.Println("Initializing OUI service...")
	if err := ouiService.Initialize(); err != nil {
		log.Printf("Warning: Failed to initialize OUI service: %v", err)
		log.Println("Continuing without OUI service - vendor lookup will rely on Nmap only")
		ouiService = nil
	} else {
		stats := ouiService.GetStatistics()
		log.Printf("OUI service initialized successfully - %v entries loaded, last updated: %v", 
			stats["total_entries"], stats["last_updated"])
	}

	// Initialize services with repositories
	networkService := network.NewNetworkService(networkRepo, cfg, dbManager)
	deviceService := device.NewDeviceService(deviceRepo, networkService, cfg, dbManager, ouiService)
	eventLogService := eventlog.NewEventLogService(eventLogRepo, deviceService, dbManager)
	systemStatusService := systemstatus.NewSystemStatusService(systemStatusRepo)
	portScanService := portscan.NewPortScanService(deviceService, eventLogService, networkService, cfg)
	pingSweepService := pingsweep.NewPingSweepService(cfg, deviceService, eventLogService, networkService, portScanService)
	nicService := nicidentifier.NewNicIdentifierService(networkService, systemStatusService, eventLogService, deviceService)
	
	authHandlers := auth.NewAuthHandlers()
	middlewareHandlers := middleware.NewMiddleware(cfg)

	// Create lifecycle manager for proper resource cleanup
	lifecycleManager := lifecycle.NewManager()
	
	// Register background services
	pingSweepWrapper := lifecycle.NewPingSweepServiceWrapper(pingSweepService, 30*time.Second)
	deviceUpdaterService := lifecycle.NewDeviceUpdaterService(deviceService, 5*time.Second)
	
	lifecycleManager.Register(pingSweepWrapper)
	lifecycleManager.Register(deviceUpdaterService)
	
	// Start all background services
	if err := lifecycleManager.StartAll(); err != nil {
		log.Printf("Warning: Failed to start some background services: %v", err)
	}
	
	// Initial NIC identification
	nicService.Identify()

	mux := setupRouter(deviceService, eventLogService, systemStatusService, networkService, authHandlers, middlewareHandlers, cfg)
	loggedRouter := middleware.LoggingMiddleware(mux)

	server := &http.Server{
		Addr:    ":3008",
		Handler: loggedRouter,
	}

	go func() {
		log.Println("Server is starting on port 3008...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	waitForShutdown(server, lifecycleManager, sqliteDB)
}

func setupRouter(
	deviceService *device.DeviceService,
	eventLogService *eventlog.EventLogService,
	systemStatusService *systemstatus.SystemStatusService,
	networkService *network.NetworkService,
	authHandlers *auth.AuthHandlers,
	middlewareHandlers *middleware.Middleware,
	cfg *config.Config) http.Handler {
	deviceHandlers := device.NewDeviceHandlers(deviceService, cfg)
	eventLogHandlers := eventlog.NewEventLogHandlers(eventLogService)
	systemStatusHandlers := systemstatus.NewSystemStatusHandlers(systemStatusService)
	networkHandlers := network.NewNetworkHandlers(networkService)

	mux := http.NewServeMux()
	corsRouter := middleware.SetupCORS()(mux)

	mux.HandleFunc("/login", authHandlers.LoginHandler)
	mux.HandleFunc("/check-auth", authHandlers.CheckAuthHandler)
	
	// In development Docker environment, make these endpoints accessible without auth
	// In production, uncomment the middlewareHandlers.AuthMiddleware wrapper
	mux.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			deviceHandlers.GetAllDevices(w, r)
		case http.MethodPost:
			deviceHandlers.CreateDevice(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/devices/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			deviceHandlers.UpdateDevice(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/system-status/latest", systemStatusHandlers.GetLatestSystemStatus)
	mux.HandleFunc("/event-log", eventLogHandlers.FindLatest)
	mux.HandleFunc("/event-log/", eventLogHandlers.FindAllByDeviceId)
	
	// Legacy single network endpoint
	mux.HandleFunc("/network", networkHandlers.GetNetwork)
	
	// New network management endpoints
	mux.HandleFunc("/networks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			networkHandlers.GetAllNetworks(w, r)
		case http.MethodPost:
			networkHandlers.CreateNetwork(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			networkHandlers.UpdateNetwork(w, r)
		case http.MethodDelete:
			networkHandlers.DeleteNetwork(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/networks/scan-targets", networkHandlers.GetScanTargets)
	mux.HandleFunc("/networks/scan-config", networkHandlers.GetNetworkScanConfig)

	return corsRouter
}

func waitForShutdown(server *http.Server, lifecycleManager *lifecycle.Manager, db *sql.DB) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop

	log.Println("Received shutdown signal, initiating graceful shutdown...")

	// Create contexts for shutdown phases
	serverCtx, serverCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer serverCancel()

	// Phase 1: Shutdown HTTP server
	log.Println("Shutting down HTTP server...")
	if err := server.Shutdown(serverCtx); err != nil {
		log.Printf("HTTP server shutdown failed: %v", err)
	} else {
		log.Println("HTTP server stopped gracefully")
	}

	// Phase 2: Shutdown background services
	log.Println("Shutting down background services...")
	if err := lifecycleManager.Shutdown(15 * time.Second); err != nil {
		log.Printf("Background services shutdown failed: %v", err)
	} else {
		log.Println("Background services stopped gracefully")
	}

	// Phase 3: Close database connections
	log.Println("Closing database connections...")
	if err := db.Close(); err != nil {
		log.Printf("Database close failed: %v", err)
	} else {
		log.Println("Database connections closed")
	}

	log.Println("Graceful shutdown completed")
}
