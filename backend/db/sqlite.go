package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ConnectToSQLite initializes and returns a SQLite connection
func ConnectToSQLite(dbPath string) (*sql.DB, error) {
	// Ensure the directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for SQLite: %w", err)
	}
	// Open connection with extended query string parameters for better concurrency
	dsn := fmt.Sprintf("%s?_journal=WAL&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Set connection pool size - important for handling concurrent requests
	db.SetMaxOpenConns(25)                  // Allow up to 25 concurrent connections (increased for better throughput)
	db.SetMaxIdleConns(15)                  // Keep up to 15 idle connections (increased for better performance)
	db.SetConnMaxLifetime(30 * time.Minute) // Recycle connections after 30 minutes
	db.SetConnMaxIdleTime(5 * time.Minute)  // Close idle connections after 5 minutes

	// Set PRAGMA statements for better concurrent access
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=30000", // Increased to 30 seconds
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000", // Increased cache size
		"PRAGMA foreign_keys=ON",
		"PRAGMA temp_store=MEMORY",   // Use memory for temp storage
		"PRAGMA mmap_size=268435456", // Use memory mapping (256MB)
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return nil, fmt.Errorf("failed to set %s: %w", pragma, err)
		}
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	log.Println("Connected to SQLite database with optimized settings for concurrency")
	return db, nil
}

// InitializeSchema creates all the necessary tables if they don't exist
func InitializeSchema(db *sql.DB) error {
	// Create networks table
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS networks (
		id TEXT PRIMARY KEY,
		cidr TEXT NOT NULL UNIQUE,
		name TEXT,
		description TEXT,
		enabled BOOLEAN DEFAULT 1,
		scan_all_ports BOOLEAN DEFAULT 0,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create networks table: %w", err)
	}

	// Add new columns to existing networks table if they don't exist
	alterCommands := []string{
		"ALTER TABLE networks ADD COLUMN name TEXT",
		"ALTER TABLE networks ADD COLUMN description TEXT", 
		"ALTER TABLE networks ADD COLUMN enabled BOOLEAN DEFAULT 1",
		"ALTER TABLE networks ADD COLUMN scan_all_ports BOOLEAN DEFAULT 0",
		"ALTER TABLE networks ADD COLUMN created_at TIMESTAMP",
		"ALTER TABLE networks ADD COLUMN updated_at TIMESTAMP",
	}
	
	for _, cmd := range alterCommands {
		_, err = db.Exec(cmd)
		if err != nil {
			// Column might already exist, log but continue
			log.Printf("Note: %s - column might already exist: %v", cmd, err)
		}
	}

	// Create devices table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		ipv4 TEXT NOT NULL,
		mac TEXT,
		vendor TEXT,
		status TEXT NOT NULL,
		network_id TEXT,
		hostname TEXT,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_seen_online_at TIMESTAMP,
		port_scan_started_at TIMESTAMP,
		port_scan_ended_at TIMESTAMP,
		FOREIGN KEY (network_id) REFERENCES networks(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create devices table: %w", err)
	}

	// Create unique index on ipv4 to prevent duplicate IP addresses
	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ipv4 ON devices(ipv4)`)
	if err != nil {
		return fmt.Errorf("failed to create unique index on devices.ipv4: %w", err)
	}

	// Create index on MAC address for faster lookups
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)`)
	if err != nil {
		return fmt.Errorf("failed to create index on devices.mac: %w", err)
	}

	// Create index on network_id for faster network queries
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_network_id ON devices(network_id)`)
	if err != nil {
		return fmt.Errorf("failed to create index on devices.network_id: %w", err)
	}

	// Create ports table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT NOT NULL,
		number TEXT NOT NULL,
		protocol TEXT NOT NULL,
		state TEXT NOT NULL,
		service TEXT NOT NULL,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create ports table: %w", err)
	}

	// Create event_logs table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS event_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		description TEXT NOT NULL,
		device_id TEXT,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create event_logs table: %w", err)
	}

	// Create system_status table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS system_status (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		network_id TEXT,
		public_ip TEXT,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (network_id) REFERENCES networks(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create system_status table: %w", err)
	}

	// Create local_device table for system_status
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS local_devices (
		system_status_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		ipv4 TEXT NOT NULL,
		mac TEXT,
		vendor TEXT,
		status TEXT NOT NULL,
		hostname TEXT,
		PRIMARY KEY (system_status_id),
		FOREIGN KEY (system_status_id) REFERENCES system_status(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create local_devices table: %w", err)
	}

	// Add web_scan_ended_at column if it doesn't exist (for backward compatibility)
	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN web_scan_ended_at TIMESTAMP`)
	if err != nil {
		// Column might already exist, so we ignore the error
		log.Printf("Note: web_scan_ended_at column might already exist: %v", err)
	}

	// Add device fingerprinting columns if they don't exist (for backward compatibility)
	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN device_type TEXT`)
	if err != nil {
		log.Printf("Note: device_type column might already exist: %v", err)
	}

	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN os_name TEXT`)
	if err != nil {
		log.Printf("Note: os_name column might already exist: %v", err)
	}

	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN os_version TEXT`)
	if err != nil {
		log.Printf("Note: os_version column might already exist: %v", err)
	}

	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN os_family TEXT`)
	if err != nil {
		log.Printf("Note: os_family column might already exist: %v", err)
	}

	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN os_confidence INTEGER`)
	if err != nil {
		log.Printf("Note: os_confidence column might already exist: %v", err)
	}

	// Add comment column if it doesn't exist (for device editing)
	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN comment TEXT`)
	if err != nil {
		log.Printf("Note: comment column might already exist: %v", err)
	}

	// Create web_services table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS web_services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id TEXT NOT NULL,
		url TEXT NOT NULL,
		title TEXT,
		server TEXT,
		status_code INTEGER NOT NULL,
		content_type TEXT,
		size INTEGER,
		screenshot TEXT,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		scanned_at TIMESTAMP NOT NULL,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create web_services table: %w", err)
	}

	// Create index on device_id for web_services
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_web_services_device_id ON web_services(device_id)`)
	if err != nil {
		return fmt.Errorf("failed to create index on web_services.device_id: %w", err)
	}

	// Create snmp_data table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS snmp_data (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL,
		system_name TEXT,
		system_descr TEXT,
		system_object_id TEXT,
		system_contact TEXT,
		system_location TEXT,
		system_uptime INTEGER,
		interface_count INTEGER,
		interfaces TEXT, -- JSON array of interface data
		community TEXT,
		version TEXT,
		custom_oids TEXT, -- JSON object of custom OID values
		last_scanned TIMESTAMP NOT NULL,
		scan_duration INTEGER, -- Duration in nanoseconds
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create snmp_data table: %w", err)
	}

	// Create index on device_id for SNMP data
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_snmp_data_device_id ON snmp_data(device_id)`)
	if err != nil {
		return fmt.Errorf("failed to create index on snmp_data.device_id: %w", err)
	}

	// Create certificates table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		subject_common_name TEXT,
		subject_organization TEXT,
		issuer_common_name TEXT,
		issuer_organization TEXT,
		serial_number TEXT,
		thumbprint TEXT NOT NULL,
		thumbprint_sha256 TEXT NOT NULL,
		version INTEGER,
		signature_algorithm TEXT,
		public_key_algorithm TEXT,
		key_size INTEGER,
		not_before TIMESTAMP NOT NULL,
		not_after TIMESTAMP NOT NULL,
		dns_names TEXT, -- JSON array
		ip_addresses TEXT, -- JSON array
		is_ca BOOLEAN DEFAULT 0,
		is_self_signed BOOLEAN DEFAULT 0,
		is_valid BOOLEAN DEFAULT 1,
		is_expired BOOLEAN DEFAULT 0,
		is_expiring_soon BOOLEAN DEFAULT 0,
		validation_errors TEXT, -- JSON array
		certificate_chain TEXT, -- JSON array
		tls_version TEXT,
		cipher_suite TEXT,
		security_level TEXT,
		last_scanned TIMESTAMP NOT NULL,
		first_seen TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create certificates table: %w", err)
	}

	// Create indexes for certificates
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_certificates_device_id ON certificates(device_id)`)
	if err != nil {
		return fmt.Errorf("failed to create index on certificates.device_id: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_certificates_host_port ON certificates(host, port)`)
	if err != nil {
		return fmt.Errorf("failed to create index on certificates.host_port: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_certificates_thumbprint ON certificates(thumbprint)`)
	if err != nil {
		return fmt.Errorf("failed to create index on certificates.thumbprint: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_certificates_expiration ON certificates(not_after)`)
	if err != nil {
		return fmt.Errorf("failed to create index on certificates.not_after: %w", err)
	}

	// Create network_topology table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS network_topology (
		id TEXT PRIMARY KEY,
		local_subnet TEXT NOT NULL,
		discovered_routes TEXT, -- JSON array
		gateways TEXT, -- JSON array
		hop_counts TEXT, -- JSON object
		last_discovered TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create network_topology table: %w", err)
	}

	// Create gateways table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS gateways (
		id TEXT PRIMARY KEY,
		ip_address TEXT NOT NULL UNIQUE,
		mac_address TEXT,
		hostname TEXT,
		vendor TEXT,
		is_default BOOLEAN DEFAULT 0,
		subnets TEXT, -- JSON array
		hop_distance INTEGER,
		response_time REAL,
		last_seen TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create gateways table: %w", err)
	}

	// Create traceroute_results table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS traceroute_results (
		id TEXT PRIMARY KEY,
		source TEXT NOT NULL,
		destination TEXT NOT NULL,
		hops TEXT NOT NULL, -- JSON array
		total_hops INTEGER,
		success BOOLEAN,
		duration INTEGER, -- Duration in nanoseconds
		timestamp TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create traceroute_results table: %w", err)
	}

	// Create subnet_reachability table
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS subnet_reachability (
		id TEXT PRIMARY KEY,
		subnet_cidr TEXT NOT NULL UNIQUE,
		is_reachable BOOLEAN,
		hop_count INTEGER,
		preferred_gateway TEXT,
		alternate_gateways TEXT, -- JSON array
		latency_ms REAL,
		device_count INTEGER DEFAULT 0,
		active_devices INTEGER DEFAULT 0,
		last_scanned TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create subnet_reachability table: %w", err)
	}

	// Create indexes for topology tables
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateways_ip ON gateways(ip_address)`)
	if err != nil {
		return fmt.Errorf("failed to create index on gateways.ip_address: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_gateways_default ON gateways(is_default)`)
	if err != nil {
		return fmt.Errorf("failed to create index on gateways.is_default: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_traceroute_destination ON traceroute_results(destination)`)
	if err != nil {
		return fmt.Errorf("failed to create index on traceroute_results.destination: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_subnet_reachability_cidr ON subnet_reachability(subnet_cidr)`)
	if err != nil {
		return fmt.Errorf("failed to create index on subnet_reachability.subnet_cidr: %w", err)
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_subnet_reachability_reachable ON subnet_reachability(is_reachable)`)
	if err != nil {
		return fmt.Errorf("failed to create index on subnet_reachability.is_reachable: %w", err)
	}

	log.Println("Database schema initialized successfully")
	return nil
}

// ResetPortScanCooldowns clears all port scan timestamps to allow immediate re-scanning (for development)
func ResetPortScanCooldowns(db *sql.DB) error {
	// Clear port scan timestamps
	_, err := db.Exec(`UPDATE devices SET port_scan_ended_at = NULL, port_scan_started_at = NULL`)
	if err != nil {
		return fmt.Errorf("failed to reset port scan cooldowns: %w", err)
	}

	// Clear web scan timestamps if the column exists
	_, err = db.Exec(`UPDATE devices SET web_scan_ended_at = NULL`)
	if err != nil {
		// Column might not exist yet, so we ignore this error
		log.Printf("Note: web_scan_ended_at column might not exist yet: %v", err)
	}

	log.Println("Port scan cooldowns reset - all devices are now eligible for scanning")
	return nil
}
