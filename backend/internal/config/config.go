package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"reconya-ai/internal/validation"
)

type DatabaseType string

const (
	SQLite DatabaseType = "sqlite"
)

type Config struct {
	NetworkCIDR   string   // Raw network range string from environment
	NetworkRanges []string // Parsed list of individual network CIDRs
	DatabaseType  DatabaseType
	// SQLite config
	SQLitePath   string
	// Common configs
	DatabaseName string
	// Port scanning config
	ScanAllPorts bool // Whether to scan all 65535 ports instead of just top 100
	// SNMP scanning config
	SNMPCommunityStrings string // Comma-separated list of SNMP community strings
}

func LoadConfig() (*Config, error) {
	// Try to load .env file but don't fail if it doesn't exist
	// This allows using environment variables directly in Docker
	_ = godotenv.Load()

	networkCIDR := os.Getenv("NETWORK_RANGE")
	if networkCIDR == "" {
		return nil, fmt.Errorf("NETWORK_RANGE environment variable is not set")
	}

	// Validate network CIDR format and security
	validator := validation.NewNetworkValidator()
	if err := validator.ValidateNetworkRange(networkCIDR); err != nil {
		return nil, fmt.Errorf("invalid NETWORK_RANGE: %w", err)
	}

	// Parse and sanitize individual network ranges
	networkRanges, err := validator.SanitizeNetworkRanges(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NETWORK_RANGE: %w", err)
	}

	databaseName := os.Getenv("DATABASE_NAME")
	if databaseName == "" {
		return nil, fmt.Errorf("DATABASE_NAME environment variable is not set")
	}

	// Set database type to SQLite
	dbType := string(SQLite)

	// Parse SCAN_ALL_PORTS environment variable (defaults to false for top 100 ports)
	scanAllPorts := false
	if scanAllPortsEnv := os.Getenv("SCAN_ALL_PORTS"); scanAllPortsEnv == "true" || scanAllPortsEnv == "1" {
		scanAllPorts = true
	}

	// Parse SNMP community strings (optional)
	snmpCommunityStrings := os.Getenv("SNMP_COMMUNITY_STRINGS")

	config := &Config{
		NetworkCIDR:          networkCIDR,
		NetworkRanges:        networkRanges,
		DatabaseType:         DatabaseType(dbType),
		DatabaseName:         databaseName,
		ScanAllPorts:         scanAllPorts,
		SNMPCommunityStrings: snmpCommunityStrings,
	}

	// Configure SQLite database
	sqlitePath := os.Getenv("SQLITE_PATH")
	if sqlitePath == "" {
		// Default to a data directory in the current directory
		sqlitePath = filepath.Join("data", fmt.Sprintf("%s.db", databaseName))
	}
	config.SQLitePath = sqlitePath

	return config, nil
}
