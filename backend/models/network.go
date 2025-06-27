package models

import "time"

// Network represents a network entity that can be scanned
type Network struct {
	ID           string    `bson:"_id,omitempty" json:"id"`
	CIDR         string    `bson:"cidr" json:"cidr"`
	Name         string    `bson:"name" json:"name"`                 // User-friendly name
	Description  string    `bson:"description" json:"description"`   // Optional description
	Enabled      bool      `bson:"enabled" json:"enabled"`           // Whether to include in scans
	ScanAllPorts bool      `bson:"scan_all_ports" json:"scan_all_ports"` // Whether to scan all 65535 ports vs top 100
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}
