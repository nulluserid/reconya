package models

import (
	"time"
)

// NetworkTopology represents the discovered network topology information
type NetworkTopology struct {
	ID               string          `bson:"_id,omitempty" json:"id"`
	LocalSubnet      string          `bson:"local_subnet" json:"local_subnet"`           // The subnet we're scanning from
	DiscoveredRoutes []NetworkRoute  `bson:"discovered_routes" json:"discovered_routes"` // Routes to other subnets
	Gateways         []Gateway       `bson:"gateways" json:"gateways"`                   // Discovered gateways
	HopCounts        map[string]int  `bson:"hop_counts" json:"hop_counts"`               // Subnet -> hop count
	LastDiscovered   time.Time       `bson:"last_discovered" json:"last_discovered"`
	CreatedAt        time.Time       `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time       `bson:"updated_at" json:"updated_at"`
}

// NetworkRoute represents a route to a subnet
type NetworkRoute struct {
	Destination    string    `bson:"destination" json:"destination"`         // Target subnet CIDR
	Gateway        string    `bson:"gateway" json:"gateway"`                 // Gateway IP address
	Interface      string    `bson:"interface,omitempty" json:"interface,omitempty"` // Network interface
	Metric         int       `bson:"metric" json:"metric"`                   // Route metric/cost
	HopCount       int       `bson:"hop_count" json:"hop_count"`             // Number of hops to reach
	IsReachable    bool      `bson:"is_reachable" json:"is_reachable"`       // Whether subnet is reachable
	LatencyMs      *float64  `bson:"latency_ms,omitempty" json:"latency_ms,omitempty"` // Average latency
	LastTested     time.Time `bson:"last_tested" json:"last_tested"`
	DiscoveryMethod string   `bson:"discovery_method" json:"discovery_method"` // "route_table", "traceroute", "ping"
}

// Gateway represents a network gateway/router
type Gateway struct {
	ID           string    `bson:"_id,omitempty" json:"id"`
	IPAddress    string    `bson:"ip_address" json:"ip_address"`
	MACAddress   string    `bson:"mac_address,omitempty" json:"mac_address,omitempty"`
	Hostname     string    `bson:"hostname,omitempty" json:"hostname,omitempty"`
	Vendor       string    `bson:"vendor,omitempty" json:"vendor,omitempty"`
	IsDefault    bool      `bson:"is_default" json:"is_default"`             // Default gateway
	Subnets      []string  `bson:"subnets" json:"subnets"`                   // Subnets this gateway routes to
	HopDistance  int       `bson:"hop_distance" json:"hop_distance"`         // Hops from local subnet
	ResponseTime *float64  `bson:"response_time,omitempty" json:"response_time,omitempty"` // Ping response time
	LastSeen     time.Time `bson:"last_seen" json:"last_seen"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

// TracerouteHop represents a single hop in a traceroute
type TracerouteHop struct {
	HopNumber    int       `bson:"hop_number" json:"hop_number"`
	IPAddress    string    `bson:"ip_address" json:"ip_address"`
	Hostname     string    `bson:"hostname,omitempty" json:"hostname,omitempty"`
	ResponseTime *float64  `bson:"response_time,omitempty" json:"response_time,omitempty"` // in milliseconds
	Timeout      bool      `bson:"timeout" json:"timeout"`
}

// TracerouteResult represents the result of a traceroute operation
type TracerouteResult struct {
	ID          string          `bson:"_id,omitempty" json:"id"`
	Source      string          `bson:"source" json:"source"`           // Source IP
	Destination string          `bson:"destination" json:"destination"` // Target IP or subnet
	Hops        []TracerouteHop `bson:"hops" json:"hops"`
	TotalHops   int             `bson:"total_hops" json:"total_hops"`
	Success     bool            `bson:"success" json:"success"`
	Duration    time.Duration   `bson:"duration" json:"duration"`
	Timestamp   time.Time       `bson:"timestamp" json:"timestamp"`
}

// SubnetReachability represents reachability information for a subnet
type SubnetReachability struct {
	ID                string    `bson:"_id,omitempty" json:"id"`
	SubnetCIDR        string    `bson:"subnet_cidr" json:"subnet_cidr"`
	IsReachable       bool      `bson:"is_reachable" json:"is_reachable"`
	HopCount          int       `bson:"hop_count" json:"hop_count"`
	PreferredGateway  string    `bson:"preferred_gateway,omitempty" json:"preferred_gateway,omitempty"`
	AlternateGateways []string  `bson:"alternate_gateways,omitempty" json:"alternate_gateways,omitempty"`
	LatencyMs         *float64  `bson:"latency_ms,omitempty" json:"latency_ms,omitempty"`
	DeviceCount       int       `bson:"device_count" json:"device_count"`         // Number of discovered devices
	ActiveDevices     int       `bson:"active_devices" json:"active_devices"`     // Number of currently active devices
	LastScanned       time.Time `bson:"last_scanned" json:"last_scanned"`
	CreatedAt         time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time `bson:"updated_at" json:"updated_at"`
}

// TopologyStats provides statistical information about network topology
type TopologyStats struct {
	TotalSubnets      int                    `json:"total_subnets"`
	ReachableSubnets  int                    `json:"reachable_subnets"`
	TotalGateways     int                    `json:"total_gateways"`
	AverageHopCount   float64                `json:"average_hop_count"`
	MaxHopCount       int                    `json:"max_hop_count"`
	SubnetDistribution map[string]int        `json:"subnet_distribution"` // hop count -> subnet count
	GatewayTypes      map[string]int         `json:"gateway_types"`       // vendor -> count
	LastDiscovery     time.Time              `json:"last_discovery"`
}

// DiscoveryMethod represents the method used to discover topology information
type DiscoveryMethod string

const (
	DiscoveryMethodRouteTable  DiscoveryMethod = "route_table"
	DiscoveryMethodTraceroute  DiscoveryMethod = "traceroute"
	DiscoveryMethodPing        DiscoveryMethod = "ping"
	DiscoveryMethodARP         DiscoveryMethod = "arp"
	DiscoveryMethodSNMP        DiscoveryMethod = "snmp"
)