package models

import "time"

// SNMPData represents SNMP-discovered device information
type SNMPData struct {
	ID              string            `bson:"_id,omitempty" json:"id"`
	DeviceID        string            `bson:"device_id" json:"device_id"`
	SystemName      string            `bson:"system_name,omitempty" json:"system_name,omitempty"`
	SystemDescr     string            `bson:"system_descr,omitempty" json:"system_descr,omitempty"`
	SystemObjectID  string            `bson:"system_object_id,omitempty" json:"system_object_id,omitempty"`
	SystemContact   string            `bson:"system_contact,omitempty" json:"system_contact,omitempty"`
	SystemLocation  string            `bson:"system_location,omitempty" json:"system_location,omitempty"`
	SystemUptime    *int64            `bson:"system_uptime,omitempty" json:"system_uptime,omitempty"`
	InterfaceCount  *int              `bson:"interface_count,omitempty" json:"interface_count,omitempty"`
	Interfaces      []SNMPInterface   `bson:"interfaces,omitempty" json:"interfaces,omitempty"`
	Community       string            `bson:"community,omitempty" json:"community,omitempty"`
	Version         string            `bson:"version,omitempty" json:"version,omitempty"`
	CustomOIDs      map[string]string `bson:"custom_oids,omitempty" json:"custom_oids,omitempty"`
	LastScanned     time.Time         `bson:"last_scanned" json:"last_scanned"`
	ScanDuration    time.Duration     `bson:"scan_duration,omitempty" json:"scan_duration,omitempty"`
	CreatedAt       time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time         `bson:"updated_at" json:"updated_at"`
}

// SNMPInterface represents a network interface discovered via SNMP
type SNMPInterface struct {
	Index       int    `bson:"index" json:"index"`
	Name        string `bson:"name,omitempty" json:"name,omitempty"`
	Type        string `bson:"type,omitempty" json:"type,omitempty"`
	MTU         *int   `bson:"mtu,omitempty" json:"mtu,omitempty"`
	Speed       *int64 `bson:"speed,omitempty" json:"speed,omitempty"`
	PhysAddress string `bson:"phys_address,omitempty" json:"phys_address,omitempty"`
	AdminStatus string `bson:"admin_status,omitempty" json:"admin_status,omitempty"`
	OperStatus  string `bson:"oper_status,omitempty" json:"oper_status,omitempty"`
	Description string `bson:"description,omitempty" json:"description,omitempty"`
	InOctets    *int64 `bson:"in_octets,omitempty" json:"in_octets,omitempty"`
	OutOctets   *int64 `bson:"out_octets,omitempty" json:"out_octets,omitempty"`
}

// SNMPCommunityString represents an SNMP community configuration
type SNMPCommunityString struct {
	Community string `json:"community"`
	Version   string `json:"version"` // "1", "2c", or "3"
}

// Common SNMP OIDs for system information
var (
	SystemNameOID      = "1.3.6.1.2.1.1.5.0"
	SystemDescrOID     = "1.3.6.1.2.1.1.1.0"
	SystemObjectIDOID  = "1.3.6.1.2.1.1.2.0"
	SystemContactOID   = "1.3.6.1.2.1.1.4.0"
	SystemLocationOID  = "1.3.6.1.2.1.1.6.0"
	SystemUptimeOID    = "1.3.6.1.2.1.1.3.0"
	IfNumberOID        = "1.3.6.1.2.1.2.1.0"
	IfTableOID         = "1.3.6.1.2.1.2.2.1"
	IfIndexOID         = "1.3.6.1.2.1.2.2.1.1"
	IfDescrOID         = "1.3.6.1.2.1.2.2.1.2"
	IfTypeOID          = "1.3.6.1.2.1.2.2.1.3"
	IfMtuOID           = "1.3.6.1.2.1.2.2.1.4"
	IfSpeedOID         = "1.3.6.1.2.1.2.2.1.5"
	IfPhysAddressOID   = "1.3.6.1.2.1.2.2.1.6"
	IfAdminStatusOID   = "1.3.6.1.2.1.2.2.1.7"
	IfOperStatusOID    = "1.3.6.1.2.1.2.2.1.8"
	IfInOctetsOID      = "1.3.6.1.2.1.2.2.1.10"
	IfOutOctetsOID     = "1.3.6.1.2.1.2.2.1.16"
)

// GetDefaultCommunityStrings returns common SNMP community strings to try
func GetDefaultCommunityStrings() []SNMPCommunityString {
	return []SNMPCommunityString{
		{Community: "public", Version: "2c"},
		{Community: "private", Version: "2c"},
		{Community: "admin", Version: "2c"},
		{Community: "snmp", Version: "2c"},
		{Community: "community", Version: "2c"},
		{Community: "public", Version: "1"},
		{Community: "private", Version: "1"},
	}
}