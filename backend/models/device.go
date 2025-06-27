package models

import (
	"time"
)

type DeviceStatus string

const (
	DeviceStatusUnknown DeviceStatus = "unknown"
	DeviceStatusOnline  DeviceStatus = "online"
	DeviceStatusIdle    DeviceStatus = "idle"
	DeviceStatusOffline DeviceStatus = "offline"
)

type DeviceType string

const (
	DeviceTypeUnknown     DeviceType = "unknown"
	DeviceTypeRouter      DeviceType = "router"
	DeviceTypeSwitch      DeviceType = "switch"
	DeviceTypeNAS         DeviceType = "nas"
	DeviceTypePrinter     DeviceType = "printer"
	DeviceTypeCamera      DeviceType = "camera"
	DeviceTypeServer      DeviceType = "server"
	DeviceTypeWorkstation DeviceType = "workstation"
	DeviceTypeLaptop      DeviceType = "laptop"
	DeviceTypeMobile      DeviceType = "mobile"
	DeviceTypeIoT         DeviceType = "iot"
	DeviceTypeAccessPoint DeviceType = "access_point"
	DeviceTypeFirewall    DeviceType = "firewall"
	DeviceTypeVoIP        DeviceType = "voip"
)

type DeviceOS struct {
	Name       string  `bson:"name,omitempty" json:"name,omitempty"`
	Version    string  `bson:"version,omitempty" json:"version,omitempty"`
	Family     string  `bson:"family,omitempty" json:"family,omitempty"`
	Confidence int     `bson:"confidence,omitempty" json:"confidence,omitempty"`
}

type Device struct {
	ID                string        `bson:"_id,omitempty" json:"id"`
	Name              string        `bson:"name" json:"name"`
	Comment           *string       `bson:"comment,omitempty" json:"comment,omitempty"`
	IPv4              string        `bson:"ipv4" json:"ipv4"`
	MAC               *string       `bson:"mac,omitempty" json:"mac,omitempty"`
	Vendor            *string       `bson:"vendor,omitempty" json:"vendor,omitempty"`
	DeviceType        DeviceType    `bson:"device_type,omitempty" json:"device_type,omitempty"`
	OS                *DeviceOS     `bson:"os,omitempty" json:"os,omitempty"`
	Status            DeviceStatus  `bson:"status" json:"status"`
	NetworkID         string        `bson:"network_id,omitempty" json:"network_id,omitempty"`
	Ports             []Port        `bson:"ports,omitempty" json:"ports,omitempty"`
	Hostname          *string       `bson:"hostname,omitempty" json:"hostname,omitempty"`
	WebServices       []WebService  `bson:"web_services,omitempty" json:"web_services,omitempty"`
	SNMPData          *SNMPData     `bson:"snmp_data,omitempty" json:"snmp_data,omitempty"`
	Certificates      []Certificate `bson:"certificates,omitempty" json:"certificates,omitempty"`
	CreatedAt         time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time     `bson:"updated_at" json:"updated_at"`
	LastSeenOnlineAt  *time.Time    `bson:"last_seen_online_at,omitempty" json:"last_seen_online_at,omitempty"`
	PortScanStartedAt *time.Time    `bson:"port_scan_started_at,omitempty" json:"port_scan_started_at,omitempty"`
	PortScanEndedAt   *time.Time    `bson:"port_scan_ended_at,omitempty" json:"port_scan_ended_at,omitempty"`
	WebScanEndedAt    *time.Time    `bson:"web_scan_ended_at,omitempty" json:"web_scan_ended_at,omitempty"`
}
