package db

import (
	"context"
	"database/sql"
	"errors"
	"reconya-ai/models"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrAlreadyExists = errors.New("record already exists")
)

// Repository defines a common interface for all repositories
type Repository interface {
	Close() error
}

// NetworkRepository defines the interface for network operations
type NetworkRepository interface {
	Repository
	FindByID(ctx context.Context, id string) (*models.Network, error)
	FindByCIDR(ctx context.Context, cidr string) (*models.Network, error)
	FindAll(ctx context.Context) ([]*models.Network, error)
	FindByEnabled(ctx context.Context, enabled bool) ([]*models.Network, error)
	CreateOrUpdate(ctx context.Context, network *models.Network) (*models.Network, error)
	Delete(ctx context.Context, id string) error
}

// DeviceRepository defines the interface for device operations
type DeviceRepository interface {
	Repository
	FindByID(ctx context.Context, id string) (*models.Device, error)
	FindByIP(ctx context.Context, ip string) (*models.Device, error)
	FindAll(ctx context.Context) ([]*models.Device, error)
	CreateOrUpdate(ctx context.Context, device *models.Device) (*models.Device, error)
	UpdateDeviceStatuses(ctx context.Context, timeout time.Duration) error
	DeleteByID(ctx context.Context, id string) error
}

// EventLogRepository defines the interface for event log operations
type EventLogRepository interface {
	Repository
	Create(ctx context.Context, eventLog *models.EventLog) error
	FindLatest(ctx context.Context, limit int) ([]*models.EventLog, error)
	FindAllByDeviceID(ctx context.Context, deviceID string) ([]*models.EventLog, error)
}

// SystemStatusRepository defines the interface for system status operations
type SystemStatusRepository interface {
	Repository
	Create(ctx context.Context, status *models.SystemStatus) error
	FindLatest(ctx context.Context) (*models.SystemStatus, error)
}

// SNMPDataRepository defines the interface for SNMP data operations
type SNMPDataRepository interface {
	Repository
	FindByDeviceID(ctx context.Context, deviceID string) (*models.SNMPData, error)
	CreateOrUpdate(ctx context.Context, snmpData *models.SNMPData) (*models.SNMPData, error)
	Delete(ctx context.Context, id string) error
	FindAll(ctx context.Context) ([]*models.SNMPData, error)
}

// CertificateRepository defines the interface for certificate operations
type CertificateRepository interface {
	Repository
	FindByDeviceID(ctx context.Context, deviceID string) ([]*models.Certificate, error)
	FindByThumbprint(ctx context.Context, thumbprint string) (*models.Certificate, error)
	FindExpiring(ctx context.Context, days int) ([]*models.Certificate, error)
	FindExpired(ctx context.Context) ([]*models.Certificate, error)
	CreateOrUpdate(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error)
	Delete(ctx context.Context, id string) error
	FindAll(ctx context.Context) ([]*models.Certificate, error)
	GetStats(ctx context.Context) (*models.CertificateStats, error)
}

// TopologyRepository defines the interface for network topology operations
type TopologyRepository interface {
	Repository
	FindLatest(ctx context.Context) (*models.NetworkTopology, error)
	CreateOrUpdate(ctx context.Context, topology *models.NetworkTopology) (*models.NetworkTopology, error)
	FindByLocalSubnet(ctx context.Context, subnet string) (*models.NetworkTopology, error)
	GetTopologyStats(ctx context.Context) (*models.TopologyStats, error)
}

// GatewayRepository defines the interface for gateway operations
type GatewayRepository interface {
	Repository
	FindByIP(ctx context.Context, ip string) (*models.Gateway, error)
	FindAll(ctx context.Context) ([]*models.Gateway, error)
	FindDefault(ctx context.Context) (*models.Gateway, error)
	CreateOrUpdate(ctx context.Context, gateway *models.Gateway) (*models.Gateway, error)
	Delete(ctx context.Context, id string) error
	UpdateLastSeen(ctx context.Context, ip string, timestamp time.Time) error
}

// RepositoryFactory creates repositories
type RepositoryFactory struct {
	SQLiteDB *sql.DB
	DBName   string
}

// NewRepositoryFactory creates a new repository factory
func NewRepositoryFactory(sqliteDB *sql.DB, dbName string) *RepositoryFactory {
	return &RepositoryFactory{
		SQLiteDB: sqliteDB,
		DBName:   dbName,
	}
}

// NewNetworkRepository creates a new network repository
func (f *RepositoryFactory) NewNetworkRepository() NetworkRepository {
	return NewSQLiteNetworkRepository(f.SQLiteDB)
}

// NewDeviceRepository creates a new device repository
func (f *RepositoryFactory) NewDeviceRepository() DeviceRepository {
	return NewSQLiteDeviceRepository(f.SQLiteDB)
}

// NewEventLogRepository creates a new event log repository
func (f *RepositoryFactory) NewEventLogRepository() EventLogRepository {
	return NewSQLiteEventLogRepository(f.SQLiteDB)
}

// NewSystemStatusRepository creates a new system status repository
func (f *RepositoryFactory) NewSystemStatusRepository() SystemStatusRepository {
	return NewSQLiteSystemStatusRepository(f.SQLiteDB)
}

// NewSNMPDataRepository creates a new SNMP data repository
func (f *RepositoryFactory) NewSNMPDataRepository() SNMPDataRepository {
	return NewSQLiteSNMPDataRepository(f.SQLiteDB)
}

// NewCertificateRepository creates a new certificate repository
func (f *RepositoryFactory) NewCertificateRepository() CertificateRepository {
	return NewSQLiteCertificateRepository(f.SQLiteDB)
}

// NewTopologyRepository creates a new topology repository
func (f *RepositoryFactory) NewTopologyRepository() TopologyRepository {
	return NewSQLiteTopologyRepository(f.SQLiteDB)
}

// NewGatewayRepository creates a new gateway repository
func (f *RepositoryFactory) NewGatewayRepository() GatewayRepository {
	return NewSQLiteGatewayRepository(f.SQLiteDB)
}

// GenerateID generates a unique ID for a record
func GenerateID() string {
	return uuid.New().String()
}

