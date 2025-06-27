// Full solution in backend/db/sqlite_repositories.go
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reconya-ai/models"
	"strconv"
	"time"
)

// SQLiteNetworkRepository implements the NetworkRepository interface for SQLite
type SQLiteNetworkRepository struct {
	db *sql.DB
}

// NewSQLiteNetworkRepository creates a new SQLiteNetworkRepository
func NewSQLiteNetworkRepository(db *sql.DB) *SQLiteNetworkRepository {
	return &SQLiteNetworkRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteNetworkRepository) Close() error {
	return r.db.Close()
}

// FindByID finds a network by ID
func (r *SQLiteNetworkRepository) FindByID(ctx context.Context, id string) (*models.Network, error) {
	query := `SELECT id, cidr, COALESCE(name, ''), COALESCE(description, ''), COALESCE(enabled, 1), 
	          COALESCE(scan_all_ports, 0), COALESCE(created_at, ''), COALESCE(updated_at, '') FROM networks WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

	var network models.Network
	var createdAtStr, updatedAtStr string
	err := row.Scan(&network.ID, &network.CIDR, &network.Name, &network.Description, 
		&network.Enabled, &network.ScanAllPorts, &createdAtStr, &updatedAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error scanning network: %w", err)
	}

	// Parse timestamps if they exist
	if createdAtStr != "" {
		if parsed, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			network.CreatedAt = parsed
		}
	}
	if updatedAtStr != "" {
		if parsed, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			network.UpdatedAt = parsed
		}
	}

	return &network, nil
}

// FindByCIDR finds a network by CIDR
func (r *SQLiteNetworkRepository) FindByCIDR(ctx context.Context, cidr string) (*models.Network, error) {
	query := `SELECT id, cidr, COALESCE(name, ''), COALESCE(description, ''), COALESCE(enabled, 1), 
	          COALESCE(scan_all_ports, 0), COALESCE(created_at, ''), COALESCE(updated_at, '') FROM networks WHERE cidr = ?`
	row := r.db.QueryRowContext(ctx, query, cidr)

	var network models.Network
	var createdAtStr, updatedAtStr string
	err := row.Scan(&network.ID, &network.CIDR, &network.Name, &network.Description, 
		&network.Enabled, &network.ScanAllPorts, &createdAtStr, &updatedAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error scanning network: %w", err)
	}

	// Parse timestamps if they exist
	if createdAtStr != "" {
		if parsed, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			network.CreatedAt = parsed
		}
	}
	if updatedAtStr != "" {
		if parsed, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			network.UpdatedAt = parsed
		}
	}

	return &network, nil
}

// FindAll returns all networks
func (r *SQLiteNetworkRepository) FindAll(ctx context.Context) ([]*models.Network, error) {
	query := `SELECT id, cidr, COALESCE(name, ''), COALESCE(description, ''), COALESCE(enabled, 1), 
	          COALESCE(scan_all_ports, 0), COALESCE(created_at, ''), COALESCE(updated_at, '') FROM networks ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error querying networks: %w", err)
	}
	defer rows.Close()

	var networks []*models.Network
	for rows.Next() {
		var network models.Network
		var createdAtStr, updatedAtStr string
		err := rows.Scan(&network.ID, &network.CIDR, &network.Name, &network.Description,
			&network.Enabled, &network.ScanAllPorts, &createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("error scanning network: %w", err)
		}

		// Parse timestamps if they exist
		if createdAtStr != "" {
			if parsed, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
				network.CreatedAt = parsed
			}
		}
		if updatedAtStr != "" {
			if parsed, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
				network.UpdatedAt = parsed
			}
		}

		networks = append(networks, &network)
	}

	return networks, nil
}

// FindByEnabled returns networks filtered by enabled status
func (r *SQLiteNetworkRepository) FindByEnabled(ctx context.Context, enabled bool) ([]*models.Network, error) {
	query := `SELECT id, cidr, COALESCE(name, ''), COALESCE(description, ''), COALESCE(enabled, 1), 
	          COALESCE(scan_all_ports, 0), COALESCE(created_at, ''), COALESCE(updated_at, '') FROM networks WHERE enabled = ? ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, enabled)
	if err != nil {
		return nil, fmt.Errorf("error querying networks by enabled status: %w", err)
	}
	defer rows.Close()

	var networks []*models.Network
	for rows.Next() {
		var network models.Network
		var createdAtStr, updatedAtStr string
		err := rows.Scan(&network.ID, &network.CIDR, &network.Name, &network.Description,
			&network.Enabled, &network.ScanAllPorts, &createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("error scanning network: %w", err)
		}

		// Parse timestamps if they exist
		if createdAtStr != "" {
			if parsed, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
				network.CreatedAt = parsed
			}
		}
		if updatedAtStr != "" {
			if parsed, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
				network.UpdatedAt = parsed
			}
		}

		networks = append(networks, &network)
	}

	return networks, nil
}

// Delete removes a network by ID
func (r *SQLiteNetworkRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM networks WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("error deleting network: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// CreateOrUpdate creates or updates a network
func (r *SQLiteNetworkRepository) CreateOrUpdate(ctx context.Context, network *models.Network) (*models.Network, error) {
	if network.ID == "" {
		network.ID = GenerateID()
	}

	_, err := r.FindByID(ctx, network.ID)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	now := time.Now().Format(time.RFC3339)

	if err == ErrNotFound {
		// Set created timestamp if not set
		if network.CreatedAt.IsZero() {
			network.CreatedAt = time.Now()
		}
		network.UpdatedAt = time.Now()

		query := `INSERT INTO networks (id, cidr, name, description, enabled, scan_all_ports, created_at, updated_at) 
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := r.db.ExecContext(ctx, query, network.ID, network.CIDR, network.Name, 
			network.Description, network.Enabled, network.ScanAllPorts, network.CreatedAt.Format(time.RFC3339), now)
		if err != nil {
			return nil, fmt.Errorf("error inserting network: %w", err)
		}
	} else {
		network.UpdatedAt = time.Now()
		query := `UPDATE networks SET cidr = ?, name = ?, description = ?, enabled = ?, scan_all_ports = ?, updated_at = ? WHERE id = ?`
		_, err := r.db.ExecContext(ctx, query, network.CIDR, network.Name, 
			network.Description, network.Enabled, network.ScanAllPorts, now, network.ID)
		if err != nil {
			return nil, fmt.Errorf("error updating network: %w", err)
		}
	}

	return network, nil
}

// SQLiteDeviceRepository implements the DeviceRepository interface for SQLite
type SQLiteDeviceRepository struct {
	db *sql.DB
}

// NewSQLiteDeviceRepository creates a new SQLiteDeviceRepository
func NewSQLiteDeviceRepository(db *sql.DB) *SQLiteDeviceRepository {
	return &SQLiteDeviceRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteDeviceRepository) Close() error {
	return r.db.Close()
}

// FindByID finds a device by ID
func (r *SQLiteDeviceRepository) FindByID(ctx context.Context, id string) (*models.Device, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
	SELECT id, name, comment, ipv4, mac, vendor, device_type, os_name, os_version, os_family, os_confidence,
	       status, network_id, hostname, created_at, updated_at, last_seen_online_at, 
	       port_scan_started_at, port_scan_ended_at, web_scan_ended_at
	FROM devices WHERE id = ?`

	row := tx.QueryRowContext(ctx, query, id)

	var device models.Device
	var mac, vendor, hostname, comment sql.NullString
	var deviceType sql.NullString
	var osName, osVersion, osFamily sql.NullString
	var osConfidence sql.NullInt64
	var networkID sql.NullString
	var lastSeenOnlineAt, portScanStartedAt, portScanEndedAt, webScanEndedAt sql.NullTime

	err = row.Scan(
		&device.ID, &device.Name, &comment, &device.IPv4, &mac, &vendor, &deviceType,
		&osName, &osVersion, &osFamily, &osConfidence,
		&device.Status, &networkID, &hostname, &device.CreatedAt, &device.UpdatedAt,
		&lastSeenOnlineAt, &portScanStartedAt, &portScanEndedAt, &webScanEndedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error scanning device: %w", err)
	}

	// Set the network ID
	if networkID.Valid {
		device.NetworkID = networkID.String
	}
	
	if mac.Valid {
		device.MAC = &mac.String
	}
	if vendor.Valid {
		device.Vendor = &vendor.String
	}
	if comment.Valid {
		device.Comment = &comment.String
	}
	if deviceType.Valid {
		device.DeviceType = models.DeviceType(deviceType.String)
	}
	if hostname.Valid {
		device.Hostname = &hostname.String
	}
	if lastSeenOnlineAt.Valid {
		device.LastSeenOnlineAt = &lastSeenOnlineAt.Time
	}
	if portScanStartedAt.Valid {
		device.PortScanStartedAt = &portScanStartedAt.Time
	}
	if portScanEndedAt.Valid {
		device.PortScanEndedAt = &portScanEndedAt.Time
	}
	if webScanEndedAt.Valid {
		device.WebScanEndedAt = &webScanEndedAt.Time
	}
	
	// Set OS information
	if osName.Valid || osVersion.Valid || osFamily.Valid || osConfidence.Valid {
		device.OS = &models.DeviceOS{}
		if osName.Valid {
			device.OS.Name = osName.String
		}
		if osVersion.Valid {
			device.OS.Version = osVersion.String
		}
		if osFamily.Valid {
			device.OS.Family = osFamily.String
		}
		if osConfidence.Valid {
			device.OS.Confidence = int(osConfidence.Int64)
		}
	}

	portsQuery := `
	SELECT number, protocol, state, service
	FROM ports WHERE device_id = ?`

	portRows, err := tx.QueryContext(ctx, portsQuery, device.ID)
	if err != nil {
		return nil, fmt.Errorf("error querying device ports: %w", err)
	}
	defer portRows.Close()

	for portRows.Next() {
		var port models.Port
		if err := portRows.Scan(&port.Number, &port.Protocol, &port.State, &port.Service); err != nil {
			return nil, fmt.Errorf("error scanning port: %w", err)
		}
		device.Ports = append(device.Ports, port)
	}

	// Load web services
	webServicesQuery := `
	SELECT url, title, server, status_code, content_type, size, screenshot, port, protocol, scanned_at
	FROM web_services WHERE device_id = ?`

	webServiceRows, err := tx.QueryContext(ctx, webServicesQuery, device.ID)
	if err != nil {
		return nil, fmt.Errorf("error querying device web services: %w", err)
	}
	defer webServiceRows.Close()

	for webServiceRows.Next() {
		var ws models.WebService
		var title, server, contentType, screenshot sql.NullString
		var size sql.NullInt64
		if err := webServiceRows.Scan(&ws.URL, &title, &server, &ws.StatusCode, &contentType, &size, &screenshot, &ws.Port, &ws.Protocol, &ws.ScannedAt); err != nil {
			return nil, fmt.Errorf("error scanning web service: %w", err)
		}
		
		if title.Valid {
			ws.Title = title.String
		}
		if server.Valid {
			ws.Server = server.String
		}
		if contentType.Valid {
			ws.ContentType = contentType.String
		}
		if size.Valid {
			ws.Size = size.Int64
		}
		if screenshot.Valid {
			ws.Screenshot = screenshot.String
		}
		
		device.WebServices = append(device.WebServices, ws)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("error committing transaction: %w", err)
	}

	return &device, nil
}

// FindByIP finds a device by IP address
func (r *SQLiteDeviceRepository) FindByIP(ctx context.Context, ip string) (*models.Device, error) {
	query := `SELECT id FROM devices WHERE ipv4 = ?`
	row := r.db.QueryRowContext(ctx, query, ip)

	var id string
	err := row.Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error scanning device id: %w", err)
	}

	return r.FindByID(ctx, id)
}

// FindAll finds all devices
func (r *SQLiteDeviceRepository) FindAll(ctx context.Context) ([]*models.Device, error) {
	query := `SELECT id FROM devices ORDER BY updated_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error querying devices: %w", err)
	}
	defer rows.Close()

	var devices []*models.Device
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("error scanning device id: %w", err)
		}

		device, err := r.FindByID(ctx, id)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// CreateOrUpdate creates or updates a device
func (r *SQLiteDeviceRepository) CreateOrUpdate(ctx context.Context, device *models.Device) (*models.Device, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now()
	device.UpdatedAt = now

	// Convert strings to *string
	networkIDPtr := stringToPtr(device.NetworkID)

	// Check if a device with this IP address already exists
	var existingID string
	err = tx.QueryRowContext(ctx, "SELECT id FROM devices WHERE ipv4 = ?", device.IPv4).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("error checking if device with IP exists: %w", err)
	}

	deviceExists := err != sql.ErrNoRows

	if deviceExists {
		// Update existing device with the same IP address
		device.ID = existingID
		
		// Get the existing created_at timestamp and preserve device type/OS if not provided
		var createdAt time.Time
		var existingDeviceType sql.NullString
		var existingOsName, existingOsVersion, existingOsFamily sql.NullString
		var existingOsConfidence sql.NullInt64
		
		err = tx.QueryRowContext(ctx, 
			"SELECT created_at, device_type, os_name, os_version, os_family, os_confidence FROM devices WHERE id = ?", 
			device.ID).Scan(&createdAt, &existingDeviceType, &existingOsName, &existingOsVersion, &existingOsFamily, &existingOsConfidence)
		if err != nil {
			return nil, fmt.Errorf("error getting existing device data: %w", err)
		}
		device.CreatedAt = createdAt
		
		// Preserve existing device type if not provided in update
		if device.DeviceType == "" && existingDeviceType.Valid {
			device.DeviceType = models.DeviceType(existingDeviceType.String)
		}
		
		// Preserve existing OS data if not provided in update
		if device.OS == nil && (existingOsName.Valid || existingOsVersion.Valid || existingOsFamily.Valid || existingOsConfidence.Valid) {
			device.OS = &models.DeviceOS{}
			if existingOsName.Valid {
				device.OS.Name = existingOsName.String
			}
			if existingOsVersion.Valid {
				device.OS.Version = existingOsVersion.String
			}
			if existingOsFamily.Valid {
				device.OS.Family = existingOsFamily.String
			}
			if existingOsConfidence.Valid {
				device.OS.Confidence = int(existingOsConfidence.Int64)
			}
		}

		query := `
		UPDATE devices SET name = ?, comment = ?, mac = ?, vendor = ?, device_type = ?, 
			os_name = ?, os_version = ?, os_family = ?, os_confidence = ?,
			status = ?, network_id = ?, hostname = ?, updated_at = ?, last_seen_online_at = ?, 
			port_scan_started_at = ?, port_scan_ended_at = ?, web_scan_ended_at = ?
		WHERE id = ?`

		// Prepare OS fields
		var osName, osVersion, osFamily sql.NullString
		var osConfidence sql.NullInt64
		if device.OS != nil {
			if device.OS.Name != "" {
				osName = sql.NullString{String: device.OS.Name, Valid: true}
			}
			if device.OS.Version != "" {
				osVersion = sql.NullString{String: device.OS.Version, Valid: true}
			}
			if device.OS.Family != "" {
				osFamily = sql.NullString{String: device.OS.Family, Valid: true}
			}
			if device.OS.Confidence > 0 {
				osConfidence = sql.NullInt64{Int64: int64(device.OS.Confidence), Valid: true}
			}
		}

		_, err = tx.ExecContext(ctx, query,
			device.Name, nullableString(device.Comment), nullableString(device.MAC), nullableString(device.Vendor), 
			string(device.DeviceType), osName, osVersion, osFamily, osConfidence,
			device.Status, networkIDPtr, nullableString(device.Hostname),
			device.UpdatedAt, nullableTime(device.LastSeenOnlineAt),
			nullableTime(device.PortScanStartedAt), nullableTime(device.PortScanEndedAt), nullableTime(device.WebScanEndedAt),
			device.ID,
		)
		if err != nil {
			return nil, fmt.Errorf("error updating device: %w", err)
		}

		// Only delete existing ports if new ports are being provided
		if len(device.Ports) > 0 {
			_, err = tx.ExecContext(ctx, "DELETE FROM ports WHERE device_id = ?", device.ID)
			if err != nil {
				return nil, fmt.Errorf("error deleting device ports: %w", err)
			}
		}

		// Only delete existing web services if new web services are being provided
		if len(device.WebServices) > 0 {
			_, err = tx.ExecContext(ctx, "DELETE FROM web_services WHERE device_id = ?", device.ID)
			if err != nil {
				return nil, fmt.Errorf("error deleting device web services: %w", err)
			}
		}
	} else {
		// Create new device
		if device.ID == "" {
			device.ID = GenerateID()
		}
		device.CreatedAt = now

		query := `
		INSERT INTO devices (id, name, comment, ipv4, mac, vendor, device_type, 
			os_name, os_version, os_family, os_confidence,
			status, network_id, hostname, created_at, updated_at, last_seen_online_at, 
			port_scan_started_at, port_scan_ended_at, web_scan_ended_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

		// Prepare OS fields for insert
		var osName, osVersion, osFamily sql.NullString
		var osConfidence sql.NullInt64
		if device.OS != nil {
			if device.OS.Name != "" {
				osName = sql.NullString{String: device.OS.Name, Valid: true}
			}
			if device.OS.Version != "" {
				osVersion = sql.NullString{String: device.OS.Version, Valid: true}
			}
			if device.OS.Family != "" {
				osFamily = sql.NullString{String: device.OS.Family, Valid: true}
			}
			if device.OS.Confidence > 0 {
				osConfidence = sql.NullInt64{Int64: int64(device.OS.Confidence), Valid: true}
			}
		}

		_, err = tx.ExecContext(ctx, query,
			device.ID, device.Name, nullableString(device.Comment), device.IPv4, nullableString(device.MAC), nullableString(device.Vendor),
			string(device.DeviceType), osName, osVersion, osFamily, osConfidence,
			device.Status, networkIDPtr, nullableString(device.Hostname),
			device.CreatedAt, device.UpdatedAt, nullableTime(device.LastSeenOnlineAt),
			nullableTime(device.PortScanStartedAt), nullableTime(device.PortScanEndedAt), nullableTime(device.WebScanEndedAt),
		)
		if err != nil {
			return nil, fmt.Errorf("error inserting device: %w", err)
		}
	}

	if len(device.Ports) > 0 {
		portQuery := `INSERT INTO ports (device_id, number, protocol, state, service) VALUES (?, ?, ?, ?, ?)`
		for _, port := range device.Ports {
			_, err = tx.ExecContext(ctx, portQuery, device.ID, port.Number, port.Protocol, port.State, port.Service)
			if err != nil {
				return nil, fmt.Errorf("error inserting port: %w", err)
			}
		}
	}

	// Insert web services
	if len(device.WebServices) > 0 {
		webServiceQuery := `INSERT INTO web_services (device_id, url, title, server, status_code, content_type, size, screenshot, port, protocol, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		for _, ws := range device.WebServices {
			_, err = tx.ExecContext(ctx, webServiceQuery, device.ID, ws.URL, nullableString(&ws.Title), nullableString(&ws.Server), ws.StatusCode, nullableString(&ws.ContentType), ws.Size, nullableString(&ws.Screenshot), ws.Port, ws.Protocol, ws.ScannedAt)
			if err != nil {
				return nil, fmt.Errorf("error inserting web service: %w", err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("error committing transaction: %w", err)
	}

	return device, nil
}

// UpdateDeviceStatuses updates device statuses based on last seen time
func (r *SQLiteDeviceRepository) UpdateDeviceStatuses(ctx context.Context, timeout time.Duration) error {
	now := time.Now()
	offlineThreshold := now.Add(-timeout)

	query := `
	UPDATE devices 
	SET status = ?, updated_at = ?
	WHERE status IN (?, ?) AND last_seen_online_at < ?`

	_, err := r.db.ExecContext(ctx, query,
		models.DeviceStatusOffline, now,
		models.DeviceStatusOnline, models.DeviceStatusIdle,
		offlineThreshold,
	)
	if err != nil {
		return fmt.Errorf("error updating device statuses: %w", err)
	}

	idleThreshold := now.Add(-timeout / 2)
	query = `
	UPDATE devices 
	SET status = ?, updated_at = ?
	WHERE status = ? AND last_seen_online_at < ?`

	_, err = r.db.ExecContext(ctx, query,
		models.DeviceStatusIdle, now,
		models.DeviceStatusOnline,
		idleThreshold,
	)
	if err != nil {
		return fmt.Errorf("error updating device idle statuses: %w", err)
	}

	return nil
}

// DeleteByID deletes a device by ID
func (r *SQLiteDeviceRepository) DeleteByID(ctx context.Context, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM ports WHERE device_id = ?", id)
	if err != nil {
		return fmt.Errorf("error deleting device ports: %w", err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM web_services WHERE device_id = ?", id)
	if err != nil {
		return fmt.Errorf("error deleting device web services: %w", err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM devices WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("error deleting device: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

// SQLiteEventLogRepository implements the EventLogRepository interface for SQLite
type SQLiteEventLogRepository struct {
	db *sql.DB
}

// NewSQLiteEventLogRepository creates a new SQLiteEventLogRepository
func NewSQLiteEventLogRepository(db *sql.DB) *SQLiteEventLogRepository {
	return &SQLiteEventLogRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteEventLogRepository) Close() error {
	return r.db.Close()
}

// Create creates a new event log
func (r *SQLiteEventLogRepository) Create(ctx context.Context, eventLog *models.EventLog) error {
	now := time.Now()
	if eventLog.CreatedAt == nil {
		eventLog.CreatedAt = &now
	}
	if eventLog.UpdatedAt == nil {
		eventLog.UpdatedAt = &now
	}

	query := `INSERT INTO event_logs (type, description, device_id, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query,
		eventLog.Type, eventLog.Description, nullableString(eventLog.DeviceID),
		eventLog.CreatedAt, eventLog.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("error inserting event log: %w", err)
	}

	return nil
}

// FindLatest finds the latest event logs
func (r *SQLiteEventLogRepository) FindLatest(ctx context.Context, limit int) ([]*models.EventLog, error) {
	query := `SELECT type, description, device_id, created_at, updated_at
			  FROM event_logs ORDER BY created_at DESC LIMIT ?`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("error querying event logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.EventLog
	for rows.Next() {
		var log models.EventLog
		var deviceID sql.NullString
		var createdAt, updatedAt sql.NullTime

		err := rows.Scan(&log.Type, &log.Description, &deviceID, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning event log: %w", err)
		}

		if deviceID.Valid {
			log.DeviceID = &deviceID.String
		}
		if createdAt.Valid {
			log.CreatedAt = &createdAt.Time
		}
		if updatedAt.Valid {
			log.UpdatedAt = &updatedAt.Time
		}

		logs = append(logs, &log)
	}

	return logs, nil
}

// FindAllByDeviceID finds all event logs for a device
func (r *SQLiteEventLogRepository) FindAllByDeviceID(ctx context.Context, deviceID string) ([]*models.EventLog, error) {
	query := `SELECT type, description, device_id, created_at, updated_at
			  FROM event_logs WHERE device_id = ? ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("error querying device event logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.EventLog
	for rows.Next() {
		var log models.EventLog
		var createdAt, updatedAt sql.NullTime

		err := rows.Scan(&log.Type, &log.Description, &log.DeviceID, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning event log: %w", err)
		}

		if createdAt.Valid {
			log.CreatedAt = &createdAt.Time
		}
		if updatedAt.Valid {
			log.UpdatedAt = &updatedAt.Time
		}

		logs = append(logs, &log)
	}

	return logs, nil
}

// SQLiteSystemStatusRepository implements the SystemStatusRepository interface for SQLite
type SQLiteSystemStatusRepository struct {
	db *sql.DB
}

// NewSQLiteSystemStatusRepository creates a new SQLiteSystemStatusRepository
func NewSQLiteSystemStatusRepository(db *sql.DB) *SQLiteSystemStatusRepository {
	return &SQLiteSystemStatusRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteSystemStatusRepository) Close() error {
	return r.db.Close()
}

// Create creates a new system status
func (r *SQLiteSystemStatusRepository) Create(ctx context.Context, status *models.SystemStatus) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	// Convert strings to *string
	networkIDPtr := stringToPtr(status.NetworkID)

	query := `INSERT INTO system_status (network_id, public_ip, created_at, updated_at)
			  VALUES (?, ?, ?, ?)`

	result, err := tx.ExecContext(ctx, query,
		networkIDPtr, nullableString(status.PublicIP),
		status.CreatedAt, status.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("error inserting system status: %w", err)
	}

	statusID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("error getting last insert ID: %w", err)
	}

	query = `INSERT INTO local_devices (system_status_id, name, ipv4, mac, vendor, status, hostname)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, query,
		statusID, status.LocalDevice.Name, status.LocalDevice.IPv4,
		nullableString(status.LocalDevice.MAC), nullableString(status.LocalDevice.Vendor),
		status.LocalDevice.Status, nullableString(status.LocalDevice.Hostname),
	)
	if err != nil {
		return fmt.Errorf("error inserting local device: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

// FindLatest finds the latest system status
func (r *SQLiteSystemStatusRepository) FindLatest(ctx context.Context) (*models.SystemStatus, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	// Get the latest system status
	query := `SELECT id, network_id, public_ip, created_at, updated_at
			  FROM system_status ORDER BY created_at DESC LIMIT 1`

	var status models.SystemStatus
	var id int64
	var networkID, publicIP sql.NullString

	err = tx.QueryRowContext(ctx, query).Scan(
		&id, &networkID, &publicIP, &status.CreatedAt, &status.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("error scanning system status: %w", err)
	}

	if networkID.Valid {
		status.NetworkID = networkID.String
	}
	if publicIP.Valid {
		status.PublicIP = &publicIP.String
	}

	// Get the local device for this system status
	query = `SELECT name, ipv4, mac, vendor, status, hostname
			 FROM local_devices WHERE system_status_id = ?`

	var mac, vendor, hostname sql.NullString

	err = tx.QueryRowContext(ctx, query, id).Scan(
		&status.LocalDevice.Name, &status.LocalDevice.IPv4,
		&mac, &vendor, &status.LocalDevice.Status, &hostname,
	)
	if err != nil {
		return nil, fmt.Errorf("error scanning local device: %w", err)
	}

	if mac.Valid {
		status.LocalDevice.MAC = &mac.String
	}
	if vendor.Valid {
		status.LocalDevice.Vendor = &vendor.String
	}
	if hostname.Valid {
		status.LocalDevice.Hostname = &hostname.String
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("error committing transaction: %w", err)
	}

	return &status, nil
}

// Helper functions for handling nullable values
func nullableString(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullableTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// Converts a string to a pointer to string
func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullableInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

// SQLiteSNMPDataRepository implements the SNMPDataRepository interface for SQLite
type SQLiteSNMPDataRepository struct {
	db *sql.DB
}

// NewSQLiteSNMPDataRepository creates a new SQLiteSNMPDataRepository
func NewSQLiteSNMPDataRepository(db *sql.DB) *SQLiteSNMPDataRepository {
	return &SQLiteSNMPDataRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteSNMPDataRepository) Close() error {
	return r.db.Close()
}

// FindByDeviceID finds SNMP data by device ID
func (r *SQLiteSNMPDataRepository) FindByDeviceID(ctx context.Context, deviceID string) (*models.SNMPData, error) {
	query := `SELECT id, device_id, COALESCE(system_name, ''), COALESCE(system_descr, ''), 
	          COALESCE(system_object_id, ''), COALESCE(system_contact, ''), COALESCE(system_location, ''),
	          system_uptime, interface_count, COALESCE(interfaces, '[]'), COALESCE(community, ''),
	          COALESCE(version, ''), COALESCE(custom_oids, '{}'), last_scanned, scan_duration,
	          created_at, updated_at FROM snmp_data WHERE device_id = ?`
	
	row := r.db.QueryRowContext(ctx, query, deviceID)
	return r.scanSNMPData(row)
}

// CreateOrUpdate creates or updates SNMP data
func (r *SQLiteSNMPDataRepository) CreateOrUpdate(ctx context.Context, snmpData *models.SNMPData) (*models.SNMPData, error) {
	if snmpData.ID == "" {
		snmpData.ID = GenerateID()
	}

	// Marshal interfaces to JSON
	interfacesJSON, err := json.Marshal(snmpData.Interfaces)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interfaces: %w", err)
	}

	// Marshal custom OIDs to JSON
	customOIDsJSON, err := json.Marshal(snmpData.CustomOIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal custom OIDs: %w", err)
	}

	snmpData.UpdatedAt = time.Now()
	if snmpData.CreatedAt.IsZero() {
		snmpData.CreatedAt = time.Now()
	}

	// Check if record exists
	existing, err := r.FindByDeviceID(ctx, snmpData.DeviceID)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	if existing != nil {
		// Update existing record
		snmpData.ID = existing.ID
		query := `UPDATE snmp_data SET system_name = ?, system_descr = ?, system_object_id = ?,
		          system_contact = ?, system_location = ?, system_uptime = ?, interface_count = ?,
		          interfaces = ?, community = ?, version = ?, custom_oids = ?, last_scanned = ?,
		          scan_duration = ?, updated_at = ? WHERE id = ?`
		
		_, err = r.db.ExecContext(ctx, query,
			snmpData.SystemName, snmpData.SystemDescr, snmpData.SystemObjectID,
			snmpData.SystemContact, snmpData.SystemLocation, snmpData.SystemUptime,
			snmpData.InterfaceCount, string(interfacesJSON), snmpData.Community,
			snmpData.Version, string(customOIDsJSON), snmpData.LastScanned,
			int64(snmpData.ScanDuration), snmpData.UpdatedAt, snmpData.ID)
	} else {
		// Insert new record
		query := `INSERT INTO snmp_data (id, device_id, system_name, system_descr, system_object_id,
		          system_contact, system_location, system_uptime, interface_count, interfaces,
		          community, version, custom_oids, last_scanned, scan_duration, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		
		_, err = r.db.ExecContext(ctx, query,
			snmpData.ID, snmpData.DeviceID, snmpData.SystemName, snmpData.SystemDescr,
			snmpData.SystemObjectID, snmpData.SystemContact, snmpData.SystemLocation,
			snmpData.SystemUptime, snmpData.InterfaceCount, string(interfacesJSON),
			snmpData.Community, snmpData.Version, string(customOIDsJSON),
			snmpData.LastScanned, int64(snmpData.ScanDuration), snmpData.CreatedAt, snmpData.UpdatedAt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to save SNMP data: %w", err)
	}

	return snmpData, nil
}

// Delete removes SNMP data by ID
func (r *SQLiteSNMPDataRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM snmp_data WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete SNMP data: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// FindAll returns all SNMP data
func (r *SQLiteSNMPDataRepository) FindAll(ctx context.Context) ([]*models.SNMPData, error) {
	query := `SELECT id, device_id, COALESCE(system_name, ''), COALESCE(system_descr, ''), 
	          COALESCE(system_object_id, ''), COALESCE(system_contact, ''), COALESCE(system_location, ''),
	          system_uptime, interface_count, COALESCE(interfaces, '[]'), COALESCE(community, ''),
	          COALESCE(version, ''), COALESCE(custom_oids, '{}'), last_scanned, scan_duration,
	          created_at, updated_at FROM snmp_data ORDER BY last_scanned DESC`
	
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query SNMP data: %w", err)
	}
	defer rows.Close()

	var snmpDataList []*models.SNMPData
	for rows.Next() {
		snmpData, err := r.scanSNMPData(rows)
		if err != nil {
			return nil, err
		}
		snmpDataList = append(snmpDataList, snmpData)
	}

	return snmpDataList, nil
}

// scanSNMPData scans a row into an SNMPData struct
func (r *SQLiteSNMPDataRepository) scanSNMPData(scanner interface{}) (*models.SNMPData, error) {
	var snmpData models.SNMPData
	var interfacesJSON, customOIDsJSON string
	var systemUptime sql.NullInt64
	var interfaceCount sql.NullInt32
	var scanDuration int64

	var err error
	switch s := scanner.(type) {
	case *sql.Row:
		err = s.Scan(&snmpData.ID, &snmpData.DeviceID, &snmpData.SystemName, &snmpData.SystemDescr,
			&snmpData.SystemObjectID, &snmpData.SystemContact, &snmpData.SystemLocation,
			&systemUptime, &interfaceCount, &interfacesJSON, &snmpData.Community,
			&snmpData.Version, &customOIDsJSON, &snmpData.LastScanned, &scanDuration,
			&snmpData.CreatedAt, &snmpData.UpdatedAt)
	case *sql.Rows:
		err = s.Scan(&snmpData.ID, &snmpData.DeviceID, &snmpData.SystemName, &snmpData.SystemDescr,
			&snmpData.SystemObjectID, &snmpData.SystemContact, &snmpData.SystemLocation,
			&systemUptime, &interfaceCount, &interfacesJSON, &snmpData.Community,
			&snmpData.Version, &customOIDsJSON, &snmpData.LastScanned, &scanDuration,
			&snmpData.CreatedAt, &snmpData.UpdatedAt)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan SNMP data: %w", err)
	}

	// Convert nullable fields
	if systemUptime.Valid {
		snmpData.SystemUptime = &systemUptime.Int64
	}
	if interfaceCount.Valid {
		count := int(interfaceCount.Int32)
		snmpData.InterfaceCount = &count
	}
	snmpData.ScanDuration = time.Duration(scanDuration)

	// Unmarshal JSON fields
	if interfacesJSON != "" && interfacesJSON != "[]" {
		if err := json.Unmarshal([]byte(interfacesJSON), &snmpData.Interfaces); err != nil {
			return nil, fmt.Errorf("failed to unmarshal interfaces: %w", err)
		}
	}

	if customOIDsJSON != "" && customOIDsJSON != "{}" {
		if err := json.Unmarshal([]byte(customOIDsJSON), &snmpData.CustomOIDs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal custom OIDs: %w", err)
		}
	}

	// Initialize maps if nil
	if snmpData.CustomOIDs == nil {
		snmpData.CustomOIDs = make(map[string]string)
	}

	return &snmpData, nil
}

// SQLiteCertificateRepository implements the CertificateRepository interface for SQLite
type SQLiteCertificateRepository struct {
	db *sql.DB
}

// NewSQLiteCertificateRepository creates a new SQLiteCertificateRepository
func NewSQLiteCertificateRepository(db *sql.DB) *SQLiteCertificateRepository {
	return &SQLiteCertificateRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteCertificateRepository) Close() error {
	return r.db.Close()
}

// FindByDeviceID finds certificates by device ID
func (r *SQLiteCertificateRepository) FindByDeviceID(ctx context.Context, deviceID string) ([]*models.Certificate, error) {
	query := `SELECT id, device_id, host, port, protocol, COALESCE(subject_common_name, ''),
	          COALESCE(issuer_common_name, ''), serial_number, thumbprint, thumbprint_sha256,
	          version, signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
	          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, 
	          COALESCE(tls_version, ''), COALESCE(cipher_suite, ''), COALESCE(security_level, ''),
	          last_scanned, first_seen, created_at, updated_at
	          FROM certificates WHERE device_id = ? ORDER BY last_scanned DESC`
	
	rows, err := r.db.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	var certificates []*models.Certificate
	for rows.Next() {
		cert, err := r.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// FindByThumbprint finds a certificate by thumbprint
func (r *SQLiteCertificateRepository) FindByThumbprint(ctx context.Context, thumbprint string) (*models.Certificate, error) {
	query := `SELECT id, device_id, host, port, protocol, COALESCE(subject_common_name, ''),
	          COALESCE(issuer_common_name, ''), serial_number, thumbprint, thumbprint_sha256,
	          version, signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
	          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, 
	          COALESCE(tls_version, ''), COALESCE(cipher_suite, ''), COALESCE(security_level, ''),
	          last_scanned, first_seen, created_at, updated_at
	          FROM certificates WHERE thumbprint = ?`
	
	row := r.db.QueryRowContext(ctx, query, thumbprint)
	return r.scanCertificate(row)
}

// FindExpiring finds certificates expiring within the specified number of days
func (r *SQLiteCertificateRepository) FindExpiring(ctx context.Context, days int) ([]*models.Certificate, error) {
	query := `SELECT id, device_id, host, port, protocol, COALESCE(subject_common_name, ''),
	          COALESCE(issuer_common_name, ''), serial_number, thumbprint, thumbprint_sha256,
	          version, signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
	          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, 
	          COALESCE(tls_version, ''), COALESCE(cipher_suite, ''), COALESCE(security_level, ''),
	          last_scanned, first_seen, created_at, updated_at
	          FROM certificates WHERE not_after <= datetime('now', '+' || ? || ' days') 
	          AND not_after > datetime('now') ORDER BY not_after ASC`
	
	rows, err := r.db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var certificates []*models.Certificate
	for rows.Next() {
		cert, err := r.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// FindExpired finds expired certificates
func (r *SQLiteCertificateRepository) FindExpired(ctx context.Context) ([]*models.Certificate, error) {
	query := `SELECT id, device_id, host, port, protocol, COALESCE(subject_common_name, ''),
	          COALESCE(issuer_common_name, ''), serial_number, thumbprint, thumbprint_sha256,
	          version, signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
	          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, 
	          COALESCE(tls_version, ''), COALESCE(cipher_suite, ''), COALESCE(security_level, ''),
	          last_scanned, first_seen, created_at, updated_at
	          FROM certificates WHERE not_after < datetime('now') ORDER BY not_after DESC`
	
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query expired certificates: %w", err)
	}
	defer rows.Close()

	var certificates []*models.Certificate
	for rows.Next() {
		cert, err := r.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// CreateOrUpdate creates or updates a certificate
func (r *SQLiteCertificateRepository) CreateOrUpdate(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	if certificate.ID == "" {
		certificate.ID = GenerateID()
	}

	certificate.UpdatedAt = time.Now()
	if certificate.CreatedAt.IsZero() {
		certificate.CreatedAt = time.Now()
	}

	// Check if certificate exists by thumbprint
	existing, err := r.FindByThumbprint(ctx, certificate.Thumbprint)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	if existing != nil {
		// Update existing certificate
		certificate.ID = existing.ID
		certificate.FirstSeen = existing.FirstSeen // Preserve first seen
		
		query := `UPDATE certificates SET device_id = ?, host = ?, port = ?, protocol = ?,
		          subject_common_name = ?, issuer_common_name = ?, serial_number = ?,
		          thumbprint_sha256 = ?, version = ?, signature_algorithm = ?, public_key_algorithm = ?,
		          key_size = ?, not_before = ?, not_after = ?, is_ca = ?, is_self_signed = ?,
		          is_valid = ?, is_expired = ?, is_expiring_soon = ?, tls_version = ?,
		          cipher_suite = ?, security_level = ?, last_scanned = ?, updated_at = ?
		          WHERE id = ?`
		
		_, err = r.db.ExecContext(ctx, query,
			certificate.DeviceID, certificate.Host, certificate.Port, certificate.Protocol,
			certificate.Subject.CommonName, certificate.Issuer.CommonName, certificate.SerialNumber,
			certificate.ThumbprintSHA256, certificate.Version, certificate.SignatureAlgorithm,
			certificate.PublicKeyAlgorithm, certificate.KeySize, certificate.NotBefore, certificate.NotAfter,
			certificate.IsCA, certificate.IsSelfSigned, certificate.IsValid, certificate.IsExpired,
			certificate.IsExpiringSoon, certificate.TLSVersion, certificate.CipherSuite,
			string(certificate.SecurityLevel), certificate.LastScanned, certificate.UpdatedAt,
			certificate.ID)
	} else {
		// Insert new certificate
		if certificate.FirstSeen.IsZero() {
			certificate.FirstSeen = time.Now()
		}
		
		query := `INSERT INTO certificates (id, device_id, host, port, protocol, subject_common_name,
		          issuer_common_name, serial_number, thumbprint, thumbprint_sha256, version,
		          signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
		          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, tls_version,
		          cipher_suite, security_level, last_scanned, first_seen, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		
		_, err = r.db.ExecContext(ctx, query,
			certificate.ID, certificate.DeviceID, certificate.Host, certificate.Port, certificate.Protocol,
			certificate.Subject.CommonName, certificate.Issuer.CommonName, certificate.SerialNumber,
			certificate.Thumbprint, certificate.ThumbprintSHA256, certificate.Version,
			certificate.SignatureAlgorithm, certificate.PublicKeyAlgorithm, certificate.KeySize,
			certificate.NotBefore, certificate.NotAfter, certificate.IsCA, certificate.IsSelfSigned,
			certificate.IsValid, certificate.IsExpired, certificate.IsExpiringSoon, certificate.TLSVersion,
			certificate.CipherSuite, string(certificate.SecurityLevel), certificate.LastScanned,
			certificate.FirstSeen, certificate.CreatedAt, certificate.UpdatedAt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	return certificate, nil
}

// Delete removes a certificate by ID
func (r *SQLiteCertificateRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM certificates WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// FindAll returns all certificates
func (r *SQLiteCertificateRepository) FindAll(ctx context.Context) ([]*models.Certificate, error) {
	query := `SELECT id, device_id, host, port, protocol, COALESCE(subject_common_name, ''),
	          COALESCE(issuer_common_name, ''), serial_number, thumbprint, thumbprint_sha256,
	          version, signature_algorithm, public_key_algorithm, key_size, not_before, not_after,
	          is_ca, is_self_signed, is_valid, is_expired, is_expiring_soon, 
	          COALESCE(tls_version, ''), COALESCE(cipher_suite, ''), COALESCE(security_level, ''),
	          last_scanned, first_seen, created_at, updated_at
	          FROM certificates ORDER BY last_scanned DESC`
	
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all certificates: %w", err)
	}
	defer rows.Close()

	var certificates []*models.Certificate
	for rows.Next() {
		cert, err := r.scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// GetStats returns certificate statistics
func (r *SQLiteCertificateRepository) GetStats(ctx context.Context) (*models.CertificateStats, error) {
	stats := &models.CertificateStats{
		SecurityLevelCounts:   make(map[models.SecurityLevel]int),
		CommonIssuers:        make(map[string]int),
		AlgorithmDistribution: make(map[string]int),
	}

	// Total certificates
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates").Scan(&stats.TotalCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to get total certificates: %w", err)
	}

	// Valid certificates
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE is_valid = 1").Scan(&stats.ValidCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid certificates: %w", err)
	}

	// Expired certificates
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE is_expired = 1").Scan(&stats.ExpiredCertificates)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired certificates: %w", err)
	}

	// Expiring soon
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE is_expiring_soon = 1").Scan(&stats.ExpiringSoonCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring soon certificates: %w", err)
	}

	// Self-signed
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE is_self_signed = 1").Scan(&stats.SelfSignedCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get self-signed certificates: %w", err)
	}

	return stats, nil
}

// scanCertificate scans a row into a Certificate struct
func (r *SQLiteCertificateRepository) scanCertificate(scanner interface{}) (*models.Certificate, error) {
	var cert models.Certificate

	var err error
	switch s := scanner.(type) {
	case *sql.Row:
		err = s.Scan(&cert.ID, &cert.DeviceID, &cert.Host, &cert.Port, &cert.Protocol,
			&cert.Subject.CommonName, &cert.Issuer.CommonName, &cert.SerialNumber,
			&cert.Thumbprint, &cert.ThumbprintSHA256, &cert.Version, &cert.SignatureAlgorithm,
			&cert.PublicKeyAlgorithm, &cert.KeySize, &cert.NotBefore, &cert.NotAfter,
			&cert.IsCA, &cert.IsSelfSigned, &cert.IsValid, &cert.IsExpired, &cert.IsExpiringSoon,
			&cert.TLSVersion, &cert.CipherSuite, &cert.SecurityLevel,
			&cert.LastScanned, &cert.FirstSeen, &cert.CreatedAt, &cert.UpdatedAt)
	case *sql.Rows:
		err = s.Scan(&cert.ID, &cert.DeviceID, &cert.Host, &cert.Port, &cert.Protocol,
			&cert.Subject.CommonName, &cert.Issuer.CommonName, &cert.SerialNumber,
			&cert.Thumbprint, &cert.ThumbprintSHA256, &cert.Version, &cert.SignatureAlgorithm,
			&cert.PublicKeyAlgorithm, &cert.KeySize, &cert.NotBefore, &cert.NotAfter,
			&cert.IsCA, &cert.IsSelfSigned, &cert.IsValid, &cert.IsExpired, &cert.IsExpiringSoon,
			&cert.TLSVersion, &cert.CipherSuite, &cert.SecurityLevel,
			&cert.LastScanned, &cert.FirstSeen, &cert.CreatedAt, &cert.UpdatedAt)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan certificate: %w", err)
	}

	return &cert, nil
}

// SQLiteTopologyRepository implements the TopologyRepository interface for SQLite
type SQLiteTopologyRepository struct {
	db *sql.DB
}

// NewSQLiteTopologyRepository creates a new SQLiteTopologyRepository
func NewSQLiteTopologyRepository(db *sql.DB) *SQLiteTopologyRepository {
	return &SQLiteTopologyRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteTopologyRepository) Close() error {
	return r.db.Close()
}

// FindLatest finds the latest network topology
func (r *SQLiteTopologyRepository) FindLatest(ctx context.Context) (*models.NetworkTopology, error) {
	query := `SELECT id, local_subnet, COALESCE(discovered_routes, '[]'), COALESCE(gateways, '[]'),
	          COALESCE(hop_counts, '{}'), last_discovered, created_at, updated_at
	          FROM network_topology ORDER BY last_discovered DESC LIMIT 1`
	
	row := r.db.QueryRowContext(ctx, query)
	return r.scanTopology(row)
}

// CreateOrUpdate creates or updates network topology
func (r *SQLiteTopologyRepository) CreateOrUpdate(ctx context.Context, topology *models.NetworkTopology) (*models.NetworkTopology, error) {
	if topology.ID == "" {
		topology.ID = GenerateID()
	}

	// Marshal complex fields to JSON
	routesJSON, err := json.Marshal(topology.DiscoveredRoutes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal routes: %w", err)
	}

	gatewaysJSON, err := json.Marshal(topology.Gateways)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal gateways: %w", err)
	}

	hopCountsJSON, err := json.Marshal(topology.HopCounts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hop counts: %w", err)
	}

	topology.UpdatedAt = time.Now()
	if topology.CreatedAt.IsZero() {
		topology.CreatedAt = time.Now()
	}

	// Check if record exists
	existing, err := r.FindByLocalSubnet(ctx, topology.LocalSubnet)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	if existing != nil {
		// Update existing record
		topology.ID = existing.ID
		query := `UPDATE network_topology SET discovered_routes = ?, gateways = ?, hop_counts = ?,
		          last_discovered = ?, updated_at = ? WHERE id = ?`
		
		_, err = r.db.ExecContext(ctx, query,
			string(routesJSON), string(gatewaysJSON), string(hopCountsJSON),
			topology.LastDiscovered, topology.UpdatedAt, topology.ID)
	} else {
		// Insert new record
		query := `INSERT INTO network_topology (id, local_subnet, discovered_routes, gateways,
		          hop_counts, last_discovered, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		
		_, err = r.db.ExecContext(ctx, query,
			topology.ID, topology.LocalSubnet, string(routesJSON), string(gatewaysJSON),
			string(hopCountsJSON), topology.LastDiscovered, topology.CreatedAt, topology.UpdatedAt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to save topology: %w", err)
	}

	return topology, nil
}

// FindByLocalSubnet finds topology by local subnet
func (r *SQLiteTopologyRepository) FindByLocalSubnet(ctx context.Context, subnet string) (*models.NetworkTopology, error) {
	query := `SELECT id, local_subnet, COALESCE(discovered_routes, '[]'), COALESCE(gateways, '[]'),
	          COALESCE(hop_counts, '{}'), last_discovered, created_at, updated_at
	          FROM network_topology WHERE local_subnet = ?`
	
	row := r.db.QueryRowContext(ctx, query, subnet)
	return r.scanTopology(row)
}

// GetTopologyStats returns topology statistics
func (r *SQLiteTopologyRepository) GetTopologyStats(ctx context.Context) (*models.TopologyStats, error) {
	stats := &models.TopologyStats{
		SubnetDistribution: make(map[string]int),
		GatewayTypes:      make(map[string]int),
	}

	// Get basic counts
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateways").Scan(&stats.TotalGateways)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway count: %w", err)
	}

	// Get latest topology for subnet analysis
	topology, err := r.FindLatest(ctx)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	if topology != nil {
		stats.TotalSubnets = len(topology.HopCounts)
		stats.LastDiscovery = topology.LastDiscovered

		// Calculate statistics
		totalHops := 0
		maxHops := 0
		reachableCount := 0

		for _, hopCount := range topology.HopCounts {
			if hopCount > 0 {
				reachableCount++
				totalHops += hopCount
				if hopCount > maxHops {
					maxHops = hopCount
				}
				
				hopStr := strconv.Itoa(hopCount)
				stats.SubnetDistribution[hopStr]++
			}
		}

		stats.ReachableSubnets = reachableCount
		stats.MaxHopCount = maxHops
		if reachableCount > 0 {
			stats.AverageHopCount = float64(totalHops) / float64(reachableCount)
		}
	}

	return stats, nil
}

// scanTopology scans a row into a NetworkTopology struct
func (r *SQLiteTopologyRepository) scanTopology(scanner interface{}) (*models.NetworkTopology, error) {
	var topology models.NetworkTopology
	var routesJSON, gatewaysJSON, hopCountsJSON string

	var err error
	switch s := scanner.(type) {
	case *sql.Row:
		err = s.Scan(&topology.ID, &topology.LocalSubnet, &routesJSON, &gatewaysJSON,
			&hopCountsJSON, &topology.LastDiscovered, &topology.CreatedAt, &topology.UpdatedAt)
	case *sql.Rows:
		err = s.Scan(&topology.ID, &topology.LocalSubnet, &routesJSON, &gatewaysJSON,
			&hopCountsJSON, &topology.LastDiscovered, &topology.CreatedAt, &topology.UpdatedAt)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan topology: %w", err)
	}

	// Unmarshal JSON fields
	if routesJSON != "" && routesJSON != "[]" {
		if err := json.Unmarshal([]byte(routesJSON), &topology.DiscoveredRoutes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal routes: %w", err)
		}
	}

	if gatewaysJSON != "" && gatewaysJSON != "[]" {
		if err := json.Unmarshal([]byte(gatewaysJSON), &topology.Gateways); err != nil {
			return nil, fmt.Errorf("failed to unmarshal gateways: %w", err)
		}
	}

	if hopCountsJSON != "" && hopCountsJSON != "{}" {
		if err := json.Unmarshal([]byte(hopCountsJSON), &topology.HopCounts); err != nil {
			return nil, fmt.Errorf("failed to unmarshal hop counts: %w", err)
		}
	}

	// Initialize maps if nil
	if topology.DiscoveredRoutes == nil {
		topology.DiscoveredRoutes = []models.NetworkRoute{}
	}
	if topology.Gateways == nil {
		topology.Gateways = []models.Gateway{}
	}
	if topology.HopCounts == nil {
		topology.HopCounts = make(map[string]int)
	}

	return &topology, nil
}

// SQLiteGatewayRepository implements the GatewayRepository interface for SQLite
type SQLiteGatewayRepository struct {
	db *sql.DB
}

// NewSQLiteGatewayRepository creates a new SQLiteGatewayRepository
func NewSQLiteGatewayRepository(db *sql.DB) *SQLiteGatewayRepository {
	return &SQLiteGatewayRepository{db: db}
}

// Close closes the database connection
func (r *SQLiteGatewayRepository) Close() error {
	return r.db.Close()
}

// FindByIP finds a gateway by IP address
func (r *SQLiteGatewayRepository) FindByIP(ctx context.Context, ip string) (*models.Gateway, error) {
	query := `SELECT id, ip_address, COALESCE(mac_address, ''), COALESCE(hostname, ''),
	          COALESCE(vendor, ''), is_default, COALESCE(subnets, '[]'), hop_distance,
	          response_time, last_seen, created_at, updated_at
	          FROM gateways WHERE ip_address = ?`
	
	row := r.db.QueryRowContext(ctx, query, ip)
	return r.scanGateway(row)
}

// FindAll returns all gateways
func (r *SQLiteGatewayRepository) FindAll(ctx context.Context) ([]*models.Gateway, error) {
	query := `SELECT id, ip_address, COALESCE(mac_address, ''), COALESCE(hostname, ''),
	          COALESCE(vendor, ''), is_default, COALESCE(subnets, '[]'), hop_distance,
	          response_time, last_seen, created_at, updated_at
	          FROM gateways ORDER BY is_default DESC, ip_address`
	
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query gateways: %w", err)
	}
	defer rows.Close()

	var gateways []*models.Gateway
	for rows.Next() {
		gateway, err := r.scanGateway(rows)
		if err != nil {
			return nil, err
		}
		gateways = append(gateways, gateway)
	}

	return gateways, nil
}

// FindDefault finds the default gateway
func (r *SQLiteGatewayRepository) FindDefault(ctx context.Context) (*models.Gateway, error) {
	query := `SELECT id, ip_address, COALESCE(mac_address, ''), COALESCE(hostname, ''),
	          COALESCE(vendor, ''), is_default, COALESCE(subnets, '[]'), hop_distance,
	          response_time, last_seen, created_at, updated_at
	          FROM gateways WHERE is_default = 1 LIMIT 1`
	
	row := r.db.QueryRowContext(ctx, query)
	return r.scanGateway(row)
}

// CreateOrUpdate creates or updates a gateway
func (r *SQLiteGatewayRepository) CreateOrUpdate(ctx context.Context, gateway *models.Gateway) (*models.Gateway, error) {
	if gateway.ID == "" {
		gateway.ID = GenerateID()
	}

	// Marshal subnets to JSON
	subnetsJSON, err := json.Marshal(gateway.Subnets)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subnets: %w", err)
	}

	gateway.UpdatedAt = time.Now()
	if gateway.CreatedAt.IsZero() {
		gateway.CreatedAt = time.Now()
	}

	// Check if gateway exists by IP
	existing, err := r.FindByIP(ctx, gateway.IPAddress)
	if err != nil && err != ErrNotFound {
		return nil, err
	}

	if existing != nil {
		// Update existing gateway
		gateway.ID = existing.ID
		query := `UPDATE gateways SET mac_address = ?, hostname = ?, vendor = ?, is_default = ?,
		          subnets = ?, hop_distance = ?, response_time = ?, last_seen = ?, updated_at = ?
		          WHERE id = ?`
		
		_, err = r.db.ExecContext(ctx, query,
			gateway.MACAddress, gateway.Hostname, gateway.Vendor, gateway.IsDefault,
			string(subnetsJSON), gateway.HopDistance, gateway.ResponseTime,
			gateway.LastSeen, gateway.UpdatedAt, gateway.ID)
	} else {
		// Insert new gateway
		query := `INSERT INTO gateways (id, ip_address, mac_address, hostname, vendor,
		          is_default, subnets, hop_distance, response_time, last_seen, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		
		_, err = r.db.ExecContext(ctx, query,
			gateway.ID, gateway.IPAddress, gateway.MACAddress, gateway.Hostname, gateway.Vendor,
			gateway.IsDefault, string(subnetsJSON), gateway.HopDistance, gateway.ResponseTime,
			gateway.LastSeen, gateway.CreatedAt, gateway.UpdatedAt)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to save gateway: %w", err)
	}

	return gateway, nil
}

// Delete removes a gateway by ID
func (r *SQLiteGatewayRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM gateways WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete gateway: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateLastSeen updates the last seen timestamp for a gateway
func (r *SQLiteGatewayRepository) UpdateLastSeen(ctx context.Context, ip string, timestamp time.Time) error {
	query := `UPDATE gateways SET last_seen = ?, updated_at = ? WHERE ip_address = ?`
	_, err := r.db.ExecContext(ctx, query, timestamp, time.Now(), ip)
	if err != nil {
		return fmt.Errorf("failed to update gateway last seen: %w", err)
	}
	return nil
}

// scanGateway scans a row into a Gateway struct
func (r *SQLiteGatewayRepository) scanGateway(scanner interface{}) (*models.Gateway, error) {
	var gateway models.Gateway
	var subnetsJSON string
	var responseTime sql.NullFloat64

	var err error
	switch s := scanner.(type) {
	case *sql.Row:
		err = s.Scan(&gateway.ID, &gateway.IPAddress, &gateway.MACAddress, &gateway.Hostname,
			&gateway.Vendor, &gateway.IsDefault, &subnetsJSON, &gateway.HopDistance,
			&responseTime, &gateway.LastSeen, &gateway.CreatedAt, &gateway.UpdatedAt)
	case *sql.Rows:
		err = s.Scan(&gateway.ID, &gateway.IPAddress, &gateway.MACAddress, &gateway.Hostname,
			&gateway.Vendor, &gateway.IsDefault, &subnetsJSON, &gateway.HopDistance,
			&responseTime, &gateway.LastSeen, &gateway.CreatedAt, &gateway.UpdatedAt)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan gateway: %w", err)
	}

	// Handle nullable response time
	if responseTime.Valid {
		gateway.ResponseTime = &responseTime.Float64
	}

	// Unmarshal subnets JSON
	if subnetsJSON != "" && subnetsJSON != "[]" {
		if err := json.Unmarshal([]byte(subnetsJSON), &gateway.Subnets); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subnets: %w", err)
		}
	}

	// Initialize subnets if nil
	if gateway.Subnets == nil {
		gateway.Subnets = []string{}
	}

	return &gateway, nil
}
