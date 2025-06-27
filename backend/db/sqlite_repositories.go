// Full solution in backend/db/sqlite_repositories.go
package db

import (
	"context"
	"database/sql"
	"fmt"
	"reconya-ai/models"
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
