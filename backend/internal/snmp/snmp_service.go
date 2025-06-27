package snmp

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"reconya-ai/internal/config"
	"reconya-ai/internal/validation"
	"reconya-ai/models"
	"strconv"
	"strings"
	"time"
)

type SNMPService struct {
	Config            *config.Config
	Validator         *validation.NetworkValidator
	CommunityStrings  []models.SNMPCommunityString
	ScanTimeout       time.Duration
	MaxRetries        int
}

func NewSNMPService(cfg *config.Config) *SNMPService {
	// Get community strings from environment or use defaults
	communityStrings := parseCommunityStringsFromConfig(cfg)
	if len(communityStrings) == 0 {
		communityStrings = models.GetDefaultCommunityStrings()
	}

	return &SNMPService{
		Config:           cfg,
		Validator:        validation.NewNetworkValidator(),
		CommunityStrings: communityStrings,
		ScanTimeout:      30 * time.Second,
		MaxRetries:       2,
	}
}

// ScanDevice performs SNMP scanning on a device and returns gathered information
func (s *SNMPService) ScanDevice(ctx context.Context, deviceIP string) (*models.SNMPData, error) {
	// Validate IP address
	if err := s.Validator.ValidateIPAddress(deviceIP); err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	log.Printf("Starting SNMP scan for device: %s", deviceIP)
	startTime := time.Now()

	// Try each community string until one works
	for _, community := range s.CommunityStrings {
		log.Printf("Trying SNMP %s with community '%s' on %s", community.Version, community.Community, deviceIP)
		
		snmpData, err := s.scanWithCommunity(ctx, deviceIP, community)
		if err != nil {
			log.Printf("SNMP scan failed with community '%s': %v", community.Community, err)
			continue
		}

		// Success! Fill in metadata
		snmpData.Community = community.Community
		snmpData.Version = community.Version
		snmpData.LastScanned = time.Now()
		snmpData.ScanDuration = time.Since(startTime)
		snmpData.CreatedAt = time.Now()
		snmpData.UpdatedAt = time.Now()

		log.Printf("SNMP scan successful for %s using community '%s' (%s)", 
			deviceIP, community.Community, snmpData.ScanDuration)
		return snmpData, nil
	}

	return nil, fmt.Errorf("SNMP scan failed for %s with all community strings", deviceIP)
}

// scanWithCommunity performs SNMP scan with a specific community string
func (s *SNMPService) scanWithCommunity(ctx context.Context, deviceIP string, community models.SNMPCommunityString) (*models.SNMPData, error) {
	snmpData := &models.SNMPData{
		CustomOIDs: make(map[string]string),
	}

	// Create context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, s.ScanTimeout)
	defer cancel()

	// Get system information
	if err := s.getSystemInfo(scanCtx, deviceIP, community, snmpData); err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	// Get interface information
	if err := s.getInterfaceInfo(scanCtx, deviceIP, community, snmpData); err != nil {
		log.Printf("Failed to get interface info for %s: %v", deviceIP, err)
		// Don't fail the entire scan if interface info fails
	}

	return snmpData, nil
}

// getSystemInfo retrieves basic system information via SNMP
func (s *SNMPService) getSystemInfo(ctx context.Context, deviceIP string, community models.SNMPCommunityString, snmpData *models.SNMPData) error {
	// System Name
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemNameOID); err == nil {
		snmpData.SystemName = value
	}

	// System Description
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemDescrOID); err == nil {
		snmpData.SystemDescr = value
	}

	// System Object ID
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemObjectIDOID); err == nil {
		snmpData.SystemObjectID = value
	}

	// System Contact
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemContactOID); err == nil {
		snmpData.SystemContact = value
	}

	// System Location
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemLocationOID); err == nil {
		snmpData.SystemLocation = value
	}

	// System Uptime
	if value, err := s.snmpGet(ctx, deviceIP, community, models.SystemUptimeOID); err == nil {
		if uptime, parseErr := strconv.ParseInt(value, 10, 64); parseErr == nil {
			snmpData.SystemUptime = &uptime
		}
	}

	// Interface Count
	if value, err := s.snmpGet(ctx, deviceIP, community, models.IfNumberOID); err == nil {
		if count, parseErr := strconv.Atoi(value); parseErr == nil {
			snmpData.InterfaceCount = &count
		}
	}

	// At least one value must be retrieved for success
	if snmpData.SystemName == "" && snmpData.SystemDescr == "" && snmpData.SystemObjectID == "" {
		return fmt.Errorf("no system information retrieved")
	}

	return nil
}

// getInterfaceInfo retrieves interface information via SNMP
func (s *SNMPService) getInterfaceInfo(ctx context.Context, deviceIP string, community models.SNMPCommunityString, snmpData *models.SNMPData) error {
	// Get interface count first
	interfaceCountStr, err := s.snmpGet(ctx, deviceIP, community, models.IfNumberOID)
	if err != nil {
		return fmt.Errorf("failed to get interface count: %w", err)
	}

	interfaceCount, err := strconv.Atoi(interfaceCountStr)
	if err != nil {
		return fmt.Errorf("invalid interface count: %w", err)
	}

	// Limit interface scanning to reasonable number
	if interfaceCount > 50 {
		interfaceCount = 50
	}

	var interfaces []models.SNMPInterface
	for i := 1; i <= interfaceCount; i++ {
		iface := models.SNMPInterface{Index: i}

		// Get interface description
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfDescrOID, i)); err == nil {
			iface.Description = value
			iface.Name = value // Use description as name if name not available
		}

		// Get interface type
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfTypeOID, i)); err == nil {
			iface.Type = value
		}

		// Get MTU
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfMtuOID, i)); err == nil {
			if mtu, parseErr := strconv.Atoi(value); parseErr == nil {
				iface.MTU = &mtu
			}
		}

		// Get Speed
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfSpeedOID, i)); err == nil {
			if speed, parseErr := strconv.ParseInt(value, 10, 64); parseErr == nil {
				iface.Speed = &speed
			}
		}

		// Get Physical Address (MAC)
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfPhysAddressOID, i)); err == nil {
			iface.PhysAddress = value
		}

		// Get Admin Status
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfAdminStatusOID, i)); err == nil {
			iface.AdminStatus = value
		}

		// Get Operational Status
		if value, err := s.snmpGet(ctx, deviceIP, community, fmt.Sprintf("%s.%d", models.IfOperStatusOID, i)); err == nil {
			iface.OperStatus = value
		}

		// Only add interface if we got some meaningful data
		if iface.Description != "" || iface.Type != "" || iface.PhysAddress != "" {
			interfaces = append(interfaces, iface)
		}
	}

	snmpData.Interfaces = interfaces
	return nil
}

// snmpGet performs a single SNMP GET operation
func (s *SNMPService) snmpGet(ctx context.Context, deviceIP string, community models.SNMPCommunityString, oid string) (string, error) {
	// Build snmpget command
	args := []string{
		"snmpget",
		"-v", community.Version,
		"-c", community.Community,
		"-t", "5", // 5 second timeout
		"-r", "1", // 1 retry
		"-Oqv",   // Quiet output, value only
		deviceIP,
		oid,
	}

	// Validate command arguments
	if err := s.Validator.SanitizeCommandArgs(args); err != nil {
		return "", fmt.Errorf("command validation failed: %w", err)
	}

	// Execute command with context
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("snmpget failed: %w", err)
	}

	// Clean and return value
	value := strings.TrimSpace(string(output))
	if value == "" || strings.Contains(value, "No Such Object") || strings.Contains(value, "Timeout") {
		return "", fmt.Errorf("no value returned for OID %s", oid)
	}

	return value, nil
}

// parseCommunityStringsFromConfig parses SNMP community strings from environment
func parseCommunityStringsFromConfig(cfg *config.Config) []models.SNMPCommunityString {
	if cfg.SNMPCommunityStrings == "" {
		return nil
	}

	communities := strings.Split(cfg.SNMPCommunityStrings, ",")
	var result []models.SNMPCommunityString

	for _, community := range communities {
		community = strings.TrimSpace(community)
		if community != "" {
			// Default to SNMP v2c for configured communities
			result = append(result, models.SNMPCommunityString{
				Community: community,
				Version:   "2c",
			})
			// Also try v1 as fallback
			result = append(result, models.SNMPCommunityString{
				Community: community,
				Version:   "1",
			})
		}
	}

	return result
}

// IsDeviceSNMPEnabled checks if a device likely supports SNMP
func (s *SNMPService) IsDeviceSNMPEnabled(ctx context.Context, deviceIP string) bool {
	// Quick check using a simple system OID with short timeout
	quickCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for _, community := range s.CommunityStrings[:2] { // Only try first 2 for quick check
		if _, err := s.snmpGet(quickCtx, deviceIP, community, models.SystemDescrOID); err == nil {
			return true
		}
	}
	return false
}