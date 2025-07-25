package portscan

import (
	"context"
	"encoding/xml"
	"log"
	"net"
	"os/exec"
	"reconya-ai/internal/certificate"
	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/eventlog"
	"reconya-ai/internal/network"
	"reconya-ai/internal/snmp"
	"reconya-ai/internal/util"
	"reconya-ai/internal/webservice"
	"reconya-ai/models"
	"strings"
	"time"
)

type PortScanService struct {
	DeviceService      *device.DeviceService
	EventLogService    *eventlog.EventLogService
	WebService         *webservice.WebService
	NetworkService     *network.NetworkService
	SNMPService        *snmp.SNMPService
	CertificateService *certificate.CertificateService
	Config             *config.Config
}

func NewPortScanService(deviceService *device.DeviceService, eventLogService *eventlog.EventLogService, networkService *network.NetworkService, cfg *config.Config) *PortScanService {
	return &PortScanService{
		DeviceService:      deviceService,
		EventLogService:    eventLogService,
		WebService:         webservice.NewWebService(),
		NetworkService:     networkService,
		SNMPService:        snmp.NewSNMPService(cfg),
		CertificateService: certificate.NewCertificateService(cfg),
		Config:             cfg,
	}
}

func (s *PortScanService) Run(requestedDevice models.Device) {
	deviceIDStr := requestedDevice.ID
	log.Printf("Starting port scan for IP [%s]", requestedDevice.IPv4)
	
	// Use retry logic for creating event log
	err := util.RetryOnLock(func() error {
		return s.EventLogService.CreateOne(&models.EventLog{
			Type:     models.PortScanStarted,
			DeviceID: &deviceIDStr,
		})
	})
	
	if err != nil {
		log.Printf("Error creating port scan started event log: %v", err)
	}

	device, err := s.DeviceService.FindByIPv4(requestedDevice.IPv4)
	if err != nil {
		log.Printf("Error finding device: %v", err)
		return
	}

	if device == nil || device.IPv4 == "" {
		log.Printf("No device found for IP: %s", device.IPv4)
		return
	}

	ports, vendor, hostname, err := s.ExecutePortScan(device.IPv4)
	if err != nil {
		log.Printf("Error executing port scan: %v", err)
		return
	}

	// Always update ports when a portscan completes, even if no ports are found
	// This distinguishes between "no scan performed" and "scan completed with no open ports"
	device.Ports = ports
	if vendor != "" {
		device.Vendor = &vendor
	}
	if hostname != "" {
		device.Hostname = &hostname
	}
	
	// Set port scan ended timestamp
	now := time.Now()
	device.PortScanEndedAt = &now
	
	// Perform device fingerprinting before saving (analyzes ports, vendor, etc.)
	log.Printf("Performing device fingerprinting for IP [%s]", device.IPv4)
	s.DeviceService.PerformDeviceFingerprinting(device)
	
	// Use retry logic for saving device with updated ports and fingerprint data
	updatedDevice, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
		return s.DeviceService.CreateOrUpdate(device)
	})
	
	if err != nil {
		log.Printf("Error saving device with updated ports: %v", err)
		return
	}
	log.Printf("Port scan for IP [%s] completed. Found ports: %+v, Type: %s, Vendor: %s", device.IPv4, ports, device.DeviceType, vendor)
	
	// Start web service scanning if we found open ports (with screenshots during portscan)
	if len(ports) > 0 {
		log.Printf("Starting web service scan with screenshots for IP [%s]", device.IPv4)
		s.scanWebServicesWithScreenshots(updatedDevice)
	}

	// Perform SNMP scanning for additional device intelligence
	log.Printf("Starting SNMP scan for IP [%s]", device.IPv4)
	s.performSNMPScan(updatedDevice)

	// Perform SSL/TLS certificate scanning
	log.Printf("Starting certificate scan for IP [%s]", device.IPv4)
	s.performCertificateScan(updatedDevice)
	
	// Use retry logic for creating event log
	err = util.RetryOnLock(func() error {
		return s.EventLogService.CreateOne(&models.EventLog{
			Type:     models.PortScanCompleted,
			DeviceID: &deviceIDStr,
		})
	})
	
	if err != nil {
		log.Printf("Error creating port scan completed event log: %v", err)
	}
}

func (s *PortScanService) ExecutePortScan(ipv4 string) ([]models.Port, string, string, error) {
	// Determine scan mode based on which network this IP belongs to
	scanAllPorts, err := s.determineScanMode(ipv4)
	if err != nil {
		log.Printf("Error determining scan mode for %s, using default: %v", ipv4, err)
		scanAllPorts = s.Config.ScanAllPorts // Fall back to global config
	}
	
	// Build nmap command based on network-specific configuration
	var args []string
	var timeoutDuration time.Duration
	var scanDescription string
	
	if scanAllPorts {
		// Scan all 65535 ports with extended timeout
		args = []string{"nmap", "-sT", "-T4", "-p-", "-oX", "-", ipv4}
		timeoutDuration = 20 * time.Minute // Extended timeout for all ports
		scanDescription = "all 65535 ports, 20min timeout"
	} else {
		// Scan top 100 ports (default behavior)
		args = []string{"nmap", "-sT", "-T4", "--top-ports", "100", "-oX", "-", ipv4}
		timeoutDuration = 2 * time.Minute // Standard timeout for top ports
		scanDescription = "top 100 ports, 2min timeout"
	}
	
	log.Printf("Running optimized port scan for IP %s (%s)", ipv4, scanDescription)
	
	// Create context with appropriate timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	
	// Ensure process cleanup on context cancellation
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Port scan timeout for %s after %v", ipv4, timeoutDuration)
			return nil, "", "", ctx.Err()
		}
		log.Printf("nmap error: %v, output: %s", err, string(output))
		return nil, "", "", err
	}

	log.Printf("Scan completed for %s, parsing results", ipv4)
	ports, vendor, hostname := s.ParseNmapOutput(string(output))
	return ports, vendor, hostname, nil
}

func (s *PortScanService) ParseNmapOutput(output string) ([]models.Port, string, string) {
	var nmapXML models.NmapXML
	err := xml.Unmarshal([]byte(output), &nmapXML)
	if err != nil {
		log.Printf("Error parsing Nmap XML output: %v", err)
		return nil, "", ""
	}

	var ports []models.Port
	var vendor, hostname string
	for _, host := range nmapXML.Hosts {
		for _, address := range host.Addresses {
			if address.AddrType == "mac" && address.Vendor != "" {
				vendor = address.Vendor
				break
			}
		}

		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		for _, xmlPort := range host.Ports {
			port := models.Port{
				Number:   xmlPort.PortID,
				Protocol: xmlPort.Protocol,
				State:    xmlPort.State.State,
				Service:  xmlPort.Service.Name,
			}
			ports = append(ports, port)
		}
	}
	return ports, vendor, hostname
}

// determineScanMode determines whether to scan all ports for a given IP
func (s *PortScanService) determineScanMode(ipv4 string) (bool, error) {
	// Get all enabled networks to find which one contains this IP
	networks, err := s.NetworkService.GetEnabledNetworks(context.Background())
	if err != nil {
		return false, err
	}
	
	// Parse the target IP
	targetIP := net.ParseIP(ipv4)
	if targetIP == nil {
		return false, nil // Invalid IP, use default
	}
	
	// Check each network to see if the IP belongs to it
	for _, network := range networks {
		_, netCIDR, err := net.ParseCIDR(network.CIDR)
		if err != nil {
			log.Printf("Invalid CIDR in network %s: %s", network.Name, network.CIDR)
			continue
		}
		
		if netCIDR.Contains(targetIP) {
			log.Printf("IP %s belongs to network %s (%s), scan_all_ports: %t", 
				ipv4, network.Name, network.CIDR, network.ScanAllPorts)
			return network.ScanAllPorts, nil
		}
	}
	
	// If no network found in database, fall back to global config
	log.Printf("IP %s not found in any configured network, using global config", ipv4)
	return s.Config.ScanAllPorts, nil
}

// performSNMPScan performs SNMP scanning on a device for enhanced intelligence gathering
func (s *PortScanService) performSNMPScan(device *models.Device) {
	if device == nil {
		return
	}

	// Quick check if device likely supports SNMP to avoid long timeouts
	if !s.SNMPService.IsDeviceSNMPEnabled(context.Background(), device.IPv4) {
		log.Printf("Device %s does not appear to support SNMP, skipping detailed scan", device.IPv4)
		return
	}

	log.Printf("Performing SNMP scan for device %s", device.IPv4)
	startTime := time.Now()

	snmpData, err := s.SNMPService.ScanDevice(context.Background(), device.IPv4)
	if err != nil {
		log.Printf("SNMP scan failed for device %s: %v", device.IPv4, err)
		return
	}

	// Associate SNMP data with device
	snmpData.DeviceID = device.ID
	device.SNMPData = snmpData

	// Save updated device with SNMP data
	_, err = util.RetryOnLockWithResult(func() (*models.Device, error) {
		return s.DeviceService.CreateOrUpdate(device)
	})

	if err != nil {
		log.Printf("Error saving device with SNMP data: %v", err)
		return
	}

	duration := time.Since(startTime)
	log.Printf("SNMP scan completed for device %s in %v", device.IPv4, duration)
	log.Printf("SNMP Details - System: %s, Description: %s, Community: %s, Interfaces: %d",
		snmpData.SystemName, snmpData.SystemDescr, snmpData.Community, len(snmpData.Interfaces))

	// Enhance device identification based on SNMP data
	s.enhanceDeviceFromSNMP(device, snmpData)
}

// enhanceDeviceFromSNMP enhances device information based on SNMP data
func (s *PortScanService) enhanceDeviceFromSNMP(device *models.Device, snmpData *models.SNMPData) {
	updated := false

	// Update hostname if we have a better one from SNMP
	if snmpData.SystemName != "" && (device.Hostname == nil || *device.Hostname == "") {
		device.Hostname = &snmpData.SystemName
		updated = true
		log.Printf("Updated hostname for %s from SNMP: %s", device.IPv4, snmpData.SystemName)
	}

	// Update vendor information if available and not already set
	if device.Vendor == nil || *device.Vendor == "" {
		if vendor := s.extractVendorFromSNMP(snmpData); vendor != "" {
			device.Vendor = &vendor
			updated = true
			log.Printf("Updated vendor for %s from SNMP: %s", device.IPv4, vendor)
		}
	}

	// Enhance device type classification based on SNMP data
	if deviceType := s.classifyDeviceFromSNMP(snmpData); deviceType != models.DeviceTypeUnknown && device.DeviceType == models.DeviceTypeUnknown {
		device.DeviceType = deviceType
		updated = true
		log.Printf("Updated device type for %s from SNMP: %s", device.IPv4, deviceType)
	}

	// Save updates if any changes were made
	if updated {
		_, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
			return s.DeviceService.CreateOrUpdate(device)
		})
		if err != nil {
			log.Printf("Error saving enhanced device data: %v", err)
		}
	}
}

// extractVendorFromSNMP extracts vendor information from SNMP data
func (s *PortScanService) extractVendorFromSNMP(snmpData *models.SNMPData) string {
	// Try to extract vendor from system description
	if snmpData.SystemDescr != "" {
		desc := strings.ToLower(snmpData.SystemDescr)
		
		// Common vendor patterns in system descriptions
		vendors := []string{"cisco", "hp", "dell", "netgear", "linksys", "d-link", "tplink", "ubiquiti", "juniper", "fortinet"}
		for _, vendor := range vendors {
			if strings.Contains(desc, vendor) {
				return strings.Title(vendor)
			}
		}
	}

	// Try to extract from system object ID
	if snmpData.SystemObjectID != "" {
		// Map common enterprise OIDs to vendors
		oidVendors := map[string]string{
			"1.3.6.1.4.1.9":     "Cisco",
			"1.3.6.1.4.1.11":    "HP",
			"1.3.6.1.4.1.674":   "Dell",
			"1.3.6.1.4.1.4526":  "Netgear",
			"1.3.6.1.4.1.3955":  "Linksys",
			"1.3.6.1.4.1.171":   "D-Link",
			"1.3.6.1.4.1.41112": "Ubiquiti",
			"1.3.6.1.4.1.2636":  "Juniper",
		}

		for oid, vendor := range oidVendors {
			if strings.HasPrefix(snmpData.SystemObjectID, oid) {
				return vendor
			}
		}
	}

	return ""
}

// classifyDeviceFromSNMP classifies device type based on SNMP data
func (s *PortScanService) classifyDeviceFromSNMP(snmpData *models.SNMPData) models.DeviceType {
	if snmpData.SystemDescr == "" {
		return models.DeviceTypeUnknown
	}

	desc := strings.ToLower(snmpData.SystemDescr)

	// Router patterns
	if strings.Contains(desc, "router") || strings.Contains(desc, "gateway") {
		return models.DeviceTypeRouter
	}

	// Switch patterns
	if strings.Contains(desc, "switch") || strings.Contains(desc, "switching") {
		return models.DeviceTypeSwitch
	}

	// Access Point patterns
	if strings.Contains(desc, "access point") || strings.Contains(desc, "wireless") || strings.Contains(desc, "wifi") {
		return models.DeviceTypeAccessPoint
	}

	// Firewall patterns
	if strings.Contains(desc, "firewall") || strings.Contains(desc, "security") {
		return models.DeviceTypeFirewall
	}

	// Printer patterns
	if strings.Contains(desc, "printer") || strings.Contains(desc, "print") {
		return models.DeviceTypePrinter
	}

	// NAS patterns
	if strings.Contains(desc, "nas") || strings.Contains(desc, "storage") || strings.Contains(desc, "file server") {
		return models.DeviceTypeNAS
	}

	// Server patterns
	if strings.Contains(desc, "server") || strings.Contains(desc, "linux") || strings.Contains(desc, "windows server") {
		return models.DeviceTypeServer
	}

	// Camera patterns
	if strings.Contains(desc, "camera") || strings.Contains(desc, "video") || strings.Contains(desc, "surveillance") {
		return models.DeviceTypeCamera
	}

	return models.DeviceTypeUnknown
}

// performCertificateScan performs SSL/TLS certificate scanning for a device
func (s *PortScanService) performCertificateScan(device *models.Device) {
	if device == nil || len(device.Ports) == 0 {
		return
	}

	log.Printf("Performing certificate scan for device %s", device.IPv4)
	startTime := time.Now()

	certificates, err := s.CertificateService.ScanDeviceCertificates(context.Background(), device.IPv4, device.Ports)
	if err != nil {
		log.Printf("Certificate scan failed for device %s: %v", device.IPv4, err)
		return
	}

	if len(certificates) == 0 {
		log.Printf("No certificates found on device %s", device.IPv4)
		return
	}

	// Save certificates using the certificate service/repository
	for _, cert := range certificates {
		cert.DeviceID = device.ID
		
		// Save each certificate individually
		_, err := s.DeviceService.SaveCertificate(cert)
		if err != nil {
			log.Printf("Error saving certificate for device %s: %v", device.IPv4, err)
			continue
		}
	}

	duration := time.Since(startTime)
	log.Printf("Certificate scan completed for device %s in %v. Found %d certificates", device.IPv4, duration, len(certificates))
	
	// Log certificate details
	for _, cert := range certificates {
		log.Printf("Certificate found on %s:%d - Subject: %s, Issuer: %s, Security: %s, Expires: %s",
			device.IPv4, cert.Port, cert.Subject.CommonName, cert.Issuer.CommonName, 
			cert.SecurityLevel, cert.NotAfter.Format("2006-01-02"))
	}
}

// scanWebServices scans for web services on the device and updates the device with web info (no screenshots)
func (s *PortScanService) scanWebServices(device *models.Device) {
	if device == nil {
		return
	}

	webInfos := s.WebService.ScanWebServices(device)
	s.saveWebServices(device, webInfos)
}

// scanWebServicesWithScreenshots scans for web services on the device with screenshot capture
func (s *PortScanService) scanWebServicesWithScreenshots(device *models.Device) {
	if device == nil {
		return
	}

	webInfos := s.WebService.ScanWebServicesWithScreenshots(device, true)
	s.saveWebServices(device, webInfos)
}

// saveWebServices saves web service information to the device
func (s *PortScanService) saveWebServices(device *models.Device, webInfos []webservice.WebInfo) {
	if len(webInfos) == 0 {
		log.Printf("No web services found on device %s", device.IPv4)
		return
	}

	// Convert webservice.WebInfo to models.WebService
	var webServices []models.WebService
	for _, webInfo := range webInfos {
		webService := models.WebService{
			URL:         webInfo.URL,
			Title:       webInfo.Title,
			Server:      webInfo.Server,
			StatusCode:  webInfo.StatusCode,
			ContentType: webInfo.ContentType,
			Size:        webInfo.Size,
			Screenshot:  webInfo.Screenshot,
			Port:        s.extractPortFromURL(webInfo.URL),
			Protocol:    s.extractProtocolFromURL(webInfo.URL),
			ScannedAt:   time.Now(),
		}
		webServices = append(webServices, webService)
	}

	// Update device with web services
	device.WebServices = webServices
	now := time.Now()
	device.WebScanEndedAt = &now

	// Save device with web services
	_, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
		return s.DeviceService.CreateOrUpdate(device)
	})

	if err != nil {
		log.Printf("Error saving device with web services: %v", err)
		return
	}

	log.Printf("Web service scan completed for IP [%s]. Found %d web services", device.IPv4, len(webServices))
	for _, ws := range webServices {
		log.Printf("  - %s: %s (Status: %d)", ws.URL, ws.Title, ws.StatusCode)
	}
}

// extractPortFromURL extracts port number from URL
func (s *PortScanService) extractPortFromURL(url string) int {
	// Simple extraction - could be improved with proper URL parsing
	if strings.Contains(url, ":80/") || strings.HasSuffix(url, ":80") {
		return 80
	}
	if strings.Contains(url, ":443/") || strings.HasSuffix(url, ":443") {
		return 443
	}
	if strings.Contains(url, ":8080/") || strings.HasSuffix(url, ":8080") {
		return 8080
	}
	if strings.Contains(url, ":8443/") || strings.HasSuffix(url, ":8443") {
		return 8443
	}
	// Add more port extractions as needed
	return 80 // Default
}

// extractProtocolFromURL extracts protocol from URL
func (s *PortScanService) extractProtocolFromURL(url string) string {
	if strings.HasPrefix(url, "https://") {
		return "https"
	}
	return "http"
}
