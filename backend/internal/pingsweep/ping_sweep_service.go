package pingsweep

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"reconya-ai/internal/config"
	"reconya-ai/internal/device"
	"reconya-ai/internal/eventlog"
	"reconya-ai/internal/network"
	"reconya-ai/internal/portscan"
	"reconya-ai/internal/scanner"
	"reconya-ai/internal/util"
	"reconya-ai/internal/validation"
	"reconya-ai/models"
	"strings"
	"sync"
)

type PingSweepService struct {
	Config          *config.Config
	DeviceService   *device.DeviceService
	EventLogService *eventlog.EventLogService
	NetworkService  *network.NetworkService
	PortScanService *portscan.PortScanService
	Validator       *validation.NetworkValidator
	portScanQueue   chan models.Device
	portScanWorkers sync.WaitGroup
}

func NewPingSweepService(
	cfg *config.Config,
	deviceService *device.DeviceService,
	eventLogService *eventlog.EventLogService,
	networkService *network.NetworkService,
	portScanService *portscan.PortScanService) *PingSweepService {
	
	service := &PingSweepService{
		Config:          cfg,
		DeviceService:   deviceService,
		EventLogService: eventLogService,
		NetworkService:  networkService,
		PortScanService: portScanService,
		Validator:       validation.NewNetworkValidator(),
		portScanQueue:   make(chan models.Device, 100), // Buffer for 100 devices
	}
	
	// Start 3 port scan workers
	service.startPortScanWorkers(3)
	
	return service
}
func (s *PingSweepService) Run() {
	log.Println("Starting new ping sweep scan...")

	// Use retry logic for creating initial ping sweep event log
	err := util.RetryOnLock(func() error {
		return s.EventLogService.CreateOne(&models.EventLog{
			Type: models.PingSweep,
		})
	})
	
	if err != nil {
		log.Printf("Error creating ping sweep event log: %v", err)
	}
	
	// Get scan targets from network service (includes database and config)
	networkRanges, err := s.NetworkService.GetScanTargets(context.Background())
	if err != nil {
		log.Printf("Error getting scan targets: %v", err)
		return
	}
	
	if len(networkRanges) == 0 {
		log.Printf("No network ranges configured for scanning")
		return
	}
	
	log.Printf("Scanning %d network ranges: %v", len(networkRanges), networkRanges)
	
	var allDevices []models.Device
	
	// Scan each network range
	for i, network := range networkRanges {
		log.Printf("Scanning network %d/%d: %s", i+1, len(networkRanges), network)
		
		// Validate each network before scanning
		if err := s.Validator.ValidateNetworkRange(network); err != nil {
			log.Printf("Invalid network CIDR %s: %v", network, err)
			continue
		}
		
		devices, err := s.ExecuteSweepScanCommand(network)
		if err != nil {
			log.Printf("Error executing sweep scan on %s: %v", network, err)
			continue
		}
		
		log.Printf("Network %s: found %d devices", network, len(devices))
		allDevices = append(allDevices, devices...)
	}
	
	log.Printf("Ping sweep found %d total devices from %d networks", len(allDevices), len(networkRanges))

	// Update all devices and add eligible ones to port scan queue
	for i, device := range allDevices {
		log.Printf("Processing device %d/%d: %s", i+1, len(allDevices), device.IPv4)
		// Use retry logic for updating device
		updatedDevice, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
			return s.DeviceService.CreateOrUpdate(&device)
		})
		
		if err != nil {
			log.Printf("Error updating device %s after retries: %v", device.IPv4, err)
			continue
		}
		log.Printf("Successfully saved device: %s", device.IPv4)

		deviceIDStr := device.ID
		// Use retry logic for creating event log
		eventLogErr := util.RetryOnLock(func() error {
			return s.EventLogService.CreateOne(&models.EventLog{
				Type:     models.DeviceOnline,
				DeviceID: &deviceIDStr,
			})
		})
		
		if eventLogErr != nil {
			log.Printf("Error creating device online event log: %v", eventLogErr)
		}

		// Add to port scan queue if eligible
		if s.DeviceService.EligibleForPortScan(updatedDevice) {
			select {
			case s.portScanQueue <- *updatedDevice:
				log.Printf("Added device %s to port scan queue", updatedDevice.IPv4)
			default:
				log.Printf("Port scan queue full, skipping device %s", updatedDevice.IPv4)
			}
		}
	}

	log.Printf("Ping sweep scan completed. Found %d devices across %d networks.", len(allDevices), len(networkRanges))
}

func (s *PingSweepService) ExecuteSweepScanCommand(network string) ([]models.Device, error) {
	log.Printf("Executing nmap command on network: %s", network)
	
	// Try multiple scan strategies for different environments
	devices, err := s.executeWithFallback(network)
	if err != nil {
		return nil, err
	}

	log.Printf("nmap command succeeded. Found %d devices", len(devices))

	// If we didn't get hostnames from nmap, try to enhance with additional methods
	for i, device := range devices {
		if device.Hostname == nil || *device.Hostname == "" {
			// Try to get hostname using additional methods
			if hostname := s.tryGetHostname(device.IPv4); hostname != "" {
				devices[i].Hostname = &hostname
				log.Printf("Enhanced hostname detection found: %s for IP: %s", hostname, device.IPv4)
			}
		}
	}
	
	return devices, nil
}

// executeWithFallback tries different scan strategies based on environment
func (s *PingSweepService) executeWithFallback(network string) ([]models.Device, error) {
	// Skip native scanner - it's too slow for large networks
	log.Printf("Skipping native Go scanner, using nmap directly")

	// Strategy 1: Try sudo with IP packets (works on most systems, gets MAC/vendor)
	devices, err := s.tryNmapCommand([]string{"sudo", "nmap", "-sn", "--send-ip", "-T4", "-R", "--system-dns", "-oX", "-", network})
	if err == nil && len(devices) > 0 {
		log.Printf("Sudo IP scan successful, found %d devices", len(devices))
		return devices, nil
	}
	log.Printf("Sudo IP scan failed or found no devices: %v", err)

	// Strategy 3: Try IP packets without sudo (may still get some MAC info)
	devices, err = s.tryNmapCommand([]string{"nmap", "-sn", "--send-ip", "-T4", "-oX", "-", network})
	if err == nil && len(devices) > 0 {
		log.Printf("IP scan without sudo successful, found %d devices", len(devices))
		return devices, nil
	}
	log.Printf("IP scan without sudo failed or found no devices: %v", err)

	// Strategy 4: Try ARP scan with sudo (best for local networks but needs interface access)
	devices, err = s.tryNmapCommand([]string{"sudo", "nmap", "-sn", "-PR", "-T4", "-R", "--system-dns", "-oX", "-", network})
	if err == nil && len(devices) > 0 {
		log.Printf("Sudo ARP scan successful, found %d devices", len(devices))
		return devices, nil
	}
	log.Printf("Sudo ARP scan failed or found no devices: %v", err)

	// Strategy 5: Try ARP scan without sudo
	devices, err = s.tryNmapCommand([]string{"nmap", "-sn", "-PR", "-T4", "-oX", "-", network})
	if err == nil && len(devices) > 0 {
		log.Printf("ARP scan without sudo successful, found %d devices", len(devices))
		return devices, nil
	}
	log.Printf("ARP scan without sudo failed or found no devices: %v", err)

	// Strategy 6: Last resort - TCP SYN scan on common ports (minimal info but finds hosts)
	devices, err = s.tryNmapCommand([]string{"nmap", "-sn", "-PS80,443,22,21,23,25,53,110,111,135,139,143,993,995", "-T4", "-oX", "-", network})
	if err == nil && len(devices) > 0 {
		log.Printf("TCP SYN probe scan successful, found %d devices", len(devices))
		return devices, nil
	}
	log.Printf("TCP SYN probe scan failed or found no devices: %v", err)

	return nil, fmt.Errorf("all scan strategies failed for network %s", network)
}

// tryNativeScanner uses the native Go scanner for network discovery
func (s *PingSweepService) tryNativeScanner(network string) ([]models.Device, error) {
	log.Printf("Trying native Go scanner on network: %s", network)
	
	nativeScanner := scanner.NewNativeScanner()
	devices, err := nativeScanner.ScanNetwork(network)
	if err != nil {
		return nil, err
	}
	
	return devices, nil
}

// tryNmapCommand executes a specific nmap command and returns parsed devices
func (s *PingSweepService) tryNmapCommand(args []string) ([]models.Device, error) {
	log.Printf("Trying nmap command: %s", strings.Join(args, " "))
	
	// Validate command arguments before execution
	if err := s.Validator.SanitizeCommandArgs(args); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}
	
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("nmap command failed: %v, output: %s", err, string(output))
		return nil, err
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("nmap returned empty output")
	}

	log.Printf("nmap command output length: %d bytes", len(output))
	
	devices := s.DeviceService.ParseFromNmapXML(string(output))
	return devices, nil
}

// tryGetHostname attempts to get hostname using additional methods
func (s *PingSweepService) tryGetHostname(ip string) string {
	// Try a dedicated nmap hostname scan first (most reliable)
	if hostname := s.tryNmapHostnameScan(ip); hostname != "" {
		return hostname
	}
	
	// Try DNS reverse lookup with timeout
	if hostname := s.tryDNSReverseLookup(ip); hostname != "" {
		return hostname
	}
	
	// Try alternative DNS lookup methods
	if hostname := s.tryDigReverseLookup(ip); hostname != "" {
		return hostname
	}
	
	return ""
}

// tryNmapHostnameScan does a quick nmap scan focused on hostname resolution
func (s *PingSweepService) tryNmapHostnameScan(ip string) string {
	// Validate IP address first
	if err := s.Validator.ValidateIPAddress(ip); err != nil {
		log.Printf("Invalid IP address for hostname scan: %v", err)
		return ""
	}
	
	// Quick hostname-focused scan
	args := []string{"nmap", "-sn", "-R", "--system-dns", "-oX", "-", ip}
	if err := s.Validator.SanitizeCommandArgs(args); err != nil {
		log.Printf("Command validation failed for hostname scan: %v", err)
		return ""
	}
	
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	
	// Parse the XML output for hostname
	devices := s.DeviceService.ParseFromNmapXML(string(output))
	if len(devices) > 0 && devices[0].Hostname != nil && *devices[0].Hostname != "" {
		return *devices[0].Hostname
	}
	
	return ""
}

// tryDNSReverseLookup attempts reverse DNS lookup with timeout
func (s *PingSweepService) tryDNSReverseLookup(ip string) string {
	// Validate IP address first
	if err := s.Validator.ValidateIPAddress(ip); err != nil {
		return ""
	}
	
	// Try using nslookup with a short timeout
	args := []string{"timeout", "2", "nslookup", ip}
	if err := s.Validator.SanitizeCommandArgs(args); err != nil {
		return ""
	}
	
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	
	// Parse hostname from nslookup output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "name =") {
			parts := strings.Split(line, "name =")
			if len(parts) > 1 {
				hostname := strings.TrimSpace(parts[1])
				hostname = strings.TrimSuffix(hostname, ".") // Remove trailing dot
				if hostname != "" && !strings.Contains(hostname, "NXDOMAIN") {
					return hostname
				}
			}
		}
	}
	
	return ""
}

// tryDigReverseLookup attempts reverse DNS lookup using dig
func (s *PingSweepService) tryDigReverseLookup(ip string) string {
	// Validate IP address first
	if err := s.Validator.ValidateIPAddress(ip); err != nil {
		return ""
	}
	
	// Try using dig with a short timeout for reverse lookup
	args := []string{"timeout", "2", "dig", "+short", "-x", ip}
	if err := s.Validator.SanitizeCommandArgs(args); err != nil {
		return ""
	}
	
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	
	hostname := strings.TrimSpace(string(output))
	hostname = strings.TrimSuffix(hostname, ".") // Remove trailing dot
	
	if hostname != "" && !strings.Contains(hostname, "NXDOMAIN") && hostname != ip {
		return hostname
	}
	
	return ""
}

// startPortScanWorkers starts background workers for port scanning
func (s *PingSweepService) startPortScanWorkers(numWorkers int) {
	log.Printf("Starting %d port scan workers", numWorkers)
	
	for i := 0; i < numWorkers; i++ {
		s.portScanWorkers.Add(1)
		go s.portScanWorker(i)
	}
}

// portScanWorker continuously processes devices from the port scan queue
func (s *PingSweepService) portScanWorker(workerID int) {
	defer s.portScanWorkers.Done()
	
	log.Printf("Port scan worker %d started", workerID)
	
	for device := range s.portScanQueue {
		log.Printf("Worker %d: Starting port scan for device %s", workerID, device.IPv4)
		s.PortScanService.Run(device)
		log.Printf("Worker %d: Completed port scan for device %s", workerID, device.IPv4)
	}
	
	log.Printf("Port scan worker %d stopped", workerID)
}
