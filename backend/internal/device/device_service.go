package device

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"reconya-ai/db"
	"reconya-ai/internal/config"
	"reconya-ai/internal/fingerprint"
	"reconya-ai/internal/network"
	"reconya-ai/internal/oui"
	"reconya-ai/internal/util"
	"reconya-ai/models"
	"sort"
	"strings"
	"time"
)

type DeviceService struct {
	Config             *config.Config
	repository         db.DeviceRepository
	networkService     *network.NetworkService
	dbManager          *db.DBManager
	fingerprintService *fingerprint.FingerprintService
	ouiService         *oui.OUIService
}

func NewDeviceService(deviceRepo db.DeviceRepository, networkService *network.NetworkService, cfg *config.Config, dbManager *db.DBManager, ouiService *oui.OUIService) *DeviceService {
	return &DeviceService{
		Config:             cfg,
		repository:         deviceRepo,
		networkService:     networkService,
		dbManager:          dbManager,
		fingerprintService: fingerprint.NewFingerprintService(),
		ouiService:         ouiService,
	}
}

func (s *DeviceService) CreateOrUpdate(device *models.Device) (*models.Device, error) {
	currentTime := time.Now()
	device.LastSeenOnlineAt = &currentTime

	network, err := s.networkService.FindOrCreate(s.Config.NetworkCIDR)
	if err != nil {
		return nil, err
	}

	existingDevice, err := s.FindByIPv4(device.IPv4)
	if err != nil && err != db.ErrNotFound {
		return nil, err
	}

	s.setTimestamps(device, existingDevice, currentTime)

	// Set network ID
	device.NetworkID = network.ID

	// Set status if not already set
	if device.Status == "" {
		device.Status = models.DeviceStatusOnline
	}

	// Preserve name and comment if device already exists and incoming values are empty
	if existingDevice != nil {
		if device.Name == "" && existingDevice.Name != "" {
			device.Name = existingDevice.Name
		}
		if (device.Comment == nil || *device.Comment == "") && existingDevice.Comment != nil && *existingDevice.Comment != "" {
			device.Comment = existingDevice.Comment
		}
	}

	// Leave device name empty if not explicitly set

	// Use DB manager to serialize database access
	return s.dbManager.CreateOrUpdateDevice(s.repository, context.Background(), device)
}

func (s *DeviceService) setTimestamps(device, existingDevice *models.Device, currentTime time.Time) {
	if existingDevice == nil || existingDevice.CreatedAt.IsZero() {
		device.CreatedAt = currentTime
	} else {
		device.CreatedAt = existingDevice.CreatedAt
	}
	device.UpdatedAt = currentTime
}

func (s *DeviceService) ParseFromNmap(bufferStream string) []models.Device {
	log.Println("Starting Nmap parse")
	var devices []models.Device
	lines := strings.Split(bufferStream, "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "Nmap scan report for") {
			device := models.Device{}
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				ipAddress := strings.Trim(parts[len(parts)-1], "()")
				device.IPv4 = ipAddress

				if len(parts) == 6 {
					hostname := strings.Trim(parts[4], "()")
					if hostname != ipAddress {
						device.Hostname = &hostname
					} else {
						empty := ""
						device.Hostname = &empty
					}
				}

				if device.Hostname != nil {
					log.Printf("Found device - IP: %s, Hostname: %s", device.IPv4, *device.Hostname)
				} else {
					log.Printf("Found device - IP: %s, Hostname: <nil>", device.IPv4)
				}

			}

			if i+2 < len(lines) && strings.HasPrefix(lines[i+2], "MAC Address: ") {
				macParts := strings.Fields(lines[i+2])
				if len(macParts) >= 3 {
					mac := macParts[2]
					device.MAC = &mac
					log.Printf("Device MAC Address: %s", *device.MAC)
				}
			}

			devices = append(devices, device)
		}
	}

	log.Printf("Finished parsing Nmap output. Total devices found: %d", len(devices))
	return devices
}

func (s *DeviceService) ParseFromNmapXML(xmlOutput string) []models.Device {
	log.Println("Starting Nmap XML parse")
	var devices []models.Device
	var nmapXML models.NmapXML

	err := xml.Unmarshal([]byte(xmlOutput), &nmapXML)
	if err != nil {
		log.Printf("Error parsing Nmap XML output: %v", err)
		// Fallback to text parsing
		return s.ParseFromNmap(xmlOutput)
	}

	for _, host := range nmapXML.Hosts {
		device := models.Device{}
		var macAddress, vendor string

		// Extract IP address, MAC address, and vendor info
		for _, address := range host.Addresses {
			if address.AddrType == "ipv4" {
				device.IPv4 = address.Addr
			} else if address.AddrType == "mac" {
				macAddress = address.Addr
				vendor = address.Vendor
			}
		}

		// Skip if no IP address found
		if device.IPv4 == "" {
			continue
		}

		// Set MAC address if found
		if macAddress != "" {
			device.MAC = &macAddress
			log.Printf("Found MAC Address: %s for IP: %s", macAddress, device.IPv4)
		}

		// Set vendor info if found from Nmap
		if vendor != "" {
			device.Vendor = &vendor
			log.Printf("Found Vendor from Nmap: %s for IP: %s", vendor, device.IPv4)
		} else if macAddress != "" && s.ouiService != nil {
			// Fallback to OUI lookup if Nmap didn't provide vendor info
			if ouiVendor := s.ouiService.LookupVendor(macAddress); ouiVendor != "" {
				device.Vendor = &ouiVendor
				log.Printf("Found Vendor from OUI: %s for MAC: %s (IP: %s)", ouiVendor, macAddress, device.IPv4)
			}
		}

		// Extract hostname if available
		if len(host.Hostnames) > 0 && host.Hostnames[0].Name != "" {
			hostname := host.Hostnames[0].Name
			device.Hostname = &hostname
			log.Printf("Found Hostname: %s for IP: %s", hostname, device.IPv4)
		}

		log.Printf("Found device - IP: %s, MAC: %v, Vendor: %v, Hostname: %v",
			device.IPv4,
			func() string {
				if device.MAC != nil {
					return *device.MAC
				} else {
					return "<nil>"
				}
			}(),
			func() string {
				if device.Vendor != nil {
					return *device.Vendor
				} else {
					return "<nil>"
				}
			}(),
			func() string {
				if device.Hostname != nil {
					return *device.Hostname
				} else {
					return "<nil>"
				}
			}())

		devices = append(devices, device)
	}

	log.Printf("Finished parsing Nmap XML output. Total devices found: %d", len(devices))
	return devices
}

func (s *DeviceService) EligibleForPortScan(device *models.Device) bool {
	if device == nil {
		log.Println("Warning: Attempted to check port scan eligibility for a nil device")
		return false
	}

	now := time.Now()
	if device.PortScanEndedAt != nil && device.PortScanEndedAt.Add(30*time.Second).After(now) {
		return false
	}
	return true
}

func sortDevicesByIP(devices []models.Device) {
	sort.Slice(devices, func(i, j int) bool {
		ip1 := net.ParseIP(devices[i].IPv4)
		ip2 := net.ParseIP(devices[j].IPv4)
		return bytes.Compare(ip1, ip2) < 0
	})
}

func (s *DeviceService) FindAll() ([]models.Device, error) {
	ctx := context.Background()
	devices, err := s.repository.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values
	deviceValues := make([]models.Device, len(devices))
	for i, d := range devices {
		deviceValues[i] = *d
	}

	// Sort devices by IP address
	sortDevicesByIP(deviceValues)

	return deviceValues, nil
}

func (s *DeviceService) FindByID(deviceID string) (*models.Device, error) {
	ctx := context.Background()
	device, err := s.repository.FindByID(ctx, deviceID)
	if err == db.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		log.Printf("Error finding device with ID %s: %v", deviceID, err)
		return nil, err
	}
	return device, nil
}

func (s *DeviceService) FindByIPv4(ipv4 string) (*models.Device, error) {
	ctx := context.Background()
	device, err := s.repository.FindByIP(ctx, ipv4)
	if err == db.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		log.Printf("Error finding device with IPv4 %s: %v", ipv4, err)
		return nil, err
	}
	return device, nil
}

func (s *DeviceService) FindAllForNetwork(cidr string) ([]models.Device, error) {
	var deviceValues []models.Device

	network, err := s.networkService.FindByCIDR(cidr)
	if err != nil {
		return nil, err
	}

	if network == nil {
		return deviceValues, nil
	}
	// Get all devices first
	ctx := context.Background()
	allDevices, err := s.repository.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	// Filter devices by network ID
	for _, d := range allDevices {
		// Make sure we're comparing non-empty values
		if d.NetworkID != "" && network.ID != "" && d.NetworkID == network.ID {
			deviceValues = append(deviceValues, *d)
		} else if d.NetworkID == "" && network.ID != "" {
			// If device has no network ID but belongs to the current network
			// The device might be in this network but the ID wasn't saved
			// This is a workaround for existing data
			d.NetworkID = network.ID

			// Use retry logic for updating the device
			_, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
				return s.repository.CreateOrUpdate(context.Background(), d)
			})

			if err != nil {
				log.Printf("Error updating device network ID: %v", err)
			} else {
				deviceValues = append(deviceValues, *d)
			}
		} else {
			log.Printf("Skipping device %s (network ID mismatch)", d.IPv4)
		}
	}

	sortDevicesByIP(deviceValues)
	return deviceValues, nil
}

// FindOnlineDevicesForNetwork returns only devices that have been actually discovered online
func (s *DeviceService) FindOnlineDevicesForNetwork(cidr string) ([]models.Device, error) {
	network, err := s.networkService.FindByCIDR(cidr)
	if err != nil {
		return nil, err
	}

	if network == nil {
		return []models.Device{}, nil
	}

	// Get all devices first
	ctx := context.Background()
	allDevices, err := s.repository.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	var deviceValues []models.Device

	// Filter devices by network ID AND only include devices that have been seen online
	for _, d := range allDevices {
		// Skip devices that have never been seen online
		if d.LastSeenOnlineAt == nil {
			continue
		}

		// Show online and idle devices - only skip offline devices
		if d.Status == models.DeviceStatusOffline {
			continue
		}

		// Skip network and broadcast addresses
		if s.isNetworkOrBroadcastAddress(d.IPv4, cidr) {
			continue
		}

		// Check network membership
		shouldInclude := false
		if d.NetworkID != "" && network.ID != "" && d.NetworkID == network.ID {
			shouldInclude = true
		} else if d.NetworkID == "" && network.ID != "" {
			// If device has no network ID but belongs to the current network
			d.NetworkID = network.ID

			// Use retry logic for updating the device
			_, err := util.RetryOnLockWithResult(func() (*models.Device, error) {
				return s.repository.CreateOrUpdate(context.Background(), d)
			})

			if err != nil {
				log.Printf("Error updating device network ID: %v", err)
			}
			shouldInclude = true
		}

		if shouldInclude {
			deviceValues = append(deviceValues, *d)
		}
	}

	sortDevicesByIP(deviceValues)
	log.Printf("Filtered to %d active devices (online/idle)", len(deviceValues))
	return deviceValues, nil
}

// isNetworkOrBroadcastAddress checks if an IP is a network or broadcast address
func (s *DeviceService) isNetworkOrBroadcastAddress(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // Invalid IP, exclude it
	}

	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false // Can't parse CIDR, include the IP
	}

	// Check if it's the network address
	if ip.Equal(network.IP) {
		return true
	}

	// Check if it's the broadcast address
	// For IPv4, calculate the broadcast address
	if ip.To4() != nil {
		mask := network.Mask
		broadcast := make(net.IP, len(network.IP))
		for i := range network.IP {
			broadcast[i] = network.IP[i] | ^mask[i]
		}
		if ip.Equal(broadcast) {
			return true
		}
	}

	return false
}

func (s *DeviceService) UpdateDeviceStatuses() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use DB manager to serialize database access
	// Increased timeout to keep devices visible longer: 15 minutes total
	// This means: online -> idle after 7.5 minutes, idle/online -> offline after 15 minutes
	return s.dbManager.UpdateDeviceStatuses(s.repository, ctx, 15*time.Minute)
}

// PerformDeviceFingerprinting analyzes device characteristics to determine type and OS
func (s *DeviceService) UpdateDevice(deviceID string, name *string, comment *string) (*models.Device, error) {
	ctx := context.Background()

	device, err := s.repository.FindByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device not found: %v", err)
	}

	if name != nil {
		device.Name = *name
	}
	if comment != nil {
		device.Comment = comment
	}

	updatedDevice, err := s.repository.CreateOrUpdate(ctx, device)
	if err != nil {
		return nil, fmt.Errorf("failed to update device: %v", err)
	}

	return updatedDevice, nil
}

func (s *DeviceService) PerformDeviceFingerprinting(device *models.Device) {
	log.Printf("Starting device fingerprinting for %s", device.IPv4)
	s.fingerprintService.AnalyzeDevice(device)
}

// SaveCertificate saves a certificate using the certificate repository
func (s *DeviceService) SaveCertificate(certificate *models.Certificate) (*models.Certificate, error) {
	certRepo := db.NewSQLiteCertificateRepository(s.dbManager.GetDB())
	defer certRepo.Close()
	
	return certRepo.CreateOrUpdate(context.Background(), certificate)
}
