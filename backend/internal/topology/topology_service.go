package topology

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"reconya-ai/db"
	"reconya-ai/internal/config"
	"reconya-ai/internal/validation"
	"reconya-ai/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type TopologyService struct {
	Config              *config.Config
	Validator           *validation.NetworkValidator
	TopologyRepo        db.TopologyRepository
	GatewayRepo         db.GatewayRepository
	DiscoveryTimeout    time.Duration
	TracerouteTimeout   time.Duration
	MaxHops             int
}

func NewTopologyService(cfg *config.Config, dbManager *db.DBManager) *TopologyService {
	return &TopologyService{
		Config:            cfg,
		Validator:         validation.NewNetworkValidator(),
		TopologyRepo:      db.NewSQLiteTopologyRepository(dbManager.GetDB()),
		GatewayRepo:       db.NewSQLiteGatewayRepository(dbManager.GetDB()),
		DiscoveryTimeout:  30 * time.Second,
		TracerouteTimeout: 60 * time.Second,
		MaxHops:           30,
	}
}

// DiscoverNetworkTopology performs comprehensive network topology discovery
func (s *TopologyService) DiscoverNetworkTopology(ctx context.Context) (*models.NetworkTopology, error) {
	log.Printf("Starting network topology discovery")
	startTime := time.Now()

	topology := &models.NetworkTopology{
		LocalSubnet:      s.getLocalSubnet(),
		DiscoveredRoutes: []models.NetworkRoute{},
		Gateways:         []models.Gateway{},
		HopCounts:        make(map[string]int),
		LastDiscovered:   time.Now(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Discover routes from system routing table
	routes, err := s.discoverRoutes(ctx)
	if err != nil {
		log.Printf("Error discovering routes: %v", err)
	} else {
		topology.DiscoveredRoutes = append(topology.DiscoveredRoutes, routes...)
	}

	// Discover gateways
	gateways, err := s.discoverGateways(ctx)
	if err != nil {
		log.Printf("Error discovering gateways: %v", err)
	} else {
		topology.Gateways = gateways
	}

	// Test reachability and measure hop counts for configured subnets
	configuredSubnets := s.parseConfiguredSubnets()
	for _, subnet := range configuredSubnets {
		hopCount, reachable := s.measureHopCount(ctx, subnet)
		topology.HopCounts[subnet] = hopCount
		
		// Add route information if not already present
		s.addRouteIfMissing(topology, subnet, hopCount, reachable)
	}

	// Discover additional subnets via traceroute to key destinations
	additionalSubnets := s.discoverSubnetsViaTraceroute(ctx, gateways)
	for subnet, hopCount := range additionalSubnets {
		if _, exists := topology.HopCounts[subnet]; !exists {
			topology.HopCounts[subnet] = hopCount
		}
	}

	duration := time.Since(startTime)
	log.Printf("Network topology discovery completed in %v. Found %d routes, %d gateways, %d subnets",
		duration, len(topology.DiscoveredRoutes), len(topology.Gateways), len(topology.HopCounts))

	return topology, nil
}

// discoverRoutes discovers network routes from the system routing table
func (s *TopologyService) discoverRoutes(ctx context.Context) ([]models.NetworkRoute, error) {
	log.Printf("Discovering network routes from routing table")

	// Use 'ip route' command on Linux/Alpine
	cmd := exec.CommandContext(ctx, "ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to 'route' command
		cmd = exec.CommandContext(ctx, "route", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get routing table: %w", err)
		}
	}

	return s.parseRoutingTable(string(output))
}

// parseRoutingTable parses routing table output into NetworkRoute structs
func (s *TopologyService) parseRoutingTable(output string) ([]models.NetworkRoute, error) {
	var routes []models.NetworkRoute
	lines := strings.Split(output, "\n")

	// Regex for 'ip route' format
	ipRouteRegex := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+/\d+|\d+\.\d+\.\d+\.\d+|default)\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:\s+dev\s+(\w+))?(?:\s+metric\s+(\d+))?`)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := ipRouteRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			destination := matches[1]
			gateway := matches[2]
			iface := ""
			metric := 0

			if len(matches) > 3 && matches[3] != "" {
				iface = matches[3]
			}
			if len(matches) > 4 && matches[4] != "" {
				if m, err := strconv.Atoi(matches[4]); err == nil {
					metric = m
				}
			}

			// Convert 'default' to 0.0.0.0/0
			if destination == "default" {
				destination = "0.0.0.0/0"
			}

			// Ensure destination has CIDR notation
			if !strings.Contains(destination, "/") {
				destination += "/32"
			}

			route := models.NetworkRoute{
				Destination:     destination,
				Gateway:         gateway,
				Interface:       iface,
				Metric:          metric,
				HopCount:        1, // Will be updated by traceroute
				IsReachable:     true,
				LastTested:      time.Now(),
				DiscoveryMethod: string(models.DiscoveryMethodRouteTable),
			}

			routes = append(routes, route)
		}
	}

	log.Printf("Parsed %d routes from routing table", len(routes))
	return routes, nil
}

// discoverGateways discovers network gateways
func (s *TopologyService) discoverGateways(ctx context.Context) ([]models.Gateway, error) {
	log.Printf("Discovering network gateways")

	gateways := make(map[string]*models.Gateway)

	// Get default gateway
	defaultGW, err := s.getDefaultGateway(ctx)
	if err != nil {
		log.Printf("Error getting default gateway: %v", err)
	} else if defaultGW != "" {
		gateway := &models.Gateway{
			IPAddress:    defaultGW,
			IsDefault:    true,
			HopDistance:  1,
			Subnets:      []string{},
			LastSeen:     time.Now(),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		// Try to get MAC address and vendor info
		s.enhanceGatewayInfo(ctx, gateway)
		gateways[defaultGW] = gateway
	}

	// Discover additional gateways from ARP table
	arpGateways, err := s.discoverGatewaysFromARP(ctx)
	if err != nil {
		log.Printf("Error discovering gateways from ARP: %v", err)
	} else {
		for _, gw := range arpGateways {
			if existing, exists := gateways[gw.IPAddress]; exists {
				// Merge information
				if gw.MACAddress != "" {
					existing.MACAddress = gw.MACAddress
				}
				if gw.Vendor != "" {
					existing.Vendor = gw.Vendor
				}
			} else {
				gateways[gw.IPAddress] = gw
			}
		}
	}

	// Convert map to slice
	var result []models.Gateway
	for _, gw := range gateways {
		result = append(result, *gw)
	}

	log.Printf("Discovered %d gateways", len(result))
	return result, nil
}

// getDefaultGateway gets the default gateway IP address
func (s *TopologyService) getDefaultGateway(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse: default via 192.168.1.1 dev eth0
	re := regexp.MustCompile(`default via (\d+\.\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("default gateway not found")
}

// discoverGatewaysFromARP discovers potential gateways from ARP table
func (s *TopologyService) discoverGatewaysFromARP(ctx context.Context) ([]*models.Gateway, error) {
	cmd := exec.CommandContext(ctx, "arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var gateways []*models.Gateway
	lines := strings.Split(string(output), "\n")

	// Parse ARP entries: gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
	re := regexp.MustCompile(`(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([a-fA-F0-9:]{17})`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 3 {
			hostname := matches[1]
			ip := matches[2]
			mac := matches[3]

			// Only consider devices that might be gateways (usually ending in .1, .254, etc.)
			if s.isLikelyGateway(ip) {
				gateway := &models.Gateway{
					IPAddress:   ip,
					MACAddress:  mac,
					Hostname:    hostname,
					IsDefault:   false,
					HopDistance: 1,
					Subnets:     []string{},
					LastSeen:    time.Now(),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}

				// Get vendor from MAC
				gateway.Vendor = s.getVendorFromMAC(mac)
				gateways = append(gateways, gateway)
			}
		}
	}

	return gateways, nil
}

// isLikelyGateway checks if an IP address is likely to be a gateway
func (s *TopologyService) isLikelyGateway(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	lastOctet := parts[3]
	// Common gateway addresses
	return lastOctet == "1" || lastOctet == "254" || lastOctet == "253" || lastOctet == "250"
}

// measureHopCount measures the hop count to reach a subnet
func (s *TopologyService) measureHopCount(ctx context.Context, subnet string) (int, bool) {
	// Extract first usable IP from subnet for testing
	testIP, err := s.getFirstUsableIP(subnet)
	if err != nil {
		return 0, false
	}

	log.Printf("Measuring hop count to subnet %s via %s", subnet, testIP)

	// Perform traceroute
	result, err := s.performTraceroute(ctx, testIP)
	if err != nil {
		log.Printf("Traceroute to %s failed: %v", testIP, err)
		// Fallback to ping test
		if s.pingTest(ctx, testIP) {
			return 1, true // Assume 1 hop if ping succeeds but traceroute fails
		}
		return 0, false
	}

	return result.TotalHops, result.Success
}

// performTraceroute performs a traceroute to the specified destination
func (s *TopologyService) performTraceroute(ctx context.Context, destination string) (*models.TracerouteResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, s.TracerouteTimeout)
	defer cancel()

	// Use traceroute command
	cmd := exec.CommandContext(timeoutCtx, "traceroute", "-n", "-m", strconv.Itoa(s.MaxHops), destination)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("traceroute failed: %w", err)
	}

	return s.parseTracerouteOutput(destination, string(output))
}

// parseTracerouteOutput parses traceroute output into a TracerouteResult
func (s *TopologyService) parseTracerouteOutput(destination, output string) (*models.TracerouteResult, error) {
	result := &models.TracerouteResult{
		Destination: destination,
		Hops:        []models.TracerouteHop{},
		Timestamp:   time.Now(),
	}

	lines := strings.Split(output, "\n")
	hopRegex := regexp.MustCompile(`^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+\.?\d*)\s*ms`)

	for _, line := range lines {
		matches := hopRegex.FindStringSubmatch(line)
		if len(matches) >= 4 {
			hopNum, _ := strconv.Atoi(matches[1])
			hopIP := matches[2]
			
			hop := models.TracerouteHop{
				HopNumber: hopNum,
				Timeout:   hopIP == "*",
			}

			if hopIP != "*" {
				hop.IPAddress = hopIP
				if responseTime, err := strconv.ParseFloat(matches[3], 64); err == nil {
					hop.ResponseTime = &responseTime
				}
			}

			result.Hops = append(result.Hops, hop)
			result.TotalHops = hopNum
		}
	}

	result.Success = len(result.Hops) > 0 && !result.Hops[len(result.Hops)-1].Timeout
	return result, nil
}

// getFirstUsableIP gets the first usable IP address from a subnet
func (s *TopologyService) getFirstUsableIP(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	// Get the first IP in the range
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 subnets supported")
	}

	// Increment to get first usable IP (skip network address)
	ip[3]++
	return ip.String(), nil
}

// pingTest performs a simple ping test to check reachability
func (s *TopologyService) pingTest(ctx context.Context, destination string) bool {
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", destination)
	err := cmd.Run()
	return err == nil
}

// parseConfiguredSubnets parses the configured network ranges
func (s *TopologyService) parseConfiguredSubnets() []string {
	if s.Config.NetworkCIDR == "" {
		return []string{}
	}

	ranges := strings.Split(s.Config.NetworkCIDR, ",")
	var subnets []string
	
	for _, r := range ranges {
		subnet := strings.TrimSpace(r)
		if subnet != "" {
			subnets = append(subnets, subnet)
		}
	}

	return subnets
}

// Helper methods
func (s *TopologyService) getLocalSubnet() string {
	// Get the local subnet by examining network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet.String()
				}
			}
		}
	}

	return ""
}

func (s *TopologyService) enhanceGatewayInfo(ctx context.Context, gateway *models.Gateway) {
	// Try to ping the gateway to get response time
	if responseTime := s.measureLatency(ctx, gateway.IPAddress); responseTime != nil {
		gateway.ResponseTime = responseTime
	}

	// Try to resolve hostname
	if hostname := s.resolveHostname(gateway.IPAddress); hostname != "" {
		gateway.Hostname = hostname
	}
}

func (s *TopologyService) measureLatency(ctx context.Context, ip string) *float64 {
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", ip)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse ping output for response time
	re := regexp.MustCompile(`time=(\d+\.?\d*)\s*ms`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		if latency, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return &latency
		}
	}

	return nil
}

func (s *TopologyService) resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func (s *TopologyService) getVendorFromMAC(mac string) string {
	// This would integrate with OUI lookup - simplified for now
	macPrefix := strings.ToUpper(strings.Replace(mac[:8], ":", "", -1))
	
	// Common vendor prefixes
	vendors := map[string]string{
		"00:1A:79": "Cisco",
		"00:0C:29": "VMware",
		"08:00:27": "VirtualBox",
		"00:50:56": "VMware",
		"00:1B:21": "Netgear",
		"BC:AE:C5": "Apple",
	}

	for prefix, vendor := range vendors {
		if strings.HasPrefix(mac, prefix) {
			return vendor
		}
	}

	return ""
}

func (s *TopologyService) addRouteIfMissing(topology *models.NetworkTopology, subnet string, hopCount int, reachable bool) {
	// Check if route already exists
	for _, route := range topology.DiscoveredRoutes {
		if route.Destination == subnet {
			return
		}
	}

	// Add new route
	route := models.NetworkRoute{
		Destination:     subnet,
		Gateway:         "", // Will be determined from traceroute
		HopCount:        hopCount,
		IsReachable:     reachable,
		LastTested:      time.Now(),
		DiscoveryMethod: string(models.DiscoveryMethodTraceroute),
	}

	topology.DiscoveredRoutes = append(topology.DiscoveredRoutes, route)
}

func (s *TopologyService) discoverSubnetsViaTraceroute(ctx context.Context, gateways []models.Gateway) map[string]int {
	subnets := make(map[string]int)

	// Traceroute to each gateway to discover intermediate networks
	for _, gateway := range gateways {
		result, err := s.performTraceroute(ctx, gateway.IPAddress)
		if err != nil {
			continue
		}

		// Analyze hops to discover subnets
		for _, hop := range result.Hops {
			if hop.IPAddress != "" && !hop.Timeout {
				subnet := s.getSubnetFromIP(hop.IPAddress)
				if subnet != "" {
					subnets[subnet] = hop.HopNumber
				}
			}
		}
	}

	return subnets
}

func (s *TopologyService) getSubnetFromIP(ip string) string {
	// Convert IP to /24 subnet (simplified)
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return ""
}

// DiscoverAndSaveTopology performs topology discovery and saves results to database
func (s *TopologyService) DiscoverAndSaveTopology(ctx context.Context) error {
	log.Printf("Starting topology discovery and persistence")
	
	// Discover topology
	topology, err := s.DiscoverNetworkTopology(ctx)
	if err != nil {
		return fmt.Errorf("topology discovery failed: %w", err)
	}

	// Save topology to database
	_, err = s.TopologyRepo.CreateOrUpdate(ctx, topology)
	if err != nil {
		return fmt.Errorf("failed to save topology: %w", err)
	}

	// Save individual gateways
	for i := range topology.Gateways {
		gateway := &topology.Gateways[i]
		_, err = s.GatewayRepo.CreateOrUpdate(ctx, gateway)
		if err != nil {
			log.Printf("Failed to save gateway %s: %v", gateway.IPAddress, err)
		}
	}

	log.Printf("Topology discovery and persistence completed successfully")
	return nil
}

// GetCurrentTopology returns the current network topology from database
func (s *TopologyService) GetCurrentTopology(ctx context.Context) (*models.NetworkTopology, error) {
	return s.TopologyRepo.FindLatest(ctx)
}

// GetTopologyStats returns statistics about the network topology
func (s *TopologyService) GetTopologyStats(ctx context.Context) (*models.TopologyStats, error) {
	return s.TopologyRepo.GetTopologyStats(ctx)
}

// GetAllGateways returns all discovered gateways
func (s *TopologyService) GetAllGateways(ctx context.Context) ([]*models.Gateway, error) {
	return s.GatewayRepo.FindAll(ctx)
}

// GetDefaultGateway returns the default gateway
func (s *TopologyService) GetDefaultGateway(ctx context.Context) (*models.Gateway, error) {
	return s.GatewayRepo.FindDefault(ctx)
}

// UpdateSubnetReachability updates reachability information for discovered subnets
func (s *TopologyService) UpdateSubnetReachability(ctx context.Context, subnetCounts map[string]int) error {
	topology, err := s.GetCurrentTopology(ctx)
	if err != nil {
		return err
	}

	// Update device counts for each subnet based on actual discovered devices
	for subnet, deviceCount := range subnetCounts {
		if hopCount, exists := topology.HopCounts[subnet]; exists {
			log.Printf("Subnet %s: %d hops, %d devices discovered", subnet, hopCount, deviceCount)
		}
	}

	return nil
}

// RunPeriodicDiscovery runs topology discovery at regular intervals
func (s *TopologyService) RunPeriodicDiscovery(ctx context.Context, interval time.Duration) {
	log.Printf("Starting periodic topology discovery every %v", interval)
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial discovery
	if err := s.DiscoverAndSaveTopology(ctx); err != nil {
		log.Printf("Initial topology discovery failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("Topology discovery stopped")
			return
		case <-ticker.C:
			if err := s.DiscoverAndSaveTopology(ctx); err != nil {
				log.Printf("Periodic topology discovery failed: %v", err)
			}
		}
	}
}

// Close closes repository connections
func (s *TopologyService) Close() error {
	if s.TopologyRepo != nil {
		s.TopologyRepo.Close()
	}
	if s.GatewayRepo != nil {
		s.GatewayRepo.Close()
	}
	return nil
}