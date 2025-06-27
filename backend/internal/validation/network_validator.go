package validation

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// NetworkValidator provides validation for network-related inputs to prevent command injection
type NetworkValidator struct {
	// Allowed CIDR patterns - restrictive whitelist approach
	cidrPattern *regexp.Regexp
	// Allowed IP patterns
	ipPattern *regexp.Regexp
	// Forbidden patterns that could be used for injection
	forbiddenPatterns []*regexp.Regexp
}

// NewNetworkValidator creates a new network validator with secure patterns
func NewNetworkValidator() *NetworkValidator {
	// CIDR pattern: only allow standard CIDR notation (IP/mask)
	cidrPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	
	// IP pattern: only allow standard IPv4 addresses
	ipPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	
	// Forbidden patterns that could be used for command injection
	forbiddenPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[;&|$\(\)\[\]{}\\<>*?'"` + "`" + `]`), // Shell metacharacters
		regexp.MustCompile(`\s`),                                  // Whitespace
		regexp.MustCompile(`--`),                                  // Command line options
		regexp.MustCompile(`^-`),                                  // Commands starting with dash
		regexp.MustCompile(`\.\./`),                               // Path traversal
		regexp.MustCompile(`[a-zA-Z]`),                            // Letters (IPs should only have numbers, dots, slashes)
	}
	
	return &NetworkValidator{
		cidrPattern:       cidrPattern,
		ipPattern:         ipPattern,
		forbiddenPatterns: forbiddenPatterns,
	}
}

// ValidateNetworkRange validates a network range (CIDR notation) for safety
func (v *NetworkValidator) ValidateNetworkRange(networkRange string) error {
	if networkRange == "" {
		return fmt.Errorf("network range cannot be empty")
	}
	
	// Check for forbidden patterns first
	for _, pattern := range v.forbiddenPatterns {
		if pattern.MatchString(networkRange) {
			return fmt.Errorf("network range contains invalid characters: %s", networkRange)
		}
	}
	
	// Split by comma for multiple networks
	networks := strings.Split(networkRange, ",")
	if len(networks) > 10 { // Limit number of networks to prevent DoS
		return fmt.Errorf("too many networks specified (max 10): %d", len(networks))
	}
	
	for _, network := range networks {
		network = strings.TrimSpace(network)
		if err := v.validateSingleNetwork(network); err != nil {
			return fmt.Errorf("invalid network '%s': %w", network, err)
		}
	}
	
	return nil
}

// ValidateIPAddress validates a single IP address for safety
func (v *NetworkValidator) ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	
	// Check for forbidden patterns
	for _, pattern := range v.forbiddenPatterns {
		if pattern.MatchString(ip) {
			return fmt.Errorf("IP address contains invalid characters: %s", ip)
		}
	}
	
	// Check pattern match
	if !v.ipPattern.MatchString(ip) {
		return fmt.Errorf("IP address format invalid: %s", ip)
	}
	
	// Parse and validate with Go's net package
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("IP address parsing failed: %s", ip)
	}
	
	// Ensure it's IPv4
	if parsedIP.To4() == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", ip)
	}
	
	return nil
}

// validateSingleNetwork validates a single CIDR network
func (v *NetworkValidator) validateSingleNetwork(network string) error {
	// Check pattern match
	if !v.cidrPattern.MatchString(network) {
		return fmt.Errorf("CIDR format invalid: %s", network)
	}
	
	// Parse and validate with Go's net package
	_, _, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("CIDR parsing failed: %w", err)
	}
	
	// Additional checks for reasonable networks
	ip, ipNet, _ := net.ParseCIDR(network)
	
	// Check if it's a valid IPv4 network
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 networks are supported: %s", network)
	}
	
	// Check for reasonable subnet sizes (prevent scanning the entire internet)
	ones, bits := ipNet.Mask.Size()
	if ones < 8 { // Larger than /8 (16M addresses)
		return fmt.Errorf("network too large (minimum /8): %s", network)
	}
	if ones > bits {
		return fmt.Errorf("invalid subnet mask: %s", network)
	}
	
	return nil
}

// SanitizeNetworkRanges validates and returns sanitized network ranges
func (v *NetworkValidator) SanitizeNetworkRanges(networkRange string) ([]string, error) {
	if err := v.ValidateNetworkRange(networkRange); err != nil {
		return nil, err
	}
	
	networks := strings.Split(networkRange, ",")
	sanitized := make([]string, 0, len(networks))
	
	for _, network := range networks {
		network = strings.TrimSpace(network)
		// Double-check each network is valid
		if err := v.validateSingleNetwork(network); err != nil {
			return nil, err
		}
		sanitized = append(sanitized, network)
	}
	
	return sanitized, nil
}

// SanitizeCommandArgs validates command arguments for nmap execution
func (v *NetworkValidator) SanitizeCommandArgs(args []string) error {
	// Whitelist of allowed nmap arguments
	allowedArgs := map[string]bool{
		"nmap":         true,
		"sudo":         true,
		"timeout":      true,
		"nslookup":     true,
		"dig":          true,
		"-sn":          true,
		"-sS":          true,
		"-sT":          true,
		"-sU":          true,
		"-PR":          true,
		"-PS80,443,22,21,23,25,53,110,111,135,139,143,993,995": true,
		"--send-ip":    true,
		"-T4":          true,
		"-T3":          true,
		"-T2":          true,
		"-R":           true,
		"--system-dns": true,
		"-oX":          true,
		"-":            true,
		"+short":       true,
		"-x":           true,
		"2":            true, // timeout value
	}
	
	// Dangerous patterns that should never appear in any argument
	dangerousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[;&|$\(\)\[\]{}\\<>*?'"` + "`" + `]`), // Shell metacharacters
		regexp.MustCompile(`\.\./`),                               // Path traversal
	}
	
	for i, arg := range args {
		// Check for dangerous patterns in all arguments
		for _, pattern := range dangerousPatterns {
			if pattern.MatchString(arg) {
				return fmt.Errorf("command argument contains dangerous characters: %s", arg)
			}
		}
		
		// IP addresses and network ranges get special validation
		if i > 0 && (v.ipPattern.MatchString(arg) || v.cidrPattern.MatchString(arg)) {
			// These are validated separately by the calling code
			continue
		}
		
		// Check if argument is in whitelist
		if !allowedArgs[arg] {
			// Check for port ranges in PS arguments
			if strings.HasPrefix(arg, "-PS") && v.isValidPortList(arg[3:]) {
				continue
			}
			return fmt.Errorf("disallowed command argument: %s", arg)
		}
	}
	
	return nil
}

// isValidPortList validates a comma-separated list of ports
func (v *NetworkValidator) isValidPortList(portList string) bool {
	portPattern := regexp.MustCompile(`^[\d,]+$`)
	return portPattern.MatchString(portList)
}