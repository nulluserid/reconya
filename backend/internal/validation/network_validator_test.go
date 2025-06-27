package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNetworkValidator(t *testing.T) {
	validator := NewNetworkValidator()
	
	assert.NotNil(t, validator)
	assert.NotNil(t, validator.cidrPattern)
	assert.NotNil(t, validator.ipPattern)
	assert.NotNil(t, validator.forbiddenPatterns)
}

func TestValidateNetworkRange_Valid(t *testing.T) {
	validator := NewNetworkValidator()
	
	validRanges := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/16",
		"192.168.1.0/24,10.0.0.0/8",
	}
	
	for _, network := range validRanges {
		err := validator.ValidateNetworkRange(network)
		assert.NoError(t, err, "Network %s should be valid", network)
	}
}

func TestValidateNetworkRange_Invalid(t *testing.T) {
	validator := NewNetworkValidator()
	
	invalidRanges := []string{
		"",
		"192.168.1.0",
		"192.168.1.0/33",
		"300.168.1.0/24",
		"192.168.1.0/24; rm -rf /",
		"192.168.1.0/7",
	}
	
	for _, network := range invalidRanges {
		err := validator.ValidateNetworkRange(network)
		assert.Error(t, err, "Network %s should be invalid", network)
	}
}

func TestValidateIPAddress_Valid(t *testing.T) {
	validator := NewNetworkValidator()
	
	validIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"127.0.0.1",
	}
	
	for _, ip := range validIPs {
		err := validator.ValidateIPAddress(ip)
		assert.NoError(t, err, "IP %s should be valid", ip)
	}
}

func TestValidateIPAddress_Invalid(t *testing.T) {
	validator := NewNetworkValidator()
	
	invalidIPs := []string{
		"",
		"192.168.1",
		"300.168.1.1",
		"192.168.1.1; rm -rf /",
		"localhost",
	}
	
	for _, ip := range invalidIPs {
		err := validator.ValidateIPAddress(ip)
		assert.Error(t, err, "IP %s should be invalid", ip)
	}
}

func TestSanitizeCommandArgs_Valid(t *testing.T) {
	validator := NewNetworkValidator()
	
	validArgs := [][]string{
		{"nmap", "-sn", "192.168.1.0/24"},
		{"sudo", "nmap", "-sT", "10.0.0.1"},
	}
	
	for _, args := range validArgs {
		err := validator.SanitizeCommandArgs(args)
		assert.NoError(t, err, "Args %v should be valid", args)
	}
}

func TestSanitizeCommandArgs_Invalid(t *testing.T) {
	validator := NewNetworkValidator()
	
	invalidArgs := [][]string{
		{"nmap", "-sn", "192.168.1.0/24; rm -rf /"},
		{"rm", "-rf", "/"},
	}
	
	for _, args := range invalidArgs {
		err := validator.SanitizeCommandArgs(args)
		assert.Error(t, err, "Args %v should be invalid", args)
	}
}