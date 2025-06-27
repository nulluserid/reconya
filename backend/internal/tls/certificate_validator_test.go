package tls

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateValidator_NewCertificateValidator(t *testing.T) {
	timeout := 10 * time.Second
	validator := NewCertificateValidator(timeout)
	
	assert.NotNil(t, validator)
	assert.Equal(t, timeout, validator.timeout)
}

func TestCertificateValidator_ValidateValidCert(t *testing.T) {
	validator := NewCertificateValidator(10 * time.Second)
	
	// Test with a known good certificate (Google)
	result := validator.ValidateAndExtractCertificate("google.com", 443)
	
	if result != nil {
		assert.True(t, result.IsValid)
		assert.Empty(t, result.ValidationErrors)
		assert.NotEmpty(t, result.CertificateChain)
		assert.Equal(t, "google.com", result.ConnectionInfo.ServerName)
		
		// Check first certificate in chain
		if len(result.CertificateChain) > 0 {
			cert := result.CertificateChain[0]
			assert.NotEmpty(t, cert.Subject)
			assert.NotEmpty(t, cert.Issuer)
			assert.NotEmpty(t, cert.Thumbprint)
			assert.False(t, cert.NotAfter.IsZero())
			assert.False(t, cert.NotBefore.IsZero())
		}
	} else {
		t.Skip("Unable to connect to google.com - skipping certificate validation test")
	}
}

func TestCertificateValidator_ValidateInvalidCert(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Test with a known self-signed certificate site (should fail validation but still get cert info)
	result := validator.ValidateAndExtractCertificate("self-signed.badssl.com", 443)
	
	if result != nil {
		assert.False(t, result.IsValid)
		assert.NotEmpty(t, result.ValidationErrors)
		assert.NotEmpty(t, result.CertificateChain)
		
		// Should still extract certificate information even for invalid certs
		if len(result.CertificateChain) > 0 {
			cert := result.CertificateChain[0]
			assert.NotEmpty(t, cert.Subject)
			assert.NotEmpty(t, cert.Thumbprint)
		}
	} else {
		t.Skip("Unable to connect to test site - skipping invalid certificate test")
	}
}

func TestCertificateValidator_ConnectionTimeout(t *testing.T) {
	validator := NewCertificateValidator(100 * time.Millisecond) // Very short timeout
	
	// Test with a non-existent host that should timeout
	result := validator.ValidateAndExtractCertificate("192.0.2.1", 443) // RFC5737 test address
	
	assert.Nil(t, result) // Should return nil on timeout/connection failure
}

func TestCertificateValidator_NonExistentHost(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Test with a non-existent hostname
	result := validator.ValidateAndExtractCertificate("this-host-does-not-exist.invalid", 443)
	
	assert.Nil(t, result) // Should return nil for non-existent hosts
}

func TestCertificateValidator_NonTLSPort(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Test with a non-TLS port (HTTP)
	result := validator.ValidateAndExtractCertificate("google.com", 80)
	
	assert.Nil(t, result) // Should return nil for non-TLS connections
}

func TestCertificateValidator_TLSVersionString(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0300, "Unknown (768)"},
	}
	
	for _, test := range tests {
		result := validator.tlsVersionString(test.version)
		assert.Equal(t, test.expected, result)
	}
}

func TestCertificateValidator_KeyUsageToStrings(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Test individual key usages
	result := validator.keyUsageToStrings(1) // DigitalSignature
	assert.Contains(t, result, "Digital Signature")
	
	result = validator.keyUsageToStrings(2) // ContentCommitment
	assert.Contains(t, result, "Content Commitment")
	
	result = validator.keyUsageToStrings(4) // KeyEncipherment
	assert.Contains(t, result, "Key Encipherment")
	
	// Test combined usages
	result = validator.keyUsageToStrings(1 | 4) // DigitalSignature | KeyEncipherment
	assert.Contains(t, result, "Digital Signature")
	assert.Contains(t, result, "Key Encipherment")
	assert.Len(t, result, 2)
}

func TestCertificateValidator_ExtKeyUsageToStrings(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Use actual x509.ExtKeyUsage constants
	result := validator.extKeyUsageToStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	assert.Contains(t, result, "Server Authentication")
	
	result = validator.extKeyUsageToStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	assert.Contains(t, result, "Client Authentication")
	
	result = validator.extKeyUsageToStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
	assert.Contains(t, result, "Code Signing")
	
	// Test multiple usages
	result = validator.extKeyUsageToStrings([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	assert.Contains(t, result, "Server Authentication")
	assert.Contains(t, result, "Client Authentication")
	assert.Len(t, result, 2)
}

func TestCertificateValidator_CipherSuiteString(t *testing.T) {
	validator := NewCertificateValidator(5 * time.Second)
	
	// Test known cipher suites
	result := validator.cipherSuiteString(0x002F) // TLS_RSA_WITH_AES_128_CBC_SHA
	assert.Equal(t, "TLS_RSA_WITH_AES_128_CBC_SHA", result)
	
	result = validator.cipherSuiteString(0x009C) // TLS_RSA_WITH_AES_128_GCM_SHA256
	assert.Equal(t, "TLS_RSA_WITH_AES_128_GCM_SHA256", result)
	
	// Test unknown cipher suite
	result = validator.cipherSuiteString(0xFFFF)
	assert.Equal(t, "Unknown (65535)", result)
}