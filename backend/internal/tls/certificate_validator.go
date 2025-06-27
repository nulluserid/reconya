package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertificateInfo contains detailed information about an SSL/TLS certificate
type CertificateInfo struct {
	Subject         string
	Issuer          string
	SerialNumber    string
	Thumbprint      string
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	IPAddresses     []string
	IsCA            bool
	IsSelfSigned    bool
	KeyUsage        []string
	ExtKeyUsage     []string
	SignatureAlg    string
	PublicKeyAlg    string
	Version         int
}

// CertificateValidationResult contains the validation outcome and certificate details
type CertificateValidationResult struct {
	IsValid           bool
	ValidationErrors  []string
	CertificateChain  []CertificateInfo
	ConnectionInfo    ConnectionInfo
}

// ConnectionInfo contains details about the TLS connection
type ConnectionInfo struct {
	TLSVersion    string
	CipherSuite   string
	ServerName    string
	PeerCerts     int
	Protocol      string
}

// CertificateValidator handles TLS certificate validation and information extraction
type CertificateValidator struct {
	timeout time.Duration
}

// NewCertificateValidator creates a new certificate validator with specified timeout
func NewCertificateValidator(timeout time.Duration) *CertificateValidator {
	return &CertificateValidator{
		timeout: timeout,
	}
}

// ValidateAndExtractCertificate validates a certificate and extracts detailed information
// This method will attempt validation first, then retry with InsecureSkipVerify if needed
func (cv *CertificateValidator) ValidateAndExtractCertificate(host string, port int) *CertificateValidationResult {
	address := fmt.Sprintf("%s:%d", host, port)
	
	// First attempt: proper certificate validation
	result := cv.attemptConnection(address, false)
	if result != nil {
		return result
	}
	
	// Second attempt: skip verification to get certificate details anyway
	result = cv.attemptConnection(address, true)
	if result != nil {
		// Mark as invalid since we had to skip verification
		result.IsValid = false
		if len(result.ValidationErrors) == 0 {
			result.ValidationErrors = append(result.ValidationErrors, "Certificate validation failed - connection succeeded only with verification disabled")
		}
	}
	
	return result
}

// attemptConnection tries to establish a TLS connection with specified verification settings
func (cv *CertificateValidator) attemptConnection(address string, skipVerify bool) *CertificateValidationResult {
	// Configure TLS with or without verification
	config := &tls.Config{
		InsecureSkipVerify: skipVerify,
		ServerName:         strings.Split(address, ":")[0], // Extract hostname from address
	}
	
	// Set connection timeout
	dialer := &net.Dialer{
		Timeout: cv.timeout,
	}
	
	// Establish TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil
	}
	defer conn.Close()
	
	// Get connection state
	state := conn.ConnectionState()
	
	// Build result
	result := &CertificateValidationResult{
		IsValid:          !skipVerify, // If we needed to skip verify, it's invalid
		ValidationErrors: make([]string, 0),
		CertificateChain: make([]CertificateInfo, 0),
		ConnectionInfo: ConnectionInfo{
			TLSVersion:  cv.tlsVersionString(state.Version),
			CipherSuite: cv.cipherSuiteString(state.CipherSuite),
			ServerName:  state.ServerName,
			PeerCerts:   len(state.PeerCertificates),
			Protocol:    state.NegotiatedProtocol,
		},
	}
	
	// If we skipped verification, perform manual validation to get specific errors
	if skipVerify && len(state.PeerCertificates) > 0 {
		result.ValidationErrors = cv.validateCertificateManually(state.PeerCertificates[0], state.ServerName)
	}
	
	// Extract certificate information from the chain
	for _, cert := range state.PeerCertificates {
		certInfo := cv.extractCertificateInfo(cert)
		result.CertificateChain = append(result.CertificateChain, certInfo)
	}
	
	return result
}

// validateCertificateManually performs manual certificate validation to identify specific issues
func (cv *CertificateValidator) validateCertificateManually(cert *x509.Certificate, serverName string) []string {
	var errors []string
	
	// Check if certificate is expired
	now := time.Now()
	if cert.NotAfter.Before(now) {
		errors = append(errors, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02 15:04:05")))
	}
	
	// Check if certificate is not yet valid
	if cert.NotBefore.After(now) {
		errors = append(errors, fmt.Sprintf("Certificate not valid until %s", cert.NotBefore.Format("2006-01-02 15:04:05")))
	}
	
	// Check if certificate is self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		errors = append(errors, "Certificate is self-signed")
	}
	
	// Check hostname verification
	if serverName != "" {
		if err := cert.VerifyHostname(serverName); err != nil {
			errors = append(errors, fmt.Sprintf("Hostname verification failed: %v", err))
		}
	}
	
	// Check for weak signature algorithm
	weakAlgorithms := map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:  "MD2",
		x509.MD5WithRSA:  "MD5",
		x509.SHA1WithRSA: "SHA1",
	}
	if algName, isWeak := weakAlgorithms[cert.SignatureAlgorithm]; isWeak {
		errors = append(errors, fmt.Sprintf("Weak signature algorithm: %s", algName))
	}
	
	return errors
}

// extractCertificateInfo extracts detailed information from an x509 certificate
func (cv *CertificateValidator) extractCertificateInfo(cert *x509.Certificate) CertificateInfo {
	// Calculate thumbprint (SHA-256 hash of the certificate)
	thumbprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	
	// Extract IP addresses as strings
	ipAddresses := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddresses[i] = ip.String()
	}
	
	// Convert key usage to strings
	keyUsage := cv.keyUsageToStrings(cert.KeyUsage)
	extKeyUsage := cv.extKeyUsageToStrings(cert.ExtKeyUsage)
	
	return CertificateInfo{
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		SerialNumber:    cert.SerialNumber.String(),
		Thumbprint:      thumbprint,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DNSNames:        cert.DNSNames,
		IPAddresses:     ipAddresses,
		IsCA:            cert.IsCA,
		IsSelfSigned:    cert.Issuer.String() == cert.Subject.String(),
		KeyUsage:        keyUsage,
		ExtKeyUsage:     extKeyUsage,
		SignatureAlg:    cert.SignatureAlgorithm.String(),
		PublicKeyAlg:    cv.publicKeyAlgorithm(cert),
		Version:         cert.Version,
	}
}

// tlsVersionString converts TLS version number to readable string
func (cv *CertificateValidator) tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// cipherSuiteString converts cipher suite number to readable string
func (cv *CertificateValidator) cipherSuiteString(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown (%d)", suite)
	}
}

// keyUsageToStrings converts key usage flags to readable strings
func (cv *CertificateValidator) keyUsageToStrings(usage x509.KeyUsage) []string {
	var usages []string
	
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	
	return usages
}

// extKeyUsageToStrings converts extended key usage to readable strings
func (cv *CertificateValidator) extKeyUsageToStrings(usage []x509.ExtKeyUsage) []string {
	var usages []string
	
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown (%v)", u))
		}
	}
	
	return usages
}

// publicKeyAlgorithm extracts the public key algorithm from certificate
func (cv *CertificateValidator) publicKeyAlgorithm(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}