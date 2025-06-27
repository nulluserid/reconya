package certificate

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"reconya-ai/internal/config"
	"reconya-ai/internal/validation"
	"reconya-ai/models"
	"strconv"
	"strings"
	"time"
)

type CertificateService struct {
	Config        *config.Config
	Validator     *validation.NetworkValidator
	ScanTimeout   time.Duration
	ConnectTimeout time.Duration
}

func NewCertificateService(cfg *config.Config) *CertificateService {
	return &CertificateService{
		Config:         cfg,
		Validator:      validation.NewNetworkValidator(),
		ScanTimeout:    30 * time.Second,
		ConnectTimeout: 10 * time.Second,
	}
}

// ScanDeviceCertificates scans a device for SSL/TLS certificates on common ports
func (s *CertificateService) ScanDeviceCertificates(ctx context.Context, deviceIP string, ports []models.Port) ([]*models.Certificate, error) {
	// Validate IP address
	if err := s.Validator.ValidateIPAddress(deviceIP); err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	log.Printf("Starting certificate scan for device: %s", deviceIP)
	startTime := time.Now()

	var certificates []*models.Certificate
	var tlsPorts []int

	// Identify TLS/SSL ports from discovered ports
	for _, port := range ports {
		if s.isTLSPort(port) {
			if portNum, err := strconv.Atoi(port.Number); err == nil {
				tlsPorts = append(tlsPorts, portNum)
			}
		}
	}

	// Add common TLS ports if not found
	commonTLSPorts := []int{443, 8443, 993, 995, 465, 587, 636, 3389, 5986}
	for _, port := range commonTLSPorts {
		if !s.containsPort(tlsPorts, port) {
			tlsPorts = append(tlsPorts, port)
		}
	}

	log.Printf("Scanning %d potential TLS ports on %s: %v", len(tlsPorts), deviceIP, tlsPorts)

	// Scan each port for certificates
	for _, port := range tlsPorts {
		log.Printf("Scanning certificate on %s:%d", deviceIP, port)
		
		cert, err := s.scanPortCertificate(ctx, deviceIP, port)
		if err != nil {
			log.Printf("Certificate scan failed on %s:%d: %v", deviceIP, port, err)
			continue
		}

		if cert != nil {
			certificates = append(certificates, cert)
			log.Printf("Certificate found on %s:%d - Subject: %s, Issuer: %s, Expires: %s",
				deviceIP, port, cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))
		}
	}

	duration := time.Since(startTime)
	log.Printf("Certificate scan completed for %s in %v. Found %d certificates", deviceIP, duration, len(certificates))

	return certificates, nil
}

// scanPortCertificate scans a specific port for SSL/TLS certificates
func (s *CertificateService) scanPortCertificate(ctx context.Context, host string, port int) (*models.Certificate, error) {

	// Try to establish TLS connection
	dialer := &net.Dialer{
		Timeout: s.ConnectTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true, // We want to collect certificates even if invalid
		ServerName:         host,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	// Get connection state
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// Process the leaf certificate
	x509Cert := state.PeerCertificates[0]
	cert := &models.Certificate{
		Host:     host,
		Port:     port,
		Protocol: s.determineProtocol(port),
	}

	// Parse certificate data
	cert.ParseFromX509(x509Cert)

	// Add additional analysis
	s.enhanceCertificateData(cert, x509Cert, &state)

	// Set scanning metadata
	now := time.Now()
	cert.LastScanned = now
	cert.FirstSeen = now
	cert.CreatedAt = now
	cert.UpdatedAt = now

	return cert, nil
}

// enhanceCertificateData adds additional analysis to certificate data
func (s *CertificateService) enhanceCertificateData(cert *models.Certificate, x509Cert *x509.Certificate, state *tls.ConnectionState) {
	// Generate fingerprints
	cert.Thumbprint = s.generateSHA1Fingerprint(x509Cert.Raw)
	cert.ThumbprintSHA256 = s.generateSHA256Fingerprint(x509Cert.Raw)

	// Extract key size
	cert.KeySize = s.extractKeySize(x509Cert)

	// TLS connection information
	cert.TLSVersion = s.getTLSVersion(state.Version)
	cert.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Certificate chain
	if len(state.PeerCertificates) > 1 {
		for i, chainCert := range state.PeerCertificates[1:] {
			chainPEM := s.certificateToPEM(chainCert.Raw)
			cert.CertificateChain = append(cert.CertificateChain, chainPEM)
			log.Printf("Certificate chain [%d]: %s", i+1, chainCert.Subject.CommonName)
		}
	}

	// Validation
	cert.IsValid = s.validateCertificate(x509Cert)
	cert.ValidationErrors = s.getValidationErrors(x509Cert, cert.Host)

	// Security level
	cert.SecurityLevel = cert.CalculateSecurityLevel()

	// Certificate extensions
	cert.Extensions = s.extractExtensions(x509Cert)

	log.Printf("Certificate analysis complete - Security Level: %s, Key Size: %d, TLS: %s",
		cert.SecurityLevel, cert.KeySize, cert.TLSVersion)
}

// isTLSPort checks if a port likely supports TLS/SSL
func (s *CertificateService) isTLSPort(port models.Port) bool {
	portNum, err := strconv.Atoi(port.Number)
	if err != nil {
		return false
	}

	// Common TLS ports
	tlsPorts := map[int]bool{
		443:  true, // HTTPS
		8443: true, // Alternative HTTPS
		993:  true, // IMAPS
		995:  true, // POP3S
		465:  true, // SMTPS
		587:  true, // SMTP with STARTTLS
		636:  true, // LDAPS
		3389: true, // RDP
		5986: true, // WinRM HTTPS
		8080: true, // HTTP proxy (might support TLS)
		8008: true, // Alternative HTTP
		9443: true, // Alternative HTTPS
	}

	// Check if it's a known TLS port
	if tlsPorts[portNum] {
		return true
	}

	// Check service name for TLS indicators
	service := strings.ToLower(port.Service)
	tlsKeywords := []string{"https", "ssl", "tls", "secure", "imaps", "pop3s", "smtps", "ldaps"}
	for _, keyword := range tlsKeywords {
		if strings.Contains(service, keyword) {
			return true
		}
	}

	return false
}

// containsPort checks if a port is in the list
func (s *CertificateService) containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// determineProtocol determines the protocol based on port number
func (s *CertificateService) determineProtocol(port int) string {
	protocols := map[int]string{
		443:  "https",
		8443: "https",
		993:  "imaps",
		995:  "pop3s",
		465:  "smtps",
		587:  "smtp",
		636:  "ldaps",
		3389: "rdp",
		5986: "winrm",
	}

	if protocol, exists := protocols[port]; exists {
		return protocol
	}
	return "tls"
}

// generateSHA1Fingerprint generates SHA1 fingerprint
func (s *CertificateService) generateSHA1Fingerprint(certDER []byte) string {
	hash := sha1.Sum(certDER)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// generateSHA256Fingerprint generates SHA256 fingerprint
func (s *CertificateService) generateSHA256Fingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// extractKeySize extracts the key size from certificate
func (s *CertificateService) extractKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case *dsa.PublicKey:
		return pub.Y.BitLen()
	default:
		return 0
	}
}

// getTLSVersion converts TLS version number to string
func (s *CertificateService) getTLSVersion(version uint16) string {
	versions := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	if v, exists := versions[version]; exists {
		return v
	}
	return fmt.Sprintf("Unknown (%d)", version)
}

// validateCertificate performs basic certificate validation
func (s *CertificateService) validateCertificate(cert *x509.Certificate) bool {
	now := time.Now()
	
	// Check expiration
	if cert.NotAfter.Before(now) || cert.NotBefore.After(now) {
		return false
	}

	// Check basic constraints
	if cert.KeyUsage == 0 {
		return false
	}

	return true
}

// getValidationErrors returns validation errors for a certificate
func (s *CertificateService) getValidationErrors(cert *x509.Certificate, hostname string) []string {
	var errors []string
	now := time.Now()

	// Time validation
	if cert.NotAfter.Before(now) {
		errors = append(errors, "Certificate has expired")
	}
	if cert.NotBefore.After(now) {
		errors = append(errors, "Certificate is not yet valid")
	}

	// Hostname validation
	if err := cert.VerifyHostname(hostname); err != nil {
		errors = append(errors, fmt.Sprintf("Hostname verification failed: %v", err))
	}

	// Key size validation
	keySize := s.extractKeySize(cert)
	if keySize < models.MinimumKeySize && keySize > 0 {
		errors = append(errors, fmt.Sprintf("Weak key size: %d bits", keySize))
	}

	// Algorithm validation
	if strings.Contains(cert.SignatureAlgorithm.String(), "MD5") {
		errors = append(errors, "Weak signature algorithm: MD5")
	}
	if strings.Contains(cert.SignatureAlgorithm.String(), "SHA1") && !cert.IsCA {
		errors = append(errors, "Weak signature algorithm: SHA1")
	}

	return errors
}

// extractExtensions extracts certificate extensions
func (s *CertificateService) extractExtensions(cert *x509.Certificate) []models.CertExtension {
	var extensions []models.CertExtension

	for _, ext := range cert.Extensions {
		extensions = append(extensions, models.CertExtension{
			ID:       ext.Id.String(),
			Critical: ext.Critical,
			Value:    hex.EncodeToString(ext.Value),
		})
	}

	return extensions
}

// certificateToPEM converts certificate DER to PEM format
func (s *CertificateService) certificateToPEM(derBytes []byte) string {
	// This would encode to PEM format
	// For simplicity, returning hex for now
	return hex.EncodeToString(derBytes)
}

// QuickTLSCheck performs a quick check to see if a host:port supports TLS
func (s *CertificateService) QuickTLSCheck(ctx context.Context, host string, port int) bool {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}