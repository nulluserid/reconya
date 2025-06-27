package models

import (
	"crypto/x509"
	"time"
)

// Certificate represents an SSL/TLS certificate discovered during scanning
type Certificate struct {
	ID                string            `bson:"_id,omitempty" json:"id"`
	DeviceID          string            `bson:"device_id" json:"device_id"`
	Host              string            `bson:"host" json:"host"`
	Port              int               `bson:"port" json:"port"`
	Protocol          string            `bson:"protocol" json:"protocol"` // "https", "tls", "ssl"
	Subject           CertificateSubject `bson:"subject" json:"subject"`
	Issuer            CertificateIssuer  `bson:"issuer" json:"issuer"`
	SerialNumber      string            `bson:"serial_number" json:"serial_number"`
	Thumbprint        string            `bson:"thumbprint" json:"thumbprint"`         // SHA1 fingerprint
	ThumbprintSHA256  string            `bson:"thumbprint_sha256" json:"thumbprint_sha256"` // SHA256 fingerprint
	Version           int               `bson:"version" json:"version"`
	SignatureAlgorithm string           `bson:"signature_algorithm" json:"signature_algorithm"`
	PublicKeyAlgorithm string           `bson:"public_key_algorithm" json:"public_key_algorithm"`
	KeySize           int               `bson:"key_size,omitempty" json:"key_size,omitempty"`
	NotBefore         time.Time         `bson:"not_before" json:"not_before"`
	NotAfter          time.Time         `bson:"not_after" json:"not_after"`
	DNSNames          []string          `bson:"dns_names,omitempty" json:"dns_names,omitempty"`
	IPAddresses       []string          `bson:"ip_addresses,omitempty" json:"ip_addresses,omitempty"`
	EmailAddresses    []string          `bson:"email_addresses,omitempty" json:"email_addresses,omitempty"`
	URIs              []string          `bson:"uris,omitempty" json:"uris,omitempty"`
	Extensions        []CertExtension   `bson:"extensions,omitempty" json:"extensions,omitempty"`
	IsCA              bool              `bson:"is_ca" json:"is_ca"`
	IsSelfSigned      bool              `bson:"is_self_signed" json:"is_self_signed"`
	IsValid           bool              `bson:"is_valid" json:"is_valid"`
	IsExpired         bool              `bson:"is_expired" json:"is_expired"`
	IsExpiringSoon    bool              `bson:"is_expiring_soon" json:"is_expiring_soon"` // Within 30 days
	ValidationErrors  []string          `bson:"validation_errors,omitempty" json:"validation_errors,omitempty"`
	CertificateChain  []string          `bson:"certificate_chain,omitempty" json:"certificate_chain,omitempty"` // PEM encoded chain
	TLSVersion        string            `bson:"tls_version,omitempty" json:"tls_version,omitempty"`
	CipherSuite       string            `bson:"cipher_suite,omitempty" json:"cipher_suite,omitempty"`
	SecurityLevel     SecurityLevel     `bson:"security_level" json:"security_level"`
	LastScanned       time.Time         `bson:"last_scanned" json:"last_scanned"`
	FirstSeen         time.Time         `bson:"first_seen" json:"first_seen"`
	CreatedAt         time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time         `bson:"updated_at" json:"updated_at"`
}

// CertificateSubject represents the subject of a certificate
type CertificateSubject struct {
	CommonName         string   `bson:"common_name,omitempty" json:"common_name,omitempty"`
	Organization       []string `bson:"organization,omitempty" json:"organization,omitempty"`
	OrganizationalUnit []string `bson:"organizational_unit,omitempty" json:"organizational_unit,omitempty"`
	Country            []string `bson:"country,omitempty" json:"country,omitempty"`
	Province           []string `bson:"province,omitempty" json:"province,omitempty"`
	Locality           []string `bson:"locality,omitempty" json:"locality,omitempty"`
	StreetAddress      []string `bson:"street_address,omitempty" json:"street_address,omitempty"`
	PostalCode         []string `bson:"postal_code,omitempty" json:"postal_code,omitempty"`
}

// CertificateIssuer represents the issuer of a certificate
type CertificateIssuer struct {
	CommonName         string   `bson:"common_name,omitempty" json:"common_name,omitempty"`
	Organization       []string `bson:"organization,omitempty" json:"organization,omitempty"`
	OrganizationalUnit []string `bson:"organizational_unit,omitempty" json:"organizational_unit,omitempty"`
	Country            []string `bson:"country,omitempty" json:"country,omitempty"`
	Province           []string `bson:"province,omitempty" json:"province,omitempty"`
	Locality           []string `bson:"locality,omitempty" json:"locality,omitempty"`
}

// CertExtension represents a certificate extension
type CertExtension struct {
	ID       string `bson:"id" json:"id"`
	Critical bool   `bson:"critical" json:"critical"`
	Value    string `bson:"value,omitempty" json:"value,omitempty"`
}

// SecurityLevel represents the security level of a certificate
type SecurityLevel string

const (
	SecurityLevelUnknown  SecurityLevel = "unknown"
	SecurityLevelWeak     SecurityLevel = "weak"     // Weak algorithms, short keys
	SecurityLevelFair     SecurityLevel = "fair"     // Adequate but not recommended
	SecurityLevelGood     SecurityLevel = "good"     // Good security
	SecurityLevelStrong   SecurityLevel = "strong"   // Strong security
	SecurityLevelExcellent SecurityLevel = "excellent" // Excellent security
)

// CertificateValidation represents validation errors and warnings
type CertificateValidation struct {
	IsValid    bool     `json:"is_valid"`
	Errors     []string `json:"errors,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	WeakPoints []string `json:"weak_points,omitempty"`
}

// CertificateStats represents certificate statistics for reporting
type CertificateStats struct {
	TotalCertificates    int                       `json:"total_certificates"`
	ValidCertificates    int                       `json:"valid_certificates"`
	ExpiredCertificates  int                       `json:"expired_certificates"`
	ExpiringSoonCount    int                       `json:"expiring_soon_count"`
	SelfSignedCount      int                       `json:"self_signed_count"`
	SecurityLevelCounts  map[SecurityLevel]int     `json:"security_level_counts"`
	CommonIssuers        map[string]int            `json:"common_issuers"`
	AlgorithmDistribution map[string]int           `json:"algorithm_distribution"`
}

// Common certificate-related constants
const (
	DefaultCertificatePort = 443
	ExpirationWarningDays  = 30
	MinimumKeySize         = 2048
	WeakKeySize            = 1024
)

// GetExpirationStatus returns expiration information
func (c *Certificate) GetExpirationStatus() (bool, int) {
	now := time.Now()
	if c.NotAfter.Before(now) {
		return true, 0 // Expired
	}
	
	daysUntilExpiry := int(c.NotAfter.Sub(now).Hours() / 24)
	return false, daysUntilExpiry
}

// CheckIsExpiringSoon checks if certificate expires within the warning period
func (c *Certificate) CheckIsExpiringSoon() bool {
	_, daysUntilExpiry := c.GetExpirationStatus()
	return daysUntilExpiry <= ExpirationWarningDays && daysUntilExpiry > 0
}

// GetSecurityLevel calculates the security level based on certificate properties
func (c *Certificate) CalculateSecurityLevel() SecurityLevel {
	score := 0
	
	// Key size scoring
	if c.KeySize >= 4096 {
		score += 3
	} else if c.KeySize >= 2048 {
		score += 2
	} else if c.KeySize >= 1024 {
		score += 1
	}
	
	// Signature algorithm scoring
	switch c.SignatureAlgorithm {
	case "SHA256-RSA", "SHA384-RSA", "SHA512-RSA", "ECDSA-SHA256", "ECDSA-SHA384":
		score += 2
	case "SHA1-RSA":
		score += 1
	case "MD5-RSA":
		score += 0 // Weak
	}
	
	// Validity period (shorter is better)
	validityDays := int(c.NotAfter.Sub(c.NotBefore).Hours() / 24)
	if validityDays <= 90 {
		score += 2
	} else if validityDays <= 365 {
		score += 1
	}
	
	// Self-signed penalty
	if c.IsSelfSigned {
		score -= 1
	}
	
	// Expiration penalty
	if c.IsExpired {
		return SecurityLevelWeak
	}
	
	// Determine level based on score
	switch {
	case score >= 7:
		return SecurityLevelExcellent
	case score >= 5:
		return SecurityLevelStrong
	case score >= 3:
		return SecurityLevelGood
	case score >= 1:
		return SecurityLevelFair
	default:
		return SecurityLevelWeak
	}
}

// ParseFromX509 creates a Certificate from an x509.Certificate
func (c *Certificate) ParseFromX509(cert *x509.Certificate) {
	// Subject
	c.Subject = CertificateSubject{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		Province:           cert.Subject.Province,
		Locality:           cert.Subject.Locality,
		StreetAddress:      cert.Subject.StreetAddress,
		PostalCode:         cert.Subject.PostalCode,
	}
	
	// Issuer
	c.Issuer = CertificateIssuer{
		CommonName:         cert.Issuer.CommonName,
		Organization:       cert.Issuer.Organization,
		OrganizationalUnit: cert.Issuer.OrganizationalUnit,
		Country:            cert.Issuer.Country,
		Province:           cert.Issuer.Province,
		Locality:           cert.Issuer.Locality,
	}
	
	// Basic fields
	c.SerialNumber = cert.SerialNumber.String()
	c.Version = cert.Version
	c.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	c.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	c.NotBefore = cert.NotBefore
	c.NotAfter = cert.NotAfter
	c.IsCA = cert.IsCA
	
	// Alternative names
	c.DNSNames = cert.DNSNames
	for _, ip := range cert.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}
	c.EmailAddresses = cert.EmailAddresses
	for _, uri := range cert.URIs {
		c.URIs = append(c.URIs, uri.String())
	}
	
	// Check if self-signed
	c.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()
	
	// Expiration status
	now := time.Now()
	c.IsExpired = cert.NotAfter.Before(now)
	c.IsExpiringSoon = c.CheckIsExpiringSoon()
}