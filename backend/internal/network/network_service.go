package network

import (
	"context"
	"time"
	"reconya-ai/db"
	"reconya-ai/internal/config"
	"reconya-ai/internal/validation"
	"reconya-ai/models"
)

type NetworkService struct {
	Config     *config.Config
	Repository db.NetworkRepository
	dbManager  *db.DBManager
	validator  *validation.NetworkValidator
}

func NewNetworkService(networkRepo db.NetworkRepository, cfg *config.Config, dbManager *db.DBManager) *NetworkService {
	return &NetworkService{
		Config:     cfg,
		Repository: networkRepo,
		dbManager:  dbManager,
		validator:  validation.NewNetworkValidator(),
	}
}

func (s *NetworkService) Create(cidr string) (*models.Network, error) {
	network := &models.Network{CIDR: cidr}
	return s.dbManager.CreateOrUpdateNetwork(s.Repository, context.Background(), network)
}

func (s *NetworkService) FindOrCreate(cidr string) (*models.Network, error) {
	network, err := s.Repository.FindByCIDR(context.Background(), cidr)
	if err == db.ErrNotFound {
		return s.Create(cidr)
	}
	if err != nil {
		return nil, err
	}
	return network, nil
}

func (s *NetworkService) FindByCIDR(cidr string) (*models.Network, error) {
	network, err := s.Repository.FindByCIDR(context.Background(), cidr)
	if err == db.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return network, nil
}

func (s *NetworkService) FindCurrent() (*models.Network, error) {
	network, err := s.FindByCIDR(s.Config.NetworkCIDR)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// FindAll returns all networks in the database
func (s *NetworkService) FindAll(ctx context.Context) ([]*models.Network, error) {
	return s.Repository.FindAll(ctx)
}

// CreateNetwork creates a new network with validation
func (s *NetworkService) CreateNetwork(ctx context.Context, cidr, name, description string, enabled, scanAllPorts bool) (*models.Network, error) {
	// Validate CIDR format
	if err := s.validator.ValidateNetworkRange(cidr); err != nil {
		return nil, err
	}
	
	// Check if network already exists
	existing, err := s.Repository.FindByCIDR(ctx, cidr)
	if err != db.ErrNotFound {
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, db.ErrAlreadyExists
		}
	}
	
	network := &models.Network{
		CIDR:         cidr,
		Name:         name,
		Description:  description,
		Enabled:      enabled,
		ScanAllPorts: scanAllPorts,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	return s.dbManager.CreateOrUpdateNetwork(s.Repository, ctx, network)
}

// UpdateNetwork updates an existing network
func (s *NetworkService) UpdateNetwork(ctx context.Context, id string, cidr, name, description string, enabled, scanAllPorts bool) (*models.Network, error) {
	// Validate CIDR format
	if err := s.validator.ValidateNetworkRange(cidr); err != nil {
		return nil, err
	}
	
	// Check if network exists
	existing, err := s.Repository.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	
	// Update fields
	existing.CIDR = cidr
	existing.Name = name
	existing.Description = description
	existing.Enabled = enabled
	existing.ScanAllPorts = scanAllPorts
	existing.UpdatedAt = time.Now()
	
	return s.dbManager.CreateOrUpdateNetwork(s.Repository, ctx, existing)
}

// DeleteNetwork removes a network
func (s *NetworkService) DeleteNetwork(ctx context.Context, id string) error {
	return s.Repository.Delete(ctx, id)
}

// GetEnabledNetworks returns all enabled networks for scanning
func (s *NetworkService) GetEnabledNetworks(ctx context.Context) ([]*models.Network, error) {
	return s.Repository.FindByEnabled(ctx, true)
}

// GetScanTargets returns CIDRs of all enabled networks
func (s *NetworkService) GetScanTargets(ctx context.Context) ([]string, error) {
	networks, err := s.GetEnabledNetworks(ctx)
	if err != nil {
		return nil, err
	}
	
	var targets []string
	for _, network := range networks {
		targets = append(targets, network.CIDR)
	}
	
	// If no networks are configured in database, fall back to config
	if len(targets) == 0 {
		return s.Config.NetworkRanges, nil
	}
	
	return targets, nil
}

// GetNetworkScanConfig returns the scan configuration for a specific CIDR
func (s *NetworkService) GetNetworkScanConfig(ctx context.Context, cidr string) (bool, error) {
	network, err := s.Repository.FindByCIDR(ctx, cidr)
	if err == db.ErrNotFound {
		// If network not found in database, use global config
		return s.Config.ScanAllPorts, nil
	}
	if err != nil {
		return false, err
	}
	
	return network.ScanAllPorts, nil
}
