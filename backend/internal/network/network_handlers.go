package network

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type NetworkHandlers struct {
	Service *NetworkService
}

func NewNetworkHandlers(service *NetworkService) *NetworkHandlers {
	return &NetworkHandlers{Service: service}
}

// GetNetwork returns the current configured network (legacy endpoint)
func (h *NetworkHandlers) GetNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	network, err := h.Service.FindCurrent()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if network == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(network)
}

// GetAllNetworks returns all configured networks
func (h *NetworkHandlers) GetAllNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	networks, err := h.Service.FindAll(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networks)
}

// CreateNetworkRequest represents the request body for creating a network
type CreateNetworkRequest struct {
	CIDR         string `json:"cidr"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Enabled      *bool  `json:"enabled"`      // Pointer to distinguish between false and not provided
	ScanAllPorts *bool  `json:"scan_all_ports"` // Pointer to distinguish between false and not provided
}

// CreateNetwork creates a new network
func (h *NetworkHandlers) CreateNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.CIDR == "" {
		http.Error(w, "CIDR is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Default enabled to true if not specified
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	
	// Default scan_all_ports to false if not specified
	scanAllPorts := false
	if req.ScanAllPorts != nil {
		scanAllPorts = *req.ScanAllPorts
	}

	network, err := h.Service.CreateNetwork(context.Background(), req.CIDR, req.Name, req.Description, enabled, scanAllPorts)
	if err != nil {
		if err.Error() == "record already exists" {
			http.Error(w, "Network with this CIDR already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(network)
}

// UpdateNetworkRequest represents the request body for updating a network
type UpdateNetworkRequest struct {
	CIDR         string `json:"cidr"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Enabled      bool   `json:"enabled"`
	ScanAllPorts bool   `json:"scan_all_ports"`
}

// UpdateNetwork updates an existing network
func (h *NetworkHandlers) UpdateNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract network ID from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 {
		http.Error(w, "Network ID is required", http.StatusBadRequest)
		return
	}
	networkID := pathParts[len(pathParts)-1]

	var req UpdateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.CIDR == "" {
		http.Error(w, "CIDR is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	network, err := h.Service.UpdateNetwork(context.Background(), networkID, req.CIDR, req.Name, req.Description, req.Enabled, req.ScanAllPorts)
	if err != nil {
		if err.Error() == "record not found" {
			http.Error(w, "Network not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(network)
}

// DeleteNetwork deletes a network
func (h *NetworkHandlers) DeleteNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract network ID from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 2 {
		http.Error(w, "Network ID is required", http.StatusBadRequest)
		return
	}
	networkID := pathParts[len(pathParts)-1]

	err := h.Service.DeleteNetwork(context.Background(), networkID)
	if err != nil {
		if err.Error() == "record not found" {
			http.Error(w, "Network not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetScanTargets returns the current networks configured for scanning
func (h *NetworkHandlers) GetScanTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targets, err := h.Service.GetScanTargets(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"scan_targets": targets,
		"total_count":  len(targets),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetNetworkScanConfig returns the scan configuration for all networks
func (h *NetworkHandlers) GetNetworkScanConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	networks, err := h.Service.FindAll(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type NetworkConfig struct {
		ID           string `json:"id"`
		CIDR         string `json:"cidr"`
		Name         string `json:"name"`
		Enabled      bool   `json:"enabled"`
		ScanAllPorts bool   `json:"scan_all_ports"`
	}

	var configs []NetworkConfig
	for _, network := range networks {
		configs = append(configs, NetworkConfig{
			ID:           network.ID,
			CIDR:         network.CIDR,
			Name:         network.Name,
			Enabled:      network.Enabled,
			ScanAllPorts: network.ScanAllPorts,
		})
	}

	response := map[string]interface{}{
		"networks": configs,
		"total_count": len(configs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
