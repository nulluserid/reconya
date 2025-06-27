package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"reconya-ai/internal/topology"
	"strconv"

	"github.com/gorilla/mux"
)

type TopologyHandler struct {
	TopologyService *topology.TopologyService
}

func NewTopologyHandler(topologyService *topology.TopologyService) *TopologyHandler {
	return &TopologyHandler{
		TopologyService: topologyService,
	}
}

// GetCurrentTopology returns the current network topology
func (h *TopologyHandler) GetCurrentTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	topology, err := h.TopologyService.GetCurrentTopology(ctx)
	if err != nil {
		log.Printf("Error getting current topology: %v", err)
		http.Error(w, "Failed to get topology", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(topology); err != nil {
		log.Printf("Error encoding topology response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// GetTopologyStats returns topology statistics
func (h *TopologyHandler) GetTopologyStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	stats, err := h.TopologyService.GetTopologyStats(ctx)
	if err != nil {
		log.Printf("Error getting topology stats: %v", err)
		http.Error(w, "Failed to get topology stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("Error encoding topology stats response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// GetGateways returns all discovered gateways
func (h *TopologyHandler) GetGateways(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	gateways, err := h.TopologyService.GetAllGateways(ctx)
	if err != nil {
		log.Printf("Error getting gateways: %v", err)
		http.Error(w, "Failed to get gateways", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(gateways); err != nil {
		log.Printf("Error encoding gateways response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// GetDefaultGateway returns the default gateway
func (h *TopologyHandler) GetDefaultGateway(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	gateway, err := h.TopologyService.GetDefaultGateway(ctx)
	if err != nil {
		log.Printf("Error getting default gateway: %v", err)
		http.Error(w, "Failed to get default gateway", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(gateway); err != nil {
		log.Printf("Error encoding default gateway response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// TriggerTopologyDiscovery manually triggers topology discovery
func (h *TopologyHandler) TriggerTopologyDiscovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Trigger discovery asynchronously
	go func() {
		if err := h.TopologyService.DiscoverAndSaveTopology(ctx); err != nil {
			log.Printf("Manual topology discovery failed: %v", err)
		}
	}()

	// Return immediate response
	response := map[string]string{"status": "Discovery triggered"}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding trigger response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// RegisterTopologyRoutes registers all topology-related routes
func (h *TopologyHandler) RegisterTopologyRoutes(router *mux.Router) {
	topologyRouter := router.PathPrefix("/topology").Subrouter()
	
	topologyRouter.HandleFunc("/current", h.GetCurrentTopology).Methods("GET")
	topologyRouter.HandleFunc("/stats", h.GetTopologyStats).Methods("GET")
	topologyRouter.HandleFunc("/gateways", h.GetGateways).Methods("GET")
	topologyRouter.HandleFunc("/gateways/default", h.GetDefaultGateway).Methods("GET")
	topologyRouter.HandleFunc("/discover", h.TriggerTopologyDiscovery).Methods("POST")
}