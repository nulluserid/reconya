#!/bin/bash

# Phase Testing Script for RecoNya
# This script validates that each development phase works correctly

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test functions
test_docker_build() {
    log_info "Testing Docker builds..."
    
    # Test backend build
    log_info "Building backend container..."
    if docker compose build backend; then
        log_success "Backend Docker build successful"
    else
        log_error "Backend Docker build failed"
        return 1
    fi
    
    # Test frontend build
    log_info "Building frontend container..."
    if docker compose build frontend; then
        log_success "Frontend Docker build successful"
    else
        log_error "Frontend Docker build failed"
        return 1
    fi
    
    log_success "All Docker builds completed successfully"
}

test_backend_unit_tests() {
    log_info "Running backend unit tests..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Run Go unit tests
    if go test ./... -v -timeout=30s; then
        log_success "Backend unit tests passed"
    else
        log_error "Backend unit tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

test_backend_integration() {
    log_info "Running backend integration tests..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Run integration tests
    if go test ./tests/integration/... -v -timeout=60s; then
        log_success "Backend integration tests passed"
    else
        log_error "Backend integration tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

test_frontend_unit_tests() {
    log_info "Running frontend unit tests..."
    
    cd "$PROJECT_ROOT/frontend"
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        log_info "Installing frontend dependencies..."
        npm install
    fi
    
    # Run frontend tests
    if npm test -- --coverage --watchAll=false; then
        log_success "Frontend unit tests passed"
    else
        log_error "Frontend unit tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

test_docker_stack_startup() {
    log_info "Testing full Docker stack startup..."
    
    # Clean up any existing containers
    docker compose down || true
    
    # Start the stack
    log_info "Starting Docker stack..."
    if docker compose up -d; then
        log_success "Docker stack started successfully"
    else
        log_error "Docker stack startup failed"
        return 1
    fi
    
    # Wait for services to be ready
    log_info "Waiting for services to become ready..."
    sleep 10
    
    # Check backend health
    local backend_ready=false
    for i in {1..30}; do
        if curl -s http://localhost:3008/system-status/latest > /dev/null 2>&1; then
            backend_ready=true
            break
        fi
        sleep 2
    done
    
    if [ "$backend_ready" = true ]; then
        log_success "Backend service is responding"
    else
        log_error "Backend service failed to respond"
        docker compose logs backend
        return 1
    fi
    
    # Check frontend availability
    local frontend_ready=false
    for i in {1..30}; do
        if curl -s http://localhost:3001 > /dev/null 2>&1; then
            frontend_ready=true
            break
        fi
        sleep 2
    done
    
    if [ "$frontend_ready" = true ]; then
        log_success "Frontend service is responding"
    else
        log_warning "Frontend service not responding (may need manual check)"
    fi
    
    # Clean up
    docker compose down
    log_success "Docker stack test completed"
}

test_security_validations() {
    log_info "Testing security implementations..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Test input validation
    log_info "Testing input validation..."
    if go test ./internal/validation/... -v; then
        log_success "Input validation tests passed"
    else
        log_error "Input validation tests failed"
        return 1
    fi
    
    # Test TLS certificate handling
    log_info "Testing TLS certificate validation..."
    if go test ./internal/tls/... -v; then
        log_success "TLS validation tests passed"
    else
        log_error "TLS validation tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

test_database_performance() {
    log_info "Testing database performance optimizations..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Test database manager
    if go test ./db/... -v; then
        log_success "Database tests passed"
    else
        log_error "Database tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

test_resource_management() {
    log_info "Testing resource management and lifecycle..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Test lifecycle manager
    if go test ./internal/lifecycle/... -v; then
        log_success "Lifecycle management tests passed"
    else
        log_error "Lifecycle management tests failed"
        return 1
    fi
    
    cd - > /dev/null
}

# Main test runner
run_phase_tests() {
    local phase="$1"
    
    log_info "Starting Phase $phase validation tests..."
    echo "=================================================="
    
    case "$phase" in
        "1"|"phase1")
            log_info "Running Phase 1 tests: Security & Foundation"
            test_docker_build
            test_backend_unit_tests
            test_security_validations
            test_database_performance
            test_resource_management
            test_docker_stack_startup
            ;;
        "2"|"phase2")
            log_info "Running Phase 2 tests: Feature Enhancements"
            test_docker_build
            test_backend_unit_tests
            test_backend_integration
            test_docker_stack_startup
            ;;
        "3"|"phase3")
            log_info "Running Phase 3 tests: Advanced Intelligence"
            test_docker_build
            test_backend_unit_tests
            test_backend_integration
            test_frontend_unit_tests
            test_docker_stack_startup
            ;;
        "all"|"full")
            log_info "Running comprehensive test suite"
            test_docker_build
            test_backend_unit_tests
            test_backend_integration
            test_frontend_unit_tests
            test_security_validations
            test_database_performance
            test_resource_management
            test_docker_stack_startup
            ;;
        *)
            log_error "Unknown phase: $phase"
            echo "Usage: $0 [1|2|3|all]"
            echo "  1: Phase 1 - Security & Foundation"
            echo "  2: Phase 2 - Feature Enhancements" 
            echo "  3: Phase 3 - Advanced Intelligence"
            echo "  all: Complete test suite"
            exit 1
            ;;
    esac
    
    echo "=================================================="
    log_success "Phase $phase validation completed successfully!"
}

# Script entry point
if [ $# -eq 0 ]; then
    echo "Usage: $0 [1|2|3|all]"
    echo "  1: Phase 1 - Security & Foundation"
    echo "  2: Phase 2 - Feature Enhancements"
    echo "  3: Phase 3 - Advanced Intelligence" 
    echo "  all: Complete test suite"
    exit 1
fi

run_phase_tests "$1"