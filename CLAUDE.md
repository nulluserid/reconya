# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Reconya is a comprehensive network reconnaissance and asset discovery platform with a Go backend and React/TypeScript frontend. It performs advanced network scanning, device identification, certificate enumeration, service fingerprinting, and real-time monitoring through a web-based dashboard. Authentication is handled via proxy (nginx, OAuth2 Proxy, etc.) rather than application-level auth.

## Architecture

### Backend (Go)
- **Location**: `backend/`
- **API**: REST API (authentication handled by proxy)
- **Database**: SQLite with repository pattern
- **Scanning**: Multi-strategy nmap integration with native Go fallbacks
- **Concurrency**: 50 goroutines for network scanning, 3 workers for port scanning
- **Key Services**:
  - Device discovery and fingerprinting (`internal/device/`)
  - Network scanning (`internal/pingsweep/`, `internal/portscan/`)
  - Web service detection with screenshot capture (`internal/webservice/`)
  - SSL/TLS certificate enumeration and validation tracking
  - SNMP scanning and device intelligence gathering
  - Service fingerprinting with banner grabbing
  - Protocol enumeration (SMB, DNS, LDAP, SSH, FTP)
  - Event logging and system monitoring

### Frontend (React/TypeScript)
- **Location**: `frontend/`
- **Framework**: React 18 with TypeScript, Bootstrap 5, SASS
- **State Management**: Context API with custom hooks
- **Key Features**: Real-time dashboard, device management, network visualization
- **Build Tool**: Create React App (react-scripts)

### Key Components
- **Authentication**: Proxy-based authentication (no application-level auth)
- **Database**: Repository pattern with SQLite (`backend/db/`)
- **Scanning Engine**: Multiple nmap strategies with automatic fallback
- **Network Discovery**: ICMP ping sweeps, TCP probes, ARP lookups, multi-subnet support
- **Device Identification**: OUI database, hostname resolution, OS fingerprinting
- **Certificate Intelligence**: SSL/TLS cert collection with validation status tracking
- **Service Intelligence**: Deep service fingerprinting, banner grabbing, CVE matching
- **Device Lifecycle**: First seen, last seen, change tracking with historical timeline

## Development Commands

**IMPORTANT**: Always use Docker for builds and testing to ensure consistency and catch integration issues early.

## Testing & Validation Framework

### Phase Testing Structure
RecoNya uses a comprehensive testing framework that validates each development phase:

**Phase 1: Security & Foundation**
- Input validation and command injection prevention
- TLS certificate handling with invalid cert tracking  
- Database connection pooling and optimization
- Resource management and lifecycle cleanup

**Phase 2: Feature Enhancements** 
- Multiple subnet support and network scanning
- Advanced port scanning capabilities
- UI filtering and enhanced user experience

**Phase 3: Advanced Intelligence**
- SNMP scanning and device intelligence
- Service fingerprinting and vulnerability assessment
- Advanced analytics and behavioral analysis

### Testing Commands

```bash
# Run phase-specific validation tests
./scripts/test_phase.sh 1          # Phase 1: Security & Foundation
./scripts/test_phase.sh 2          # Phase 2: Feature Enhancements  
./scripts/test_phase.sh 3          # Phase 3: Advanced Intelligence
./scripts/test_phase.sh all        # Complete test suite

# Manual testing commands
make test                          # Backend unit tests
make test-integration              # Backend integration tests
npm test                           # Frontend unit tests (in frontend/)
docker compose build               # Validate Docker builds
docker compose up -d               # Test full stack deployment

# Security and performance testing
make security                      # Security scan with gosec
make test-coverage                 # Coverage analysis
go test -bench=.                   # Performance benchmarks
```

### Automated Testing (CI/CD)
- **GitHub Actions**: Automated validation on every push/PR
- **Multi-phase Testing**: Validates each development phase independently
- **Docker Validation**: Tests full stack deployment and startup
- **Security Scanning**: Automated security analysis with gosec
- **Performance Testing**: Benchmark testing for critical paths

### Testing Guidelines
1. **Always test with Docker** before pushing changes
2. **Run phase validation** after completing phase milestones
3. **Include security tests** for any input handling or external commands
4. **Test resource cleanup** for any new background services
5. **Validate certificate handling** for any TLS-related changes

### Docker Development (Recommended)
```bash
# Build and test changes
docker compose build backend   # Test backend compilation
docker compose build frontend # Test frontend compilation  
docker compose build          # Build both

# Full stack testing
docker compose up -d           # Start all services
docker compose logs backend   # Check backend logs
docker compose logs frontend  # Check frontend logs
docker compose down           # Stop and cleanup

# Quick backend testing
docker compose up -d backend  # Start just backend
docker compose logs backend --tail 50
```

### Backend Development (Local)
```bash
cd backend

# Development setup
go mod download
go mod tidy

# Run application
go run cmd/main.go
# OR
make run

# Build
make build

# Testing
make test              # Run all tests
make test-unit         # Unit tests only
make test-integration  # Integration tests only
make test-coverage     # Tests with coverage report
./test.sh all          # Alternative test runner
./test.sh unit         # Unit tests via script
./test.sh coverage     # Coverage via script

# Code quality
make lint              # Run golangci-lint
make fmt               # Format code
make vet               # Go vet
make security          # Run gosec
make quality           # All quality checks
```

### Frontend Development
```bash
cd frontend

# Development setup
npm install

# Development server
npm start              # Runs on port 3000

# Build and test
npm run build
npm test
```

### Docker Development
```bash
# Full stack with Docker Compose
docker compose up -d

# With host networking (for network scanning)
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d

# Development scripts
./scripts/dev_start_backend.sh
./scripts/dev_start_frontend.sh
```

## Configuration

### Environment Variables (Required)
- `NETWORK_RANGE`: Network CIDR for scanning (e.g., "192.168.1.0/24,10.0.0.0/8")
- `DATABASE_NAME`: SQLite database name
- `SQLITE_PATH`: Database file path (optional, defaults to `data/{DATABASE_NAME}.db`)

### Environment Variables (Optional)
- `SCAN_ALL_PORTS`: Enable full port scanning (default: false)
- `SNMP_COMMUNITY_STRINGS`: Comma-separated list of SNMP community strings
- `CVE_DATABASE_PATH`: Path to CVE database for vulnerability matching

### Configuration Loading
Configuration is loaded via `backend/internal/config/config.go` using godotenv for .env files and environment variables.

## Testing Strategy

### Backend Tests
- **Unit Tests**: `./models/...` and `./internal/...` packages
- **Integration Tests**: `./tests/integration/...` with shared test utilities
- **Test Environment**: Separate test database configuration
- **Coverage**: HTML reports generated to `coverage.html`

### Test Utilities
- Database setup/teardown: `tests/testutils/database.go`
- HTTP testing helpers: `tests/testutils/http.go`
- Test fixtures: `tests/testutils/fixtures.go`

## Networking and Security

### Network Scanning Requirements
- **nmap**: Required for MAC address detection and advanced scanning
- **Privileges**: nmap needs setuid permissions for ICMP scanning
- **Fallback Strategy**: Automatic fallback from privileged to unprivileged scans

### Scanning Flow
1. **Network Discovery**: Every 30 seconds with multiple nmap strategies across multiple subnets
2. **Device Identification**: OUI lookup, hostname resolution, OS fingerprinting, first/last seen tracking
3. **Port Scanning**: Background workers scan top 100 ports (or all 65535 with SCAN_ALL_PORTS=true)
4. **Service Fingerprinting**: Banner grabbing, version detection, protocol enumeration
5. **Certificate Collection**: SSL/TLS cert harvesting with validation status tracking
6. **Web Service Detection**: HTTP/HTTPS discovery with screenshot capture
7. **SNMP Enumeration**: Device intelligence gathering via SNMP
8. **Vulnerability Assessment**: CVE matching and security posture evaluation

### Security Considerations
- Proxy-based authentication (no application-level auth required)
- Comprehensive input validation for network ranges and commands
- TLS certificate validation with continued scanning for invalid certs
- CORS middleware configuration
- Database connection with retry mechanism and locking

## Database Optimization

The application has been optimized to remove database serialization bottlenecks:

### Connection Pooling
- **SQLite Configuration**: WAL mode with optimized connection pool (25 max connections, 15 idle)
- **Concurrent Access**: Removed single-threaded database queue that was forcing serialization
- **Retry Logic**: Automatic retry mechanism for SQLITE_BUSY errors with exponential backoff
- **Connection Lifecycle**: Proper connection recycling (30min max lifetime, 5min idle timeout)

### Performance Features
- **Memory Mapping**: 256MB mmap_size for better I/O performance
- **WAL Mode**: Write-Ahead Logging for concurrent reads while writing
- **Optimized Cache**: 10,000 page cache size for better query performance
- **Direct Repository Access**: Repositories now use database connections directly instead of queued operations

## Resource Management

The application implements comprehensive resource cleanup to prevent memory leaks and ensure graceful shutdowns:

### Lifecycle Management
- **Service Manager**: Centralized lifecycle manager (`backend/internal/lifecycle/`) for all background services
- **Graceful Shutdown**: Multi-phase shutdown process (HTTP server → background services → database)
- **Context Propagation**: Proper context cancellation cascades through all goroutines
- **Resource Cleanup**: Automatic cleanup of HTTP connections, file descriptors, and processes

### Background Services
- **Ping Sweep Service**: Managed lifecycle with configurable intervals and proper cancellation
- **Device Updater Service**: Status update service with error handling and controlled shutdown
- **Process Management**: External commands (nmap) properly terminated on context cancellation
- **Connection Pooling**: HTTP clients configured with `DisableKeepAlives` to prevent connection leaks

## Database Schema

### Key Models (in `backend/models/`)
- `Device`: Network devices with MAC addresses, IPs, vendors, first/last seen timestamps
- `Network`: Network configuration and scanning targets (supports multiple subnets)
- `EventLog`: System events and scanning history
- `Port`: Open ports and services on devices with version information
- `WebService`: Discovered web services with metadata and screenshots
- `Certificate`: SSL/TLS certificates with validation status, thumbprints, expiration
- `ServiceFingerprint`: Detailed service information with banners and CVE mappings
- `SNMPData`: SNMP-discovered device information and capabilities

## Common Development Patterns

### Error Handling
- Use structured error returns with context
- Log errors with appropriate levels
- Implement retry mechanisms for network operations

### Concurrency
- Producer-consumer pattern for scanning queues
- Worker pools for concurrent operations
- Database connection pooling with optimized SQLite configuration

### API Design
- RESTful endpoints with consistent JSON responses
- JWT middleware for protected routes
- CORS configuration for frontend integration

## Version Control and Release Management

### Development Phase Versioning
After completing each development phase, follow this versioning workflow:

1. **Commit Phase Changes**:
   ```bash
   git add .
   git commit -m "feat: Complete Phase X - [Brief description]
   
   ## Phase X: [Phase Name]
   ### [Category] Enhancements
   - [List major changes and improvements]
   
   🤖 Generated with [Claude Code](https://claude.ai/code)
   Co-Authored-By: Claude <noreply@anthropic.com>"
   ```

2. **Create Version Tag**:
   ```bash
   git tag -a v0.0.X -m "Release v0.0.X: [Phase summary]"
   ```

3. **Push to Remote**:
   ```bash
   git push origin master && git push origin v0.0.X
   ```

### Version History
- **v0.0.1**: Phase 1 & 2 Complete - Security foundations and advanced network scanning
  - Security enhancements (input validation, TLS handling, command sanitization)
  - Performance optimizations (database pooling, resource cleanup)
  - Multiple subnets support with per-network port scanning configuration
  - Comprehensive testing infrastructure

### Release Naming Convention
- **Major versions** (1.0.0+): Complete feature sets with breaking changes
- **Minor versions** (0.X.0): New feature phases without breaking changes  
- **Patch versions** (0.0.X): Bug fixes and small improvements within a phase

## Troubleshooting

### Network Scanning Issues
- Check nmap installation and permissions
- Verify network range configuration in environment
- Use host networking mode for Docker if needed
- Check logs via `./logs.sh` script

### Development Issues
- Backend logs: Check application output for scanning errors
- Frontend: Standard React development server on port 3000
- Database: SQLite file permissions and path configuration
- Authentication: Handled by proxy - ensure proper proxy configuration
- Certificate scanning: Invalid certs are tracked but don't stop scanning
- Multi-subnet scanning: Verify NETWORK_RANGE supports comma-separated CIDRs