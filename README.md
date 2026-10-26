# Network Monitor

A high-performance network monitoring solution built in Go. Inspired by the excellent work of the Zabbix team, Network Monitor aims to provide similar functionality while leveraging Go's advantages in concurrency, deployment simplicity, and modern tooling.

## Why Go?

While Zabbix (written in C) is an industry-proven monitoring solution, Network Monitor explores an alternative approach using Go:

- **Simpler deployment** - Single static binary, no dependencies
- **Native concurrency** - Goroutines and channels for efficient parallel operations
- **Memory safety** - Garbage collection eliminates entire classes of bugs
- **Cross-platform** - Compile for any OS/architecture from a single codebase
- **Modern tooling** - Built-in testing, profiling, and package management

## Operating Modes

Network Monitor supports two operating modes:

### ThothOS Integrated Mode

When connected to ThothOS (technologiesunlimited.net), Network Monitor operates as a distributed proxy:

- **Multi-tenant support** - Each company has isolated data and configuration
- **Centralized management** - SNMP templates, ICMP templates, and IPAM data pulled from ThothOS
- **Pull-based config sync** - The proxy re-pulls templates, OIDs, and IPAM data on a jittered 60-120s ticker and **applies** them to the live SQLite store and the running collectors (no webhook receiver; the proxy keeps a persisted local copy so it keeps polling during a ThothOS outage)
- **Results reported up to ThothOS** - The proxy batches each device's latest status (up/down), latency, and packet loss and posts them to ThothOS every 30s, so a down device on the buyer's LAN is visible in the dashboard
- **OID sync (bidirectional)** - Push-up: OIDs created/edited/deleted locally are pushed to ThothOS (user-action driven). Down-sync: on the config pull ticker the proxy reconciles ThothOS-owned OIDs into its local store — creating new ones, adopting oid-string matches, updating changed fields, and deleting local rows whose upstream OID was removed. Locally-created OIDs (never pushed) are left untouched, and a failed pull deletes nothing (so a control-plane blip can't wipe the local table)
- **User authentication** - Login through ThothOS with MFA support

```
┌─────────────────────────────────────────────────────────────┐
│                    ThothOS Cloud                            │
│  (technologiesunlimited.net)                                │
│  ├── Multi-tenant database (MongoDB)                        │
│  ├── SNMP/ICMP template management                          │
│  ├── IPAM (Supernets, Subnets, Pools, VLANs)               │
│  └── User & API key management                              │
└────────────────────────┬────────────────────────────────────┘
              GraphQL API │ ▲ results (reportMonitoringResults)
   config pull + heartbeat│ │ every 30s
                         ▼ │
┌─────────────────────────────────────────────────────────────┐
│           Network Monitor Proxy                             │
│  ├── Local SQLite store (applied config, persisted)         │
│  ├── Real-time polling (SNMP/ICMP)                         │
│  ├── Distributed nodes via gRPC                            │
│  ├── 60-120s config pull + apply ticker                     │
│  └── 30s results reporter (status/latency/loss up)          │
└─────────────────────────────────────────────────────────────┘
```

### Standalone Mode

When ThothOS is not configured, Network Monitor runs independently:

- **No external dependencies** - Fully self-contained
- **Local authentication bypass** - No login required
- **Local database** - All data stored in SQLite
- **Full functionality** - All features available locally

To enable standalone mode, either:
1. Don't configure ThothOS credentials, or
2. Click "Enable Standalone Mode" on the login page

## Features

- **Distributed Node Architecture** - Central server with multiple monitoring nodes connected via gRPC
- **High-Speed Bandwidth Testing** - 10+ Gbps throughput with 6 parallel gRPC streams
- **ICMP Monitoring** - Raw socket ping monitoring (~1,200-2,000 devices per 60s cycle per proxy; scale horizontally by adding proxies/nodes)
- **SNMP Polling** - SNMPv2c and SNMPv3 support with template-based polling
- **MIB Browser** - Interactive SNMP browser with GET, GETNEXT, and WALK operations
- **OID Template Library** - Import 4,400+ pre-defined OIDs from Zabbix templates
- **Network Discovery** - Automatic device discovery on network ranges
- **Network Tools** - Traceroute, DNS lookup, port scanning, WHOIS, and more
- **Alert Engine** - Rule-based alerting with multiple notification channels
- **IPAM Integration** - View and manage IP address space (via ThothOS)
- **Modern Web UI** - htmx-based dashboard with dark/light theme support
- **REST API** - Full-featured API for automation and integration
- **SQLite Database** - Zero-configuration embedded database

## OID Template Library

Network Monitor includes a comprehensive OID template library based on Zabbix's open-source SNMP templates. Credit to the Zabbix team for maintaining these excellent vendor templates.

### Included Vendors (122 templates, 4,400+ OIDs)

- **Cisco** - IOS, ASA, Catalyst 3750, Nexus 9000
- **MikroTik** - RouterOS, CRS, CCR, hEX series (45+ models)
- **Juniper** - JunOS, MX series
- **Fortinet** - FortiGate firewalls
- **F5** - BIG-IP load balancers
- **HP/Aruba** - ProCurve, HPN, H3C
- **Huawei** - Enterprise switches
- **Ubiquiti** - AirOS devices
- **Dell** - Force S-Series
- **Arista** - EOS switches
- **Zyxel** - Managed switches (20+ models)
- **And many more...**

### Using the Template Library

1. Navigate to **Tools > OID Templates**
2. Click **Load Template Library** to browse vendors
3. Select a vendor to see available templates
4. Import individual OIDs or bulk import by vendor
5. Imported OIDs are pushed up to ThothOS (in integrated mode)

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│           Central Server (network-monitor server)            │
│  ├── HTTP API & Web UI (port 8080)                          │
│  ├── SQLite Database (network-monitor.db)                   │
│  ├── ThothOS GraphQL Client (optional)                      │
│  ├── Node Registration & Heartbeat Management               │
│  └── Bandwidth Test Coordination                            │
└──────────────────────────────────────────────────────────────┘
                         ▲
                         │ HTTP/gRPC
         ┌───────────────┼───────────────┐
         │               │               │
┌────────▼─────┐  ┌──────▼──────┐  ┌─────▼───────┐
│  Node-Alpha  │  │  Node-Beta  │  │  Node-Gamma │
│  :50051      │  │  :50052     │  │  :50053     │
│  (gRPC)      │  │  (gRPC)     │  │  (gRPC)     │
└──────────────┘  └─────────────┘  └─────────────┘
```

## Prerequisites

- **Go 1.26+** - [Install Go](https://go.dev/doc/install)

## Quick Start

### Step I: Install Go Runtime

Download and install Go 1.26+ from [https://go.dev/dl/](https://go.dev/dl/)

### Step II: Download Network Monitor

Open PowerShell and run:

```powershell
Invoke-WebRequest -Uri "https://github.com/Technologies-Unlimited/Network-Monitor/archive/refs/tags/v1.1.3.zip" -OutFile "Network-Monitor.zip"
```

### Step III: Extract the Archive

```powershell
Expand-Archive -Path Network-Monitor.zip -DestinationPath .
```

### Step IV: Build the Application

```powershell
cd Network-Monitor-1.1.3
go build -o network-monitor.exe .
```

### Step V: Start the Server

```powershell
.\network-monitor.exe server
```

The server will start on http://localhost:8080

### Step VI: Configure Settings

Open http://localhost:8080/settings in your browser to:
- Connect to ThothOS (optional) - Enter your API key and proxy name
- Select your preferred theme (Dark, Light, or Sacred)

### Starting Monitoring Nodes (Optional)

To enable distributed monitoring, start additional nodes:

```powershell
# Start first node
.\network-monitor.exe node --name Node-Alpha --grpc-port 50051

# Start second node (in another terminal)
.\network-monitor.exe node --name Node-Beta --grpc-port 50052
```

## CLI Usage

Network Monitor uses a unified binary with subcommands:

```bash
# Start the central server
./network-monitor.exe server [options]

# Server options:
#   -p, --port        HTTP port to listen on (default: 8080)

# Start a monitoring node
./network-monitor.exe node --name <name> [options]

# Node options:
#   -n, --name        Node name (required, must be unique)
#   -p, --grpc-port   gRPC port for peer connections (default: 50051)
#   -s, --server      Central server address (default: http://localhost:8080)
#   -c, --company     Company ID (default: default)
```

## Web UI Navigation

The web interface includes the following sections:

| Page | Description |
|------|-------------|
| **Dashboard** | Overview with device counts, status, and active alerts |
| **Devices** | Manage monitored network devices (routers, switches, servers) |
| **Alerts** | View and manage active and historical alerts |
| **Nodes** | Distributed monitoring nodes, peer connections, and bandwidth tests |
| **Visualize** | Network topology and metrics visualization |
| **Tools** | Network diagnostic tools and OID template library |
| **IPAM** | IP address management (requires ThothOS) |
| **Monitor** | SNMP/ICMP template configuration (requires ThothOS) |
| **Reports** | Generate device, uptime, alert, and performance reports |
| **Settings** | Theme settings and ThothOS connection configuration |

## Network Tools

The Tools page provides 14 network diagnostic utilities:

| Tool | Description |
|------|-------------|
| **Traceroute** | Trace the network path to a destination |
| **DNS Lookup** | Query DNS records (A, AAAA, MX, TXT, etc.) |
| **Port Scan** | Scan for open ports on a target host |
| **WHOIS** | Look up domain registration information |
| **Bandwidth Test** | Test network throughput to external servers |
| **Ping** | ICMP ping with statistics |
| **MIB Browser** | Query SNMP OIDs with GET/GETNEXT/WALK (SNMPv1/v2c/v3) |
| **MAC Lookup** | Look up vendor information from MAC addresses |
| **Connection Test** | Test TCP/UDP connectivity to a host:port |
| **HTTP Test** | Test HTTP/HTTPS endpoints with response details |
| **SSL Check** | Validate SSL certificates and expiration |
| **ARP Scan** | Discover devices on the local network |
| **MTU Discovery** | Find the maximum transmission unit for a path |
| **OID Templates** | Browse and import Zabbix SNMP templates |

## ThothOS Integration

### Connecting to ThothOS

1. Navigate to **Settings**
2. Enter your ThothOS URL and API key
3. Click **Test Connection** to verify
4. Click **Connect** to establish the link

### Synced Data

When connected to ThothOS, the following data is synchronized:

| Data Type | Direction | Cadence | Description |
|-----------|-----------|---------|-------------|
| **SNMP Templates** | ThothOS → Local | 60-120s pull + apply | SNMPv2/v3 polling templates, applied to the live collectors |
| **ICMP Templates** | ThothOS → Local | 60-120s pull + apply | Ping monitoring templates, applied to the live collectors |
| **IPAM Data** | ThothOS → Local | 60-120s pull | Supernets, subnets, pools, VLANs, IPs (offset-paginated, 1000/page — no silent truncation) |
| **OIDs** | Bidirectional | push-up on create/edit; down-sync on the 60-120s pull | SNMP object identifiers. Push-up: local create/edit/delete → ThothOS (user-driven). Down-sync: ThothOS → proxy create/adopt/update/delete (upstream deletes reap ThothOS-owned local rows; locally-created rows are preserved) |
| **Heartbeat** | Local → ThothOS | ~60s | Liveness + device/node counts (`proxyHeartbeat`) |
| **Monitoring Results** | Local → ThothOS | 30s batch | Per-device up/down status, latency, and packet loss (`reportMonitoringResults`); companyId is injected server-side from the API key |

Config transfer is pull-based on a jittered 60-120s ticker (the previous webhook-push receiver was removed). Each pull **applies** the fetched config to the local SQLite store and the running collectors, and the persisted copy lets the proxy keep polling during a ThothOS outage.

### API Key Permissions

ThothOS API keys support fine-grained permissions:

- `proxy:read/write` - Proxy registration and management
- `snmp:read/write` - SNMP template and OID management
- `icmp:read/write` - ICMP template management
- `ipam:read/write` - IP address management
- `config:read/write` - Configuration synchronization (pull)
- `metrics:write` - Reporting monitoring results up to ThothOS

## Distributed Bandwidth Testing

### High-Performance Testing

Bandwidth tests between nodes use 6 parallel gRPC bidirectional streams:
- Achieves **10+ Gbps** on capable hardware
- Each stream sends/receives 4MB chunks
- Real-time latency sampling for time-series charts

### Network Path Modes

Tests support three network path modes:

| Mode | Description |
|------|-------------|
| **Direct** | Connect directly to target node's IP (default) |
| **Local** | Force traffic through localhost/loopback (127.0.0.1) |
| **Gateway** | Route through a specified gateway address |

### Running a Bandwidth Test

1. Navigate to **Nodes** page
2. Ensure at least 2 nodes are online
3. Create a peer connection between nodes
4. Click **Run Test** and select:
   - Source and target nodes
   - Test type (bidirectional, upload, download)
   - Network path mode
   - Duration (5-300 seconds)

## Node Management

### Node Registration

- Nodes register with the server on startup using their unique name
- If a node with the same name exists, the existing record is updated
- Node status is tracked via heartbeats (every 30 seconds)

### Node Status Lifecycle

| Status | Condition |
|--------|-----------|
| **Online** | Actively sending heartbeats |
| **Offline** | No heartbeat for 5+ minutes |
| **Deleted** | Automatically removed after 15+ minutes without heartbeat |

## Configuration

### Zero-Configuration Setup

Network Monitor requires **no configuration files** and **no environment variables**. All settings are managed through the Settings UI and stored in the SQLite database.

Simply start the server and configure everything through the web interface:
```bash
# Start on default port 8080
./network-monitor.exe server

# Start on custom port
./network-monitor.exe server --port 9000

# Open http://localhost:8080/settings to configure ThothOS connection
```

### Settings Page

All configuration is managed through the **Settings** page at `http://localhost:8080/settings`:

#### ThothOS Integration
- **API Key** - Your ThothOS API key (starts with `tk_`)
- **Proxy Name** - A friendly name for this proxy instance (optional, defaults to hostname)
- **Test Connection** - Validate your API key before connecting
- **Connect/Disconnect** - Enable or disable ThothOS integration

#### Theme Selection
Choose from three visual themes:
- **Dark** - Modern dark theme with blue accents (default)
- **Light** - Clean light theme for well-lit environments
- **Sacred** - Elegant dark theme with gold accents

All settings are automatically persisted to the SQLite database.

## API Examples

### List Zabbix Templates

```bash
curl http://localhost:8080/api/v1/zabbix-templates
# Returns: {"totalOids":4424,"totalTemplates":122,"vendors":[...]}
```

### Import OIDs from Templates

```bash
# Import specific OIDs
curl -X POST http://localhost:8080/api/v1/zabbix-templates/import \
  -H "Content-Type: application/json" \
  -d '{"oids": [{"oid": "1.3.6.1.2.1.1.1.0", "name": "sysDescr", ...}]}'

# Import all OIDs from all templates
curl -X POST http://localhost:8080/api/v1/zabbix-templates/import-all
```

### List Nodes

```bash
curl http://localhost:8080/api/v1/nodes
```

### Start Bandwidth Test

```bash
curl -X POST http://localhost:8080/api/v1/bandwidth-tests/start \
  -H "Content-Type: application/json" \
  -d '{
    "source_node_id": "uuid-1",
    "target_node_id": "uuid-2",
    "test_type": "bidirectional",
    "duration": 10,
    "test_mode": "direct"
  }'
```

### Add a Device

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "router-1",
    "ip_address": "192.168.1.1",
    "device_type": "router",
    "icmp_enabled": true
  }'
```

## Project Structure

```
Network-Monitor/
├── main.go                  # Unified CLI entry point (server + node)
├── internal/
│   ├── api/                 # HTTP API handlers
│   ├── database/            # SQLite database initialization
│   ├── grpc/                # gRPC server for node communication
│   │   └── pb/              # Generated protobuf files
│   ├── models/              # GORM data models
│   ├── middleware/          # Authentication middleware
│   ├── templates/           # Zabbix template parser
│   ├── thothos/             # ThothOS GraphQL client
│   └── server/              # Server state management
├── proto/
│   └── node/                # Protobuf definitions
├── templates/
│   └── snmp/                # Zabbix SNMP templates (122 vendors)
├── web/
│   ├── templates/           # HTML templates (htmx)
│   └── static/              # CSS, JS, images
└── network-monitor.db       # SQLite database (created at runtime)
```

## Database Schema

Uses SQLite with GORM ORM. Key tables:

| Table | Description |
|-------|-------------|
| `nodes` | Registered monitoring nodes |
| `node_peers` | Peer connections between nodes |
| `bandwidth_test_results` | Historical bandwidth test results |
| `scheduled_tests` | Scheduled/recurring bandwidth tests |
| `devices` | Monitored network devices |
| `alerts` | Active and historical alerts |
| `alert_rules` | Alert rule definitions |
| `snmp_templates` | SNMP polling templates |
| `oids` | SNMP OID definitions (syncs with ThothOS) |
| `settings` | Application settings (theme, ThothOS config) |
| `proxy_configs` | ThothOS proxy registration data |

## Cross-Platform Builds

```bash
# Windows
go build -o network-monitor.exe .

# Linux
GOOS=linux GOARCH=amd64 go build -o network-monitor-linux .

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o network-monitor-macos .

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o network-monitor-macos-intel .
```

## Development / Quality Gates

The repo ships a single local gate that mirrors CI. Run it before pushing:

```bash
bash scripts/check.sh
```

It runs, in order, stopping at the first hard failure:

| Gate | Catches |
|------|---------|
| `go build ./...` | Compilation errors |
| `go vet ./...` | Suspicious constructs (printf mismatches, lost locks, ...) |
| `staticcheck ./...` | Real bugs, dead code, ineffectual assignments (SA/ST/S/U) |
| `golangci-lint run` | Curated **usability** linters (see below) |
| `go test ./...` | The full suite (adds `-race` automatically when a C compiler is present) |
| `scripts/checks/*.sh` | Custom class-detection gates added by later work (extension point) |

`staticcheck` and `golangci-lint` **skip with a notice** if not installed, so a
fresh clone is never blocked — but **CI installs and enforces them**. Install
locally with:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

### What the linters guard (correctness/usability, not style)

`.golangci.yml` deliberately enables only linters that catch ways the running
product can silently misbehave — swallowed errors (`errcheck`), leaked HTTP
bodies (`bodyclose`), leaked/unchecked DB rows (`sqlclosecheck`,
`rowserrcheck`), endpoints that return `nil` after an error (`nilerr`),
ineffectual/wasted assignments, bad context propagation (`contextcheck`), and
duration bugs (`durationcheck`) — plus `staticcheck`, `govet`, `unconvert`.
Pure-style linters (gofmt/lll/gocyclo/…) are intentionally **off**; this repo is
not gofmt-clean and the gate is about correctness, not formatting.

### The race detector runs in CI

`go test -race` needs cgo, which the Windows dev box lacks, so `scripts/check.sh`
skips it locally with a notice. **CI (`.github/workflows/ci.yml`, ubuntu) runs
`go test -race ./...` on every push and PR** — that is the standing race gate for
the collectors, tickers, sweeps and shared session state. CI also runs
`govulncheck`.

### Adding a class-detection gate

When a bug is fixed, add a script under `scripts/checks/` that enumerates that
bug's whole class across the tree and exits non-zero if any instance remains
(see `scripts/checks/README.md`). `scripts/check.sh` and CI pick it up
automatically, turning the fix into a permanent regression wall.

## Performance

- **10+ Gbps** bandwidth testing between nodes
- **~1,200-2,000 devices per proxy** on a default 60s ICMP cycle (100 concurrent pings × ~3-5s per device); scale beyond that horizontally by adding proxies/nodes
- **60s default ICMP interval** with raw ICMP sockets (per-device intervals configurable)
- **~100MB RAM** base usage

> Design ceiling, honestly stated: a single proxy pings with a 100-slot concurrency
> semaphore, so one 60s cycle drains roughly 1,200-2,000 devices before the interval
> starts to stretch. Larger estates are served by running additional proxies/nodes,
> not by driving one proxy toward 100k simultaneous pings.

## Acknowledgments

- **Zabbix** - For their excellent open-source SNMP templates which power our OID template library
- **Go Team** - For creating a language that makes high-performance network tools accessible

## License

MIT License - see LICENSE file

## Contributing

Contributions welcome! Please open an issue or PR.

---

**Built with Go | High-Performance Network Monitoring**
