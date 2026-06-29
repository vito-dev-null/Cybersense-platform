# CyberSense ASPM Platform

## Overview
CyberSense is a modular, scalable Application Security Posture Management platform built with Go and Python. It provides comprehensive security coverage through discovery, intelligence, emulation, and remediation capabilities.

## Project Structure
```
cybersense-platform/
├── README.md
├── go.mod
├── go.sum
├── docker-compose.yml
├── .gitignore
├── cmd/
│   └── discovery-engine/
│       └── main.go
├── internal/
│   ├── discovery/
│   │   ├── domains/
│   │   │   ├── scanner.go
│   │   │   ├── resolver.go
│   │   │   ├── portchecker.go
│   │   │   └── types.go
│   │   ├── github/
│   │   │   └── scanner.go
│   │   ├── cloud/
│   │   │   └── scanner.go
│   │   └── exporter/
│   │       └── json_exporter.go
│   ├── secrets/
│   │   └── detector/
│   │       └── scanner.go
│   ├── emulation/
│   │   └── mitre/
│   │       └── simulator.go
│   └── remediation/
│       └── jira/
│           └── client.go
├── pkg/
│   ├── utils/
│   │   └── httpclient.go
│   └── config/
│       └── config.go
├── configs/
│   └── discovery.yaml
├── scripts/
│   └── wordlists/
│       └── subdomains.txt
├── api/
│   ├── discovery_api.py
│   ├── secrets_api.py
│   ├── emulation_api.py
│   └── remediation_api.py
└── tests/
    ├── discovery_test.go
    └── integration_tests/
        └── api_tests.py
```

## Core Modules

### /discovery
- Domain & Subdomain scanning
- DNS enumeration and resolution
- GitHub repository discovery
- Cloud asset mapping

### /secrets
- Credential and sensitive data detection
- Pattern matching engines
- False positive reduction algorithms

### /emulation
- MITRE ATT&CK framework implementation
- Adversarial attack simulation
- Security control validation

### /remediation
- Jira integration for ticket creation
- Automated issue assignment
- Remediation workflow management

## Getting Started

### Prerequisites
- Go 1.19+
- Python 3.8+
- Docker (optional for containerized deployment)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourorg/cybersense-platform.git
cd cybersense-platform

# Initialize Go modules
go mod tidy

# Install Python dependencies
pip install -r requirements.txt
```

### Running the Domain Scanner
```bash
# Run the discovery engine
go run cmd/discovery-engine/main.go --domain example.com
```
```

```go cmd/discovery-engine/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"cybersense-platform/internal/discovery/domains"
)

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Target domain to scan")
	concurrency := flag.Int("concurrency", 50, "Number of concurrent workers")
	wordlist := flag.String("wordlist", "scripts/wordlists/subdomains.txt", "Path to subdomain wordlist")
	timeout := flag.Int("timeout", 10, "Timeout for HTTP requests in seconds")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Domain is required. Use -domain flag to specify target domain")
	}

	// Create discovery context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Initialize the domain scanner
	scanner := domains.NewDomainScanner(*domain, *wordlist, *concurrency, *timeout)

	// Start the scan
	fmt.Printf("Starting domain discovery for: %s\n", *domain)
	fmt.Printf("Using wordlist: %s\n", *wordlist)
	fmt.Printf("Concurrency level: %d\n", *concurrency)

	results, err := scanner.Scan(ctx)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results as JSON
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal results: %v", err)
	}

	// Save to file
	filename := fmt.Sprintf("discovery_results_%s.json", time.Now().Format("20060102_150405"))
	if err := os.WriteFile(filename, output, 0644); err != nil {
		log.Printf("Warning: Could not save results to file: %v", err)
	}

	// Print summary
	fmt.Printf("\nDiscovery completed!\n")
	fmt.Printf("Found %d subdomains\n", len(results.Subdomains))
	fmt.Printf("Results saved to: %s\n", filename)
	fmt.Printf("\nResults:\n%s\n", output)
}
```

```go internal/discovery/domains/types.go
package domains

import (
	"time"
)

// DiscoveryResult represents the complete result of a domain discovery scan
type DiscoveryResult struct {
	TargetDomain string           `json:"target_domain"`
	ScanTime     time.Time        `json:"scan_time"`
	Subdomains   []SubdomainInfo  `json:"subdomains"`
	Statistics   DiscoveryStats   `json:"statistics"`
}

// SubdomainInfo contains information about a discovered subdomain
type SubdomainInfo struct {
	Name        string `json:"name"`
	IPAddress   string `json:"ip_address"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	HTTPSPort   bool   `json:"https_port"`
	HTTPPort    bool   `json:"http_port"`
	Responsive  bool   `json:"responsive"`
	ResponseTime int64 `json:"response_time_ms,omitempty"`
}

// DiscoveryStats contains statistics about the discovery scan
type DiscoveryStats struct {
	TotalScanned   int           `json:"total_scanned"`
	ValidSubdomains int          `json:"valid_subdomains"`
	ResponsiveHosts int          `json:"responsive_hosts"`
	ScanDuration   time.Duration `json:"scan_duration"`
}

// ScanConfig holds configuration options for the domain scanner
type ScanConfig struct {
	TargetDomain string
	WordlistPath string
	Concurrency  int
	Timeout      int
}
```

```go internal/discovery/domains/scanner.go
package domains

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DomainScanner handles the complete domain discovery process
type DomainScanner struct {
	config ScanConfig
}

// NewDomainScanner creates a new domain scanner instance
func NewDomainScanner(domain, wordlist string, concurrency, timeout int) *DomainScanner {
	return &DomainScanner{
		config: ScanConfig{
			TargetDomain: domain,
			WordlistPath: wordlist,
			Concurrency:  concurrency,
			Timeout:      timeout,
		},
	}
}

// Scan performs the complete domain discovery process
func (ds *DomainScanner) Scan(ctx context.Context) (*DiscoveryResult, error) {
	startTime := time.Now()
	
	// Load wordlist
	wordlist, err := ds.loadWordlist()
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Create channels for processing
	jobs := make(chan string, len(wordlist))
	results := make(chan SubdomainInfo, len(wordlist))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < ds.config.Concurrency; i++ {
		wg.Add(1)
		go ds.worker(ctx, &wg, jobs, results)
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, word := range wordlist {
			select {
			case jobs <- word:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var subdomains []SubdomainInfo
	for result := range results {
		subdomains = append(subdomains, result)
	}

	// Compile statistics
	stats := DiscoveryStats{
		TotalScanned:   len(wordlist),
		ValidSubdomains: len(subdomains),
		ResponsiveHosts: countResponsive(subdomains),
		ScanDuration:   time.Since(startTime),
	}

	return &DiscoveryResult{
		TargetDomain: ds.config.TargetDomain,
		ScanTime:     startTime,
		Subdomains:   subdomains,
		Statistics:   stats,
	}, nil
}

// loadWordlist loads subdomain wordlist from file
func (ds *DomainScanner) loadWordlist() ([]string, error) {
	file, err := os.Open(ds.config.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %w", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" && !startsWithComment(word) {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return words, nil
}

// worker performs the actual scanning work
func (ds *DomainScanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- SubdomainInfo) {
	defer wg.Done()
	
	resolver := NewDNSResolver(ds.config.Timeout)
	portChecker := NewPortChecker(ds.config.Timeout)

	for {
		select {
		case word, ok := <-jobs:
			if !ok {
				return
			}
			
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Generate full domain name
			fullDomain := fmt.Sprintf("%s.%s", word, ds.config.TargetDomain)
			
			// Resolve DNS
			ip, err := resolver.Resolve(fullDomain)
			if err != nil {
				continue // Skip unresolved domains
			}

			// Check ports
			httpPort, httpsPort := portChecker.CheckPorts(fullDomain)
			
			// Create subdomain info
			subdomain := SubdomainInfo{
				Name:      fullDomain,
				IPAddress: ip,
				HTTPPort:  httpPort,
				HTTPSPort: httpsPort,
			}
			
			// Check responsiveness only if ports are open
			if httpPort || httpsPort {
				status, responseTime := portChecker.CheckHTTPStatus(fullDomain)
				subdomain.HTTPStatus = status
				subdomain.ResponseTime = responseTime
				subdomain.Responsive = status > 0
			}

			// Send result
			select {
			case results <- subdomain:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// Helper functions
func startsWithComment(line string) bool {
	return len(line) > 0 && line[0] == '#'
}

func countResponsive(subdomains []SubdomainInfo) int {
	count := 0
	for _, sub := range subdomains {
		if sub.Responsive {
			count++
		}
	}
	return count
}
```

```go internal/discovery/domains/resolver.go
package domains

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSResolver handles DNS lookups for subdomain discovery
type DNSResolver struct {
	timeout int
	client  *dns.Client
}

// NewDNSResolver creates a new DNS resolver with specified timeout
func NewDNSResolver(timeout int) *DNSResolver {
	return &DNSResolver{
		timeout: timeout,
		client: &dns.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

// Resolve performs a DNS lookup for the given domain
func (r *DNSResolver) Resolve(domain string) (string, error) {
	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Use Google's DNS server as default
	server := "8.8.8.8:53"
	
	// Perform DNS query
	resp, _, err := r.client.Exchange(msg, server)
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	// Extract IP address from response
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found for %s", domain)
}

// ResolveAll performs DNS lookup and returns all IP addresses
func (r *DNSResolver) ResolveAll(domain string) ([]string, error) {
	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Use Google's DNS server as default
	server := "8.8.8.8:53"
	
	// Perform DNS query
	resp, _, err := r.client.Exchange(msg, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	// Extract all IP addresses from response
	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records found for %s", domain)
	}

	return ips, nil
}
```

```go internal/discovery/domains/portchecker.go
package domains

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PortChecker handles port scanning and HTTP status checking
type PortChecker struct {
	timeout int
	client  *http.Client
}

// NewPortChecker creates a new port checker with specified timeout
func NewPortChecker(timeout int) *PortChecker {
	return &PortChecker{
		timeout: timeout,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			// Skip certificate verification for discovery purposes
			Transport: &http.Transport{
				TLSClientConfig: &TLSConfig{InsecureSkipVerify: true},
			},
		},
	}
}

// CheckPorts checks if common web ports are open
func (pc *PortChecker) CheckPorts(domain string) (httpPort, httpsPort bool) {
	// Check HTTP port (80)
	httpConn, err := net.DialTimeout("tcp", domain+":80", time.Duration(pc.timeout)*time.Second)
	if err == nil {
		httpConn.Close()
		httpPort = true
	}

	// Check HTTPS port (443)
	httpsConn, err := net.DialTimeout("tcp", domain+":443", time.Duration(pc.timeout)*time.Second)
	if err == nil {
		httpsConn.Close()
		httpsPort = true
	}

	return httpPort, httpsPort
}

// CheckHTTPStatus performs an HTTP request to check if the service responds
func (pc *PortChecker) CheckHTTPStatus(domain string) (status int, responseTime int64) {
	// Try HTTPS first, then HTTP
	protocols := []string{"https", "http"}
	
	start := time.Now()
	
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		
		// Set a reasonable user agent
		req.Header.Set("User-Agent", "CyberSense-Discovery/1.0")
		
		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(pc.timeout)*time.Second)
		req = req.WithContext(ctx)
		
		resp, err := pc.client.Do(req)
		cancel()
		
		if err == nil {
			responseTime = time.Since(start).Milliseconds()
			status = resp.StatusCode
			resp.Body.Close()
			return status, responseTime
		}
	}
	
	return 0, time.Since(start).Milliseconds()
}

// TLSConfig is a minimal TLS config to skip verification
type TLSConfig struct {
	InsecureSkipVerify bool
}

// DialTimeout is a helper function to create connections with timeout
func DialTimeout(network, address string, timeout int) (net.Conn, error) {
	return net.DialTimeout(network, address, time.Duration(timeout)*time.Second)
}
```

```go internal/discovery/domains/scanner_test.go
package domains

import (
	"context"
	"testing"
	"time"
)

func TestDomainScanner(t *testing.T) {
	// Create a scanner with a small wordlist for testing
	scanner := NewDomainScanner("example.com", "../../scripts/wordlists/subdomains.txt", 10, 5)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Run scan
	results, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	
	// Verify results structure
	if results.TargetDomain != "example.com" {
		t.Errorf("Expected target domain 'example.com', got %s", results.TargetDomain)
	}
	
	// Check that statistics are populated
	if results.Statistics.ScanDuration <= 0 {
		t.Error("Scan duration should be greater than 0")
	}
	
	t.Logf("Scan completed successfully. Found %d subdomains", len(results.Subdomains))
}
```

```:scripts/wordlists/subdomains.txt
www
mail
ftp
localhost
webmail
smtp
pop
ns1
ns2
ns3
dns
ns
blog
api
secure
shop
admin
portal
test
m
chat
images
cdn
files
cloud
dev
staging
demo
apps
app
mysql
sql
db
database
data
monitor
monitoring
status
stats
jenkins
confluence
wiki
git
github
bitbucket
jira
gitlab
mattermost
slack
vpn
ssh
ldap
office
fileshare
sharepoint
intranet
proxy
login
admin
backend
frontend
service
services
downloads
download
assets
static
media
upload
uploads
support
help
helpdesk
kb
knowledgebase
community
forum
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
boards
```

```go intense-scanner.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DiscoveryResult represents the complete result of a domain discovery scan
type DiscoveryResult struct {
	TargetDomain string           `json:"target_domain"`
	ScanTime     time.Time        `json:"scan_time"`
	Subdomains   []SubdomainInfo  `json:"subdomains"`
	Statistics   DiscoveryStats   `json:"statistics"`
}

// SubdomainInfo contains information about a discovered subdomain
type SubdomainInfo struct {
	Name         string `json:"name"`
	IPAddress    string `json:"ip_address"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	HTTPSStatus  int    `json:"https_status,omitempty"`
	HTTPPort     bool   `json:"http_port"`
	HTTPSPort    bool   `json:"https_port"`
	Responsive   bool   `json:"responsive"`
	ResponseTime int64  `json:"response_time_ms,omitempty"`
	TLSAvailable bool   `json:"tls_available,omitempty"`
}

// DiscoveryStats contains statistics about the discovery scan
type DiscoveryStats struct {
	TotalScanned     int           `json:"total_scanned"`
	ValidSubdomains  int           `json:"valid_subdomains"`
	ResponsiveHosts  int           `json:"responsive_hosts"`
	ScanDuration     time.Duration `json:"scan_duration"`
	OpenHTTPPorts    int           `json:"open_http_ports"`
	OpenHTTPSPorts   int           `json:"open_https_ports"`
	TLSServices      int           `json:"tls_services"`
}

// DomainScanner handles the complete domain discovery process
type DomainScanner struct {
	targetDomain string
	wordlistPath string
	concurrency  int
	timeout      int
}

// NewDomainScanner creates a new domain scanner instance
func NewDomainScanner(domain, wordlist string, concurrency, timeout int) *DomainScanner {
	return &DomainScanner{
		targetDomain: domain,
		wordlistPath: wordlist,
		concurrency:  concurrency,
		timeout:      timeout,
	}
}

// Scan performs the complete domain discovery process with enhanced features
func (ds *DomainScanner) Scan(ctx context.Context) (*DiscoveryResult, error) {
	startTime := time.Now()
	
	// Load wordlist
	wordlist, err := ds.loadWordlist()
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	// Create channels for processing
	jobs := make(chan string, len(wordlist))
	results := make(chan SubdomainInfo, len(wordlist))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < ds.concurrency; i++ {
		wg.Add(1)
		go ds.worker(ctx, &wg, jobs, results)
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, word := range wordlist {
			select {
			case jobs <- word:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var subdomains []SubdomainInfo
	for result := range results {
		subdomains = append(subdomains, result)
	}

	// Compile statistics
	stats := compileStatistics(subdomains, len(wordlist), time.Since(startTime))

	return &DiscoveryResult{
		TargetDomain: ds.targetDomain,
		ScanTime:     startTime,
		Subdomains:   subdomains,
		Statistics:   stats,
	}, nil
}

// loadWordlist loads subdomain wordlist from file
func (ds *DomainScanner) loadWordlist() ([]string, error) {
	file, err := os.Open(ds.wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %w", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" && !startsWithComment(word) {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return words, nil
}

// worker performs the actual scanning work
func (ds *DomainScanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- SubdomainInfo) {
	defer wg.Done()
	
	for {
		select {
		case word, ok := <-jobs:
			if !ok {
				return
			}
			
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Generate full domain name
			fullDomain := fmt.Sprintf("%s.%s", word, ds.targetDomain)
			
			// Resolve DNS with enhanced error handling
			ips, err := resolveDNS(fullDomain, ds.timeout)
			if err != nil {
				continue // Skip unresolved domains
			}

			// Check ports with enhanced detection
			httpPort, httpsPort, tlsAvailable := checkPorts(fullDomain, ds.timeout)
			
			// Create subdomain info
			subdomain := SubdomainInfo{
				Name:         fullDomain,
				IPAddress:    strings.Join(ips, ", "),
				HTTPPort:     httpPort,
				HTTPSPort:    httpsPort,
				TLSAvailable: tlsAvailable,
			}
			
			// Check responsiveness only if ports are open
			if httpPort || httpsPort {
				httpStatus, httpsStatus, responseTime := checkHTTPStatus(fullDomain, ds.timeout)
				subdomain.HTTPStatus = httpStatus
				subdomain.HTTPSStatus = httpsStatus
				subdomain.ResponseTime = responseTime
				subdomain.Responsive = httpStatus > 0 || httpsStatus > 0
			}

			// Send result
			select {
			case results <- subdomain:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// resolveDNS performs DNS resolution with timeout
func resolveDNS(domain string, timeout int) ([]string, error) {
	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	
	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Use Google's DNS server as default
	server := "8.8.8.8:53"
	
	// Perform DNS query
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	// Extract all IP addresses from response
	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records found for %s", domain)
	}

	return ips, nil
}

// checkPorts checks if common web ports are open with enhanced detection
func checkPorts(domain string, timeout int) (httpPort, httpsPort, tlsAvailable bool) {
	var wg sync.WaitGroup
	results := make(chan struct{ port string; open bool; tls bool }, 2)
	
	// Check HTTP port (80)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", domain+":80", time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			results <- struct{ port string; open bool; tls bool }{"http", true, false}
		} else {
			results <- struct{ port string; open bool; tls bool }{"http", false, false}
		}
	}()
	
	// Check HTTPS port (443)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", domain+":443", time.Duration(timeout)*time.Second)
		if err == nil {
			// Try to negotiate TLS
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         domain,
			})
			err = tlsConn.Handshake()
			tlsAvailable := err == nil
			if tlsAvailable {
				defer tlsConn.Close()
			}
			conn.Close()
			results <- struct{ port string; open bool; tls bool }{"https", true, tlsAvailable}
		} else {
			results <- struct{ port string; open bool; tls bool }{"https", false, false}
		}
	}()
	
	// Close results channel when done
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	for result := range results {
		if result.port == "http" {
			httpPort = result.open
		}
		if result.port == "https" {
			httpsPort = result.open
			tlsAvailable = result.tls
		}
	}
	
	return httpPort, httpsPort, tlsAvailable
}

// checkHTTPStatus performs HTTP requests to check service responsiveness
func checkHTTPStatus(domain string, timeout int) (httpStatus, httpsStatus int, responseTime int64) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	start := time.Now()
	
	// Check HTTPS first
	httpsURL := fmt.Sprintf("https://%s", domain)
	req, _ := http.NewRequest("GET", httpsURL, nil)
	req.Header.Set("User-Agent", "CyberSense-Discovery/1.0")
	
	resp, err := client.Do(req)
	if err == nil {
		httpsStatus = resp.StatusCode
		resp.Body.Close()
	}
	
	// If HTTPS failed or we want to check HTTP too
	if httpsStatus == 0 {
		httpURL := fmt.Sprintf("http://%s", domain)
		req, _ = http.NewRequest("GET", httpURL, nil)
		req.Header.Set("User-Agent", "CyberSense-Discovery/1.0")
		
		resp, err = client.Do(req)
		if err == nil {
			httpStatus = resp.StatusCode
			resp.Body.Close()
		}
	}
	
	responseTime = time.Since(start).Milliseconds()
	return httpStatus, httpsStatus, responseTime
}

// compileStatistics compiles scan statistics
func compileStatistics(subdomains []SubdomainInfo, totalScanned int, duration time.Duration) DiscoveryStats {
	var stats DiscoveryStats
	stats.TotalScanned = totalScanned
	stats.ValidSubdomains = len(subdomains)
	stats.ScanDuration = duration
	
	for _, sub := range subdomains {
		if sub.Responsive {
			stats.ResponsiveHosts++
		}
		if sub.HTTPPort {
			stats.OpenHTTPPorts++
		}
		if sub.HTTPSPort {
			stats.OpenHTTPSPorts++
		}
		if sub.TLSAvailable {
			stats.TLSServices++
		}
	}
	
	return stats
}

// Helper functions
func startsWithComment(line string) bool {
	return len(line) > 0 && line[0] == '#'
}

func main() {
	// Parse command line flags
	domain := flag.String("domain", "", "Target domain to scan")
	concurrency := flag.Int("concurrency", 100, "Number of concurrent workers")
	wordlist := flag.String("wordlist", "scripts/wordlists/subdomains.txt", "Path to subdomain wordlist")
	timeout := flag.Int("timeout", 10, "Timeout for requests in seconds")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Domain is required. Use -domain flag to specify target domain")
	}

	// Create discovery context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Initialize the domain scanner
	scanner := NewDomainScanner(*domain, *wordlist, *concurrency, *timeout)

	// Start the scan
	fmt.Printf("Starting intensive domain discovery for: %s\n", *domain)
	fmt.Printf("Using wordlist: %s\n", *wordlist)
	fmt.Printf("Concurrency level: %d\n", *concurrency)
	fmt.Printf("Timeout: %d seconds\n", *timeout)

	results, err := scanner.Scan(ctx)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results as JSON
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal results: %v", err)
	}

	// Save to file
	filename := fmt.Sprintf("intense_discovery_results_%s.json", time.Now().Format("20060102_150405"))
	if err := os.WriteFile(filename, output, 0644); err != nil {
		log.Printf("Warning: Could not save results to file: %v", err)
	}

	// Print summary
	fmt.Printf("\nIntensive discovery completed!\n")
	fmt.Printf("Found %d subdomains\n", len(results.Subdomains))
	fmt.Printf("Results saved to: %s\n", filename)
	
	// Print brief statistics
	fmt.Printf("\n=== Scan Statistics ===\n")
	fmt.Printf("Total subdomains scanned: %d\n", results.Statistics.TotalScanned)
	fmt.Printf("Valid subdomains found: %d\n", results.Statistics.ValidSubdomains)
	fmt.Printf("Responsive hosts: %d\n", results.Statistics.ResponsiveHosts)
	fmt.Printf("Open HTTP ports: %d\n", results.Statistics.OpenHTTPPorts)
	fmt.Printf("Open HTTPS ports: %d\n", results.Statistics.OpenHTTPSPorts)
	fmt.Printf("TLS-enabled services: %d\n", results.Statistics.TLSServices)
	fmt.Printf("Scan duration: %s\n", results.Statistics.ScanDuration)
}