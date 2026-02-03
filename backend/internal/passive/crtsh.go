package passive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CrtShEntry represents a certificate transparency log entry
type CrtShEntry struct {
	NameValue string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// CrtShScanner queries crt.sh for subdomains
type CrtShScanner struct {
	client *http.Client
}

func NewCrtShScanner() *CrtShScanner {
	return &CrtShScanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetSubdomains queries crt.sh for all subdomains of a domain
func (s *CrtShScanner) GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("User-Agent", "Nightfall-Tsukuyomi/1.0")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Extract unique subdomains
	subdomainSet := make(map[string]bool)
	for _, entry := range entries {
		// Handle multi-domain certificates
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			d = strings.ToLower(d)
			
			// Remove wildcards
			d = strings.TrimPrefix(d, "*.")
			
			// Only include subdomains of the target
			if strings.HasSuffix(d, domain) || d == domain {
				subdomainSet[d] = true
			}
		}
	}
	
	// Convert to slice
	subdomains := make([]string, 0, len(subdomainSet))
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}
	
	return subdomains, nil
}
