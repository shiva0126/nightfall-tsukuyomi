package passive

import "time"

// PassiveIntelligence holds all passive recon results
type PassiveIntelligence struct {
	Target      string                 `json:"target"`
	Subdomains  []string               `json:"subdomains"`
	DNSRecords  map[string][]string    `json:"dns_records"`
	WHOIS       *WHOISData             `json:"whois"`
	Technologies []Technology          `json:"technologies"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
}

// WHOISData holds domain registration info
type WHOISData struct {
	Registrar    string    `json:"registrar"`
	CreatedDate  string    `json:"created_date"`
	ExpiryDate   string    `json:"expiry_date"`
	NameServers  []string  `json:"name_servers"`
	Organization string    `json:"organization"`
}

// Technology detected from target
type Technology struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Confidence string  `json:"confidence"` // High, Medium, Low
	Source     string  `json:"source"`     // Header, Body, etc
}
