package services

import (
	"encoding/json"
	"log"
	"time"
	
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/database"
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/models"
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/passive"
)

// ScanService handles scan operations
type ScanService struct {
	passiveOrch *passive.Orchestrator
}

func NewScanService() *ScanService {
	return &ScanService{
		passiveOrch: passive.NewOrchestrator(),
	}
}

// CreateScanWithPassiveRecon creates a scan and runs passive recon
func (s *ScanService) CreateScanWithPassiveRecon(targetID uint, domain string) (*models.Scan, error) {
	// Create the scan
	scan := models.Scan{
		TargetID:  targetID,
		Status:    "running",
		RiskScore: 0,
	}
	
	if err := database.DB.Create(&scan).Error; err != nil {
		return nil, err
	}
	
	log.Printf("[Scan #%d] Created for target: %s", scan.ID, domain)
	
	// Run passive recon in background
	go s.runPassiveRecon(scan.ID, domain)
	
	return &scan, nil
}

// runPassiveRecon executes passive reconnaissance
func (s *ScanService) runPassiveRecon(scanID uint, domain string) {
	log.Printf("[Scan #%d] Starting passive reconnaissance...", scanID)
	
	// Update scan status
	database.DB.Model(&models.Scan{}).Where("id = ?", scanID).Update("status", "passive_recon")
	
	// Run passive recon
	intel, err := s.passiveOrch.RunPassiveRecon(domain)
	if err != nil {
		log.Printf("[Scan #%d] Passive recon failed: %v", scanID, err)
		database.DB.Model(&models.Scan{}).Where("id = ?", scanID).Update("status", "failed")
		return
	}
	
	// Save intelligence to database
	if err := s.saveIntelligence(scanID, intel); err != nil {
		log.Printf("[Scan #%d] Failed to save intelligence: %v", scanID, err)
	}
	
	// Create findings from passive intel
	s.createFindingsFromIntel(scanID, intel)
	
	// Update scan status
	database.DB.Model(&models.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"status":       "completed",
		"completed_at": time.Now(),
	})
	
	log.Printf("[Scan #%d] Passive reconnaissance completed: %s", scanID, intel.GetSummary())
}

// saveIntelligence stores passive intelligence in database
func (s *ScanService) saveIntelligence(scanID uint, intel *passive.PassiveIntelligence) error {
	subdomainsJSON, _ := json.Marshal(intel.Subdomains)
	dnsRecordsJSON, _ := json.Marshal(intel.DNSRecords)
	technologiesJSON, _ := json.Marshal(intel.Technologies)
	rawDataJSON, _ := json.Marshal(intel)
	
	intelligence := models.Intelligence{
		ScanID:       scanID,
		Target:       intel.Target,
		Subdomains:   string(subdomainsJSON),
		DNSRecords:   string(dnsRecordsJSON),
		Technologies: string(technologiesJSON),
		RawData:      string(rawDataJSON),
	}
	
	return database.DB.Create(&intelligence).Error
}

// createFindingsFromIntel generates findings from passive intelligence
func (s *ScanService) createFindingsFromIntel(scanID uint, intel *passive.PassiveIntelligence) {
	// Finding: Subdomain count
	if len(intel.Subdomains) > 0 {
		finding := models.Finding{
			ScanID:      scanID,
			Severity:    "Info",
			Category:    "Discovery",
			Finding:     "Subdomains discovered via Certificate Transparency",
			Remediation: "Review subdomain inventory and ensure all are properly secured",
			Evidence:    string(mustMarshal(intel.Subdomains)),
		}
		database.DB.Create(&finding)
	}
	
	// Finding: Missing SPF/DMARC
	if txtRecords, ok := intel.DNSRecords["TXT"]; ok {
		hasSpF := false
		for _, txt := range txtRecords {
			if len(txt) >= 6 && txt[:6] == "v=spf1" {
				hasSpF = true
				break
			}
		}
		if !hasSpF {
			finding := models.Finding{
				ScanID:      scanID,
				Severity:    "Medium",
				Category:    "Email Security",
				Finding:     "Missing or misconfigured SPF record",
				Remediation: "Configure SPF record to prevent email spoofing",
				Evidence:    "No SPF record found in TXT records",
			}
			database.DB.Create(&finding)
		}
	}
	
	// Finding: Technologies detected
	if len(intel.Technologies) > 0 {
		for _, tech := range intel.Technologies {
			severity := "Info"
			if tech.Version != "" {
				severity = "Low" // Version disclosure
			}
			
			finding := models.Finding{
				ScanID:      scanID,
				Severity:    severity,
				Category:    "Technology Detection",
				Finding:     "Technology detected: " + tech.Name + " " + tech.Version,
				Remediation: "Review technology stack and ensure versions are up to date",
				Evidence:    tech.Source,
			}
			database.DB.Create(&finding)
		}
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
