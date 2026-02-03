package passive

import (
	"fmt"
	"log"
	"time"
)

// Orchestrator runs all passive reconnaissance modules
type Orchestrator struct {
	crtsh *CrtShScanner
	dns   *DNSScanner
	tech  *TechScanner
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		crtsh: NewCrtShScanner(),
		dns:   NewDNSScanner(),
		tech:  NewTechScanner(),
	}
}

// RunPassiveRecon executes all passive recon modules
func (o *Orchestrator) RunPassiveRecon(target string) (*PassiveIntelligence, error) {
	log.Printf("[Passive] Starting reconnaissance for %s", target)
	
	intel := &PassiveIntelligence{
		Target:    target,
		StartedAt: time.Now(),
	}
	
	// 1. Certificate Transparency - Subdomain Discovery
	log.Printf("[Passive] Querying Certificate Transparency logs...")
	subdomains, err := o.crtsh.GetSubdomains(target)
	if err != nil {
		log.Printf("[Passive] Warning: crt.sh failed: %v", err)
	} else {
		intel.Subdomains = subdomains
		log.Printf("[Passive] Found %d subdomains from CT logs", len(subdomains))
	}
	
	// 2. DNS Intelligence
	log.Printf("[Passive] Gathering DNS records...")
	dnsRecords, err := o.dns.GetDNSRecords(target)
	if err != nil {
		log.Printf("[Passive] Warning: DNS lookup failed: %v", err)
	} else {
		intel.DNSRecords = dnsRecords
		log.Printf("[Passive] Retrieved DNS records: %d types", len(dnsRecords))
	}
	
	// Check for SPF/DMARC
	if txtRecords, ok := dnsRecords["TXT"]; ok {
		spf := o.dns.GetSPFRecord(txtRecords)
		if spf != "" {
			log.Printf("[Passive] SPF Record: %s", spf)
		}
	}
	
	dmarc := o.dns.GetDMARCRecord(target)
	if dmarc != "" {
		log.Printf("[Passive] DMARC Record: %s", dmarc)
	}
	
	// 3. Technology Detection
	log.Printf("[Passive] Detecting technologies...")
	targetURL := fmt.Sprintf("https://%s", target)
	technologies, err := o.tech.DetectTechnologies(targetURL)
	if err != nil {
		// Try HTTP if HTTPS fails
		targetURL = fmt.Sprintf("http://%s", target)
		technologies, err = o.tech.DetectTechnologies(targetURL)
		if err != nil {
			log.Printf("[Passive] Warning: Technology detection failed: %v", err)
		}
	}
	
	if technologies != nil {
		intel.Technologies = technologies
		log.Printf("[Passive] Detected %d technologies", len(technologies))
	}
	
	intel.CompletedAt = time.Now()
	duration := intel.CompletedAt.Sub(intel.StartedAt)
	log.Printf("[Passive] Reconnaissance complete in %v", duration)
	
	return intel, nil
}

// GetSummary returns a summary of the intelligence gathered
func (intel *PassiveIntelligence) GetSummary() string {
	return fmt.Sprintf(
		"Target: %s | Subdomains: %d | DNS Records: %d types | Technologies: %d | Duration: %v",
		intel.Target,
		len(intel.Subdomains),
		len(intel.DNSRecords),
		len(intel.Technologies),
		intel.CompletedAt.Sub(intel.StartedAt),
	)
}
