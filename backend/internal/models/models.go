package models

import "time"

type Target struct {
	ID            uint       `json:"id" gorm:"primaryKey"`
	Domain        string     `json:"domain" gorm:"unique;not null"`
	CreatedAt     time.Time  `json:"created_at"`
	LastScannedAt *time.Time `json:"last_scanned_at"`
}

type Scan struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	TargetID    uint       `json:"target_id"`
	Status      string     `json:"status"`
	RiskScore   int        `json:"risk_score"`
	StartedAt   time.Time  `json:"started_at" gorm:"autoCreateTime"`
	CompletedAt *time.Time `json:"completed_at"`
}

type Finding struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ScanID      uint      `json:"scan_id"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Finding     string    `json:"finding"`
	Remediation string    `json:"remediation"`
	Evidence    string    `json:"evidence"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
}
