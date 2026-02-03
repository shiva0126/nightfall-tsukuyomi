package handlers

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/database"
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/models"
)

// CreateFinding adds a new finding to a scan
func CreateFinding(c *gin.Context) {
	var req struct {
		ScanID      uint   `json:"scan_id" binding:"required"`
		Severity    string `json:"severity" binding:"required"`
		Category    string `json:"category" binding:"required"`
		Finding     string `json:"finding" binding:"required"`
		Remediation string `json:"remediation"`
		Evidence    string `json:"evidence"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	finding := models.Finding{
		ScanID:      req.ScanID,
		Severity:    req.Severity,
		Category:    req.Category,
		Finding:     req.Finding,
		Remediation: req.Remediation,
		Evidence:    req.Evidence,
	}

	if err := database.DB.Create(&finding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create finding"})
		return
	}

	c.JSON(http.StatusCreated, finding)
}

// UpdateScanStatus updates scan status and risk score
func UpdateScanStatus(c *gin.Context) {
	scanID := c.Param("id")
	
	var req struct {
		Status    string `json:"status"`
		RiskScore int    `json:"risk_score"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var scan models.Scan
	if err := database.DB.First(&scan, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	scan.Status = req.Status
	scan.RiskScore = req.RiskScore

	if err := database.DB.Save(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scan"})
		return
	}

	c.JSON(http.StatusOK, scan)
}
