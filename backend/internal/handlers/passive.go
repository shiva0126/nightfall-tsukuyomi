package handlers

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/shiva0126/nightfall-tsukuyomi/backend/internal/passive"
)

// RunPassiveRecon executes passive reconnaissance on a target
func RunPassiveRecon(c *gin.Context) {
	var req struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	orchestrator := passive.NewOrchestrator()
	intel, err := orchestrator.RunPassiveRecon(req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to run passive recon",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"intelligence": intel,
		"summary": intel.GetSummary(),
	})
}
