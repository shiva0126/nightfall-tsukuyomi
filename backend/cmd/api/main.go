package main

import (
	"log"
	"github.com/gin-gonic/gin"
)

func main() {
	// Set Gin mode
	gin.SetMode(gin.DebugMode)

	// Create router
	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "nightfall-tsukuyomi",
			"version": "1.0.0",
		})
	})

	// API v1 group
	v1 := router.Group("/api/v1")
	{
		// Scans endpoints
		v1.GET("/scans", listScans)
		v1.POST("/scans", createScan)
		v1.GET("/scans/:id", getScan)
		v1.GET("/scans/:id/status", getScanStatus)
		
		// Targets endpoints
		v1.GET("/targets", listTargets)
		v1.POST("/targets", createTarget)
	}

	// Start server
	log.Println("🌙 Nightfall Tsukuyomi API starting on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Handler functions
func listScans(c *gin.Context) {
	c.JSON(200, gin.H{
		"scans": []gin.H{
			{
				"id":         1,
				"target":     "example.com",
				"status":     "completed",
				"risk_score": 72,
				"started_at": "2025-02-03T10:00:00Z",
			},
		},
	})
}

func createScan(c *gin.Context) {
	var req struct {
		Target string `json:"target" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, gin.H{
		"id":      "scan_" + req.Target,
		"target":  req.Target,
		"status":  "pending",
		"message": "Scan initiated",
	})
}

func getScan(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{
		"id":           id,
		"target":       "example.com",
		"status":       "completed",
		"risk_score":   72,
		"risk_grade":   "MEDIUM",
		"findings":     15,
		"started_at":   "2025-02-03T10:00:00Z",
		"completed_at": "2025-02-03T10:15:00Z",
	})
}

func getScanStatus(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{
		"id":       id,
		"status":   "running",
		"progress": 45,
		"message":  "Scanning headers and TLS configuration...",
	})
}

func listTargets(c *gin.Context) {
	c.JSON(200, gin.H{
		"targets": []gin.H{
			{"id": 1, "domain": "example.com", "last_scanned": "2025-02-03T10:00:00Z"},
			{"id": 2, "domain": "test.com", "last_scanned": "2025-02-02T14:30:00Z"},
		},
	})
}

func createTarget(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(201, gin.H{
		"id":         100,
		"domain":     req.Domain,
		"created_at": "2025-02-03T12:00:00Z",
	})
}
