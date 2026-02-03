package passive

import (
	"net/http"
	"strings"
	"time"
)

// TechScanner detects technologies from HTTP responses
type TechScanner struct {
	client *http.Client
}

func NewTechScanner() *TechScanner {
	return &TechScanner{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
	}
}

// DetectTechnologies analyzes HTTP response to detect technologies
func (s *TechScanner) DetectTechnologies(url string) ([]Technology, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", "Nightfall-Tsukuyomi/1.0")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var technologies []Technology
	
	// Detect from Server header
	if server := resp.Header.Get("Server"); server != "" {
		tech := parseTechnology(server, "Server Header")
		technologies = append(technologies, tech)
	}
	
	// Detect from X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		tech := parseTechnology(poweredBy, "X-Powered-By Header")
		technologies = append(technologies, tech)
	}
	
	// Detect from X-Generator header
	if generator := resp.Header.Get("X-Generator"); generator != "" {
		technologies = append(technologies, Technology{
			Name:       generator,
			Version:    "",
			Confidence: "Medium",
			Source:     "X-Generator Header",
		})
	}
	
	// Detect from cookies
	for _, cookie := range resp.Cookies() {
		if tech := detectFromCookie(cookie.Name); tech != nil {
			technologies = append(technologies, *tech)
		}
	}
	
	return technologies, nil
}

// parseTechnology extracts name and version from a technology string
func parseTechnology(techString, source string) Technology {
	parts := strings.Split(techString, "/")
	
	if len(parts) >= 2 {
		// Format: "nginx/1.18.0" or "Apache/2.4.41"
		name := parts[0]
		version := strings.Split(parts[1], " ")[0] // Handle "1.18.0 (Ubuntu)"
		
		return Technology{
			Name:       name,
			Version:    version,
			Confidence: "High",
			Source:     source,
		}
	}
	
	// No version info
	return Technology{
		Name:       techString,
		Version:    "",
		Confidence: "Medium",
		Source:     source,
	}
}

// detectFromCookie detects technology from cookie names
func detectFromCookie(cookieName string) *Technology {
	cookieName = strings.ToLower(cookieName)
	
	cookiePatterns := map[string]string{
		"phpsessid":     "PHP",
		"jsessionid":    "Java/JSP",
		"asp.net_sessionid": "ASP.NET",
		"cfid":          "ColdFusion",
		"ci_session":    "CodeIgniter",
		"laravel_session": "Laravel",
		"django":        "Django",
		"express.sid":   "Express.js",
	}
	
	for pattern, tech := range cookiePatterns {
		if strings.Contains(cookieName, pattern) {
			return &Technology{
				Name:       tech,
				Version:    "",
				Confidence: "High",
				Source:     "Cookie",
			}
		}
	}
	
	return nil
}
