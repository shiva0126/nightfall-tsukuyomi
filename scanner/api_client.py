import requests
import json
from typing import Dict, Any

API_BASE_URL = "http://localhost:8888/api/v1"

class NightfallAPI:
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
    
    def create_target(self, domain: str) -> Dict[str, Any]:
        """Create a new target"""
        try:
            response = self.session.post(
                f"{self.base_url}/targets",
                json={"domain": domain}
            )
            return response.json()
        except Exception as e:
            print(f"Failed to create target: {e}")
            return {}
    
    def create_scan(self, domain: str) -> Dict[str, Any]:
        """Create a new scan"""
        try:
            response = self.session.post(
                f"{self.base_url}/scans",
                json={"domain": domain}
            )
            return response.json()
        except Exception as e:
            print(f"Failed to create scan: {e}")
            return {}
    
    def update_scan_status(self, scan_id: int, status: str, risk_score: int = 0):
        """Update scan status (placeholder - we'll implement this endpoint later)"""
        print(f"[API] Scan #{scan_id} - Status: {status}, Risk: {risk_score}")
    
    def send_finding(self, scan_id: int, finding: Dict[str, Any]):
        """Send a finding (placeholder - we'll implement this endpoint later)"""
        print(f"[API] Scan #{scan_id} - Finding: {finding.get('severity')} - {finding.get('finding')[:50]}")

# Global API client
api = NightfallAPI()
