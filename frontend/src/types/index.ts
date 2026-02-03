export interface Target {
  id: number;
  domain: string;
  created_at: string;
  last_scanned_at: string | null;
}

export interface Scan {
  id: number;
  target_id: number;
  status: string;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  severity: string;
  category: string;
  finding: string;
  remediation: string;
  evidence: string;
}
