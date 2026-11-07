/**
 * API service for communicating with TRUSTX AI backend.
 */

const API_BASE = import.meta.env.VITE_API_URL || 
  (typeof window !== 'undefined' && window.location.hostname === 'localhost' 
    ? 'http://localhost:8000' 
    : 'https://trustx-api.onrender.com');

/**
 * Scan a URL for phishing detection.
 * @param {string} url - URL to scan
 * @returns {Promise<object>} Prediction result
 */
export async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Get scan history.
 * @param {object} params - Query parameters
 * @returns {Promise<object>} History data
 */
export async function getHistory(params = {}) {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(`${API_BASE}/history?${query}`);
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Report a URL.
 * @param {object} report - Report data
 * @returns {Promise<object>} Report response
 */
export async function reportUrl(report) {
  const response = await fetch(`${API_BASE}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report),
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Get analytics statistics.
 * @returns {Promise<object>} Stats data
 */
export async function getStats() {
  const response = await fetch(`${API_BASE}/stats`);
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Get model information.
 * @returns {Promise<object>} Model metadata
 */
export async function getModelInfo() {
  const response = await fetch(`${API_BASE}/model-info`);
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  return response.json();
}

/**
 * Check API health.
 * @returns {Promise<boolean>} API health status
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE}/health`, {
      signal: AbortSignal.timeout(5000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * List available training visualization plots.
 * @returns {Promise<object>} List of plot filenames
 */
export async function listPlots() {
  const response = await fetch(`${API_BASE}/plots/list`)
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`)
  }
  return response.json()
}

/**
 * Run comprehensive 10-step AI investigation.
 * @param {string} url - Target URL to investigate
 * @returns {Promise<object>} Full multi-module investigation report with Trust Score
 */
export async function investigateUrl(url) {
  const response = await fetch(`${API_BASE}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Investigation error: ${response.status}`);
  }
  return response.json();
}

/**
 * Retrieve saved investigation report by ID.
 * @param {string} id - Investigation ID
 * @returns {Promise<object>} Stored report
 */
export async function getInvestigation(id) {
  const response = await fetch(`${API_BASE}/investigation/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to load investigation: ${response.status}`);
  }
  return response.json();
}

/**
 * Upload and decode a QR code image to inspect embedded destination.
 * @param {File} file - QR code image file
 * @returns {Promise<object>} QR decoding result and automated investigation
 */
export async function scanQrCode(file) {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE}/qr/scan`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `QR Scan error: ${response.status}`);
  }
  return response.json();
}

/**
 * Get interactive threat relationship graph for a domain.
 * @param {string} domain - Domain name
 * @returns {Promise<object>} Graph nodes and edges
 */
export async function getThreatGraph(domain) {
  const response = await fetch(`${API_BASE}/threat-intel/graph/${encodeURIComponent(domain)}`);
  if (!response.ok) {
    throw new Error(`Failed to load threat graph: ${response.status}`);
  }
  return response.json();
}

/**
 * Get threat intelligence metrics and community reports.
 * @returns {Promise<object>} Threat summary data
 */
export async function getThreatSummary() {
  const response = await fetch(`${API_BASE}/threat-intel/summary`);
  if (!response.ok) {
    throw new Error(`Failed to load threat intel: ${response.status}`);
  }
  return response.json();
}

/**
 * Submit community upvote or downvote for a threat report.
 * @param {string} urlHash - MD5 hash of reported URL
 * @param {string} voteType - 'upvote' or 'downvote'
 * @returns {Promise<object>} Vote result
 */
export async function voteThreatReport(urlHash, voteType) {
  const response = await fetch(`${API_BASE}/community/vote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url_hash: urlHash, vote_type: voteType }),
  });
  if (!response.ok) {
    throw new Error(`Failed to submit vote: ${response.status}`);
  }
  return response.json();
}
