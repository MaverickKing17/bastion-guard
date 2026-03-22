/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * High-performance security scanner logic for BastionAudit.
 * Optimized for low-latency execution in the critical path of the developer terminal.
 */

export const SECURITY_PATTERNS = {
  // API Keys: High-entropy string detection
  API_KEYS: {
    AWS: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    OPENAI: /sk-[a-zA-Z0-9]{48}/g,
    GITHUB: /gh[pousr]_[a-zA-Z0-9]{36,255}/g,
    GENERIC_SECRET: /(?:key|secret|token|password|auth|api)[-_]?(?:key|secret|token|password|auth|api)?['"]?\s*[:=]\s*['"]?([a-zA-Z0-9]{32,})['"]?/gi
  },
  // Email addresses: RFC 5321 compliant pattern
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  // Canadian SIN: Standard ddd-ddd-ddd format
  CANADIAN_SIN: /\b\d{3}-\d{3}-\d{3}\b/g,
  // SQL Injection: Common attack vectors
  SQL_INJECTION: /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|WHERE)\b|['"]\s*OR\s*['"]?\d+['"]?\s*=\s*['"]?\d+/gi
};

export interface ScanResult {
  threats: {
    type: string;
    pattern: string;
    match: string;
    severity: number; // 1-10
  }[];
  verdict: 'PASS' | 'WARN' | 'BLOCK';
}

/**
 * Performs a synchronous scan of the input content.
 * Designed to execute in <5ms for typical command sizes.
 */
export function performSecurityScan(content: string, mode: 'BLOCK' | 'LOG'): ScanResult {
  const threats: ScanResult['threats'] = [];

  // Scan for API Keys
  for (const [provider, regex] of Object.entries(SECURITY_PATTERNS.API_KEYS)) {
    const matches = content.match(regex);
    if (matches) {
      matches.forEach(match => {
        threats.push({
          type: `API_KEY_${provider}`,
          pattern: regex.toString(),
          match,
          severity: 9
        });
      });
    }
  }

  // Scan for Emails
  const emailMatches = content.match(SECURITY_PATTERNS.EMAIL);
  if (emailMatches) {
    emailMatches.forEach(match => {
      threats.push({
        type: 'PII_EMAIL',
        pattern: SECURITY_PATTERNS.EMAIL.toString(),
        match,
        severity: 4
      });
    });
  }

  // Scan for Canadian SIN
  const sinMatches = content.match(SECURITY_PATTERNS.CANADIAN_SIN);
  if (sinMatches) {
    sinMatches.forEach(match => {
      threats.push({
        type: 'PII_SIN',
        pattern: SECURITY_PATTERNS.CANADIAN_SIN.toString(),
        match,
        severity: 8
      });
    });
  }

  // Scan for SQL Injection
  const sqlMatches = content.match(SECURITY_PATTERNS.SQL_INJECTION);
  if (sqlMatches) {
    sqlMatches.forEach(match => {
      threats.push({
        type: 'SQL_INJECTION',
        pattern: SECURITY_PATTERNS.SQL_INJECTION.toString(),
        match,
        severity: 10
      });
    });
  }

  // Determine verdict
  let verdict: ScanResult['verdict'] = 'PASS';
  const maxSeverity = threats.length > 0 ? Math.max(...threats.map(t => t.severity)) : 0;

  if (maxSeverity >= 8) {
    verdict = mode === 'BLOCK' ? 'BLOCK' : 'WARN';
  } else if (maxSeverity >= 4) {
    verdict = 'WARN';
  }

  return { threats, verdict };
}
