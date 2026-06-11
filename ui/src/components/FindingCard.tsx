import SeverityBadge from './SeverityBadge';

interface StaticMatch {
  path: string;
  evidence: string;
  detail: string;
}

interface StaticFindingData {
  mode?: string;
  ruleId: string;
  ruleName: string;
  category: string;
  severity: string;
  serverName: string;
  matches: StaticMatch[];
  riskScore: number;
  remediation: string;
  owaspRefs?: string[];
  slowmistRef?: string;
}

interface EvidenceItem {
  type: string;
  description: string;
  excerpt?: string;
}

interface DynamicFindingData {
  mode?: string;
  payloadId: string;
  payloadName: string;
  category: string;
  severity: string;
  riskScore: number;
  detectionMethod: string;
  confidence: number;
  evidence: EvidenceItem[];
  runs: number;
  successCount: number;
  remediation: string;
  reproductionCommand: string;
  owaspRefs?: string[];
  slowmistRef?: string;
  toolName?: string;
  testSurface?: string;
}

type FindingData = StaticFindingData | DynamicFindingData;

function isStatic(f: FindingData): f is StaticFindingData {
  return 'ruleId' in f;
}

export default function FindingCard({ finding }: { finding: FindingData }) {
  if (isStatic(finding)) {
    return (
      <div className="card finding-card">
        <div className="finding-header">
          <span className="finding-id">{finding.ruleId}</span>
          <span className="finding-name">{finding.ruleName}</span>
          <SeverityBadge severity={finding.severity} />
          <span className="risk-score">Risk: {finding.riskScore.toFixed(1)}</span>
        </div>
        <div className="finding-meta">
          <span>Server: {finding.serverName}</span>
          <span>Category: {finding.category}</span>
          {finding.owaspRefs && finding.owaspRefs.length > 0 && (
            <span>OWASP: {finding.owaspRefs.join(', ')}</span>
          )}
        </div>
        {finding.matches.length > 0 && (
          <div className="finding-matches">
            <strong>Matches:</strong>
            {finding.matches.map((m, i) => (
              <div key={i} className="match-item">
                <div className="match-path">Path: {m.path}</div>
                <div className="match-evidence">Evidence: <code>{m.evidence}</code></div>
                <div className="match-detail">{m.detail}</div>
              </div>
            ))}
          </div>
        )}
        <div className="finding-remediation">
          <strong>Remediation:</strong> {finding.remediation}
        </div>
      </div>
    );
  }

  // Dynamic finding
  const successRate = finding.runs > 0
    ? Math.round((finding.successCount / finding.runs) * 100)
    : 0;

  return (
    <div className="card finding-card">
      <div className="finding-header">
        <span className="finding-id">{finding.payloadId}</span>
        <span className="finding-name">{finding.payloadName}</span>
        <SeverityBadge severity={finding.severity} />
        <span className="risk-score">Risk: {finding.riskScore.toFixed(1)}</span>
      </div>
      <div className="finding-meta">
        <span>Category: {finding.category}</span>
        <span>Detection: {finding.detectionMethod} (confidence: {finding.confidence.toFixed(2)})</span>
        <span>Success: {finding.successCount}/{finding.runs} ({successRate}%)</span>
        {finding.toolName && <span>Tool: {finding.toolName}</span>}
        {finding.testSurface && <span>Surface: {finding.testSurface}</span>}
      </div>
      {finding.evidence.length > 0 && (
        <div className="finding-matches">
          <strong>Evidence:</strong>
          {finding.evidence.map((e, i) => (
            <div key={i} className="match-item">
              <div className="match-detail">{e.description}</div>
              {e.excerpt && <div className="match-evidence"><code>{e.excerpt}</code></div>}
            </div>
          ))}
        </div>
      )}
      {finding.reproductionCommand && (
        <div className="finding-reproduce">
          <strong>Reproduce:</strong> <code>{finding.reproductionCommand}</code>
        </div>
      )}
      <div className="finding-remediation">
        <strong>Remediation:</strong> {finding.remediation}
      </div>
    </div>
  );
}
