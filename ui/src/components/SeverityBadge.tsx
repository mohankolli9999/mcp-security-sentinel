const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_CLASSES[severity] ?? 'severity-low';
  return <span className={`severity-badge ${cls}`}>{severity.toUpperCase()}</span>;
}
