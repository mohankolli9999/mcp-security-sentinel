import chalk from 'chalk';
import fs from 'fs';
import type { ScanResult, ScanFinding, Severity, SentinelResult, InspectResult, AttackResult, StaticFinding } from './types.js';

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.yellow.bold,
  medium: chalk.cyan.bold,
  low: chalk.white.bold,
};

const REDACTION_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /ghp_[A-Za-z0-9]{10,}/g, replacement: 'ghp_***REDACTED***' },
  { pattern: /gho_[A-Za-z0-9]{10,}/g, replacement: 'gho_***REDACTED***' },
  { pattern: /github_pat_[A-Za-z0-9_]{10,}/g, replacement: 'github_pat_***REDACTED***' },
  { pattern: /sk-[A-Za-z0-9]{10,}/g, replacement: 'sk-***REDACTED***' },
  { pattern: /pk-[A-Za-z0-9]{10,}/g, replacement: 'pk-***REDACTED***' },
  { pattern: /AKIA[A-Z0-9]{12,}/g, replacement: 'AKIA***REDACTED***' },
  { pattern: /Bearer\s+eyJ[A-Za-z0-9._-]+/g, replacement: 'Bearer ***REDACTED***' },
  { pattern: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, replacement: 'eyJ***REDACTED***' },
];

export function redactSensitiveText(text: string): string {
  let result = text;
  for (const { pattern, replacement } of REDACTION_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

export function toRedactedJson(result: SentinelResult): SentinelResult {
  const json = JSON.stringify(result);
  const redacted = redactSensitiveText(json);
  return JSON.parse(redacted) as SentinelResult;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatFinding(finding: ScanFinding): string {
  const colorFn = SEVERITY_COLOR[finding.severity] ?? chalk.white;
  const badge = colorFn(`[${finding.severity.toUpperCase()}]`);
  const successRate = finding.runs > 0
    ? Math.round((finding.successCount / finding.runs) * 100)
    : 0;
  const lines: string[] = [
    `● ${finding.payloadId}  ${finding.payloadName}  ${badge}  Risk: ${finding.riskScore.toFixed(1)}`,
    `  Surface:   ${finding.testSurface}`,
    `  OWASP:     ${finding.owaspRefs.join(', ')}`,
    `  SlowMist:  ${finding.slowmistRef}`,
    `  Detection: ${capitalize(finding.detectionMethod)} (confidence: ${finding.confidence.toFixed(2)})`,
  ];

  if (finding.evidence.length > 0) {
    lines.push(`  Evidence:`);
    for (const e of finding.evidence) {
      const excerpt = e.excerpt ? `: "${e.excerpt}"` : '';
      lines.push(`    • ${e.description}${excerpt}`);
    }
  }

  lines.push(
    `  Runs:      ${finding.successCount}/${finding.runs} succeeded (${successRate}% attack success rate)`,
    `  Reproduce:`,
    `    ${finding.reproductionCommand}`,
    `  Remediation:`,
    `    ${finding.remediation}`,
  );

  return lines.join('\n');
}

function formatStaticFinding(finding: StaticFinding): string {
  const colorFn = SEVERITY_COLOR[finding.severity] ?? chalk.white;
  const badge = colorFn(`[${finding.severity.toUpperCase()}]`);
  const lines: string[] = [
    `● ${finding.ruleId}  ${finding.ruleName}  ${badge}  Risk: ${finding.riskScore.toFixed(1)}`,
    `  Server:    ${finding.serverName}`,
    `  OWASP:     ${finding.owaspRefs.join(', ')}`,
    `  SlowMist:  ${finding.slowmistRef}`,
  ];

  if (finding.matches.length > 0) {
    lines.push(`  Matches:`);
    for (const m of finding.matches) {
      const redactedEvidence = redactSensitiveText(m.evidence);
      const redactedDetail = redactSensitiveText(m.detail);
      lines.push(`    • Path: ${m.path}`);
      lines.push(`      Evidence: ${redactedEvidence}`);
      lines.push(`      Detail: ${redactedDetail}`);
    }
  }

  lines.push(
    `  Remediation:`,
    `    ${finding.remediation}`,
  );

  return lines.join('\n');
}

function printInspectReport(result: InspectResult): void {
  const divider = chalk.dim('─'.repeat(60));

  console.log(chalk.bold('\n MCP Security Sentinel — Inspect Report'));
  console.log(chalk.dim('═'.repeat(60)));
  console.log(`Target:             ${result.target}`);
  console.log(`Timestamp:          ${result.scanTimestamp}`);
  console.log(`Servers Inspected:  ${result.serversInspected}`);
  console.log(divider);

  if (result.findings.length === 0) {
    console.log(chalk.green('\n✓ No security findings detected.\n'));
  } else {
    console.log(`\n${chalk.red(`${result.findings.length} finding(s) detected`)}\n`);
    const sorted = result.findings.slice().sort((a, b) => b.riskScore - a.riskScore);
    for (const finding of sorted) {
      console.log(formatStaticFinding(finding));
      console.log(divider);
    }
  }

  console.log(chalk.bold('\nSummary'));
  console.log(`  Findings:  ${result.totalFindings}`);
  console.log(
    `  ${chalk.red.bold('Critical:')} ${result.criticalCount}` +
    `  ${chalk.yellow.bold('High:')} ${result.highCount}` +
    `  ${chalk.cyan.bold('Medium:')} ${result.mediumCount}` +
    `  ${chalk.white.bold('Low:')} ${result.lowCount}`
  );

  if (result.warnings.length > 0) {
    console.log(chalk.bold('\nWarnings'));
    for (const w of result.warnings) {
      const prefix = w.serverName ? `[${w.serverName}] ` : '';
      const suffix = w.path ? ` (${w.path})` : '';
      console.log(`  ⚠ ${prefix}${w.message}${suffix}`);
    }
  }

  console.log('');
}

function printAttackReport(result: ScanResult): void {
  const divider = chalk.dim('─'.repeat(60));

  console.log(chalk.bold('\n MCP Security Sentinel — Scan Report'));
  console.log(chalk.dim('═'.repeat(60)));
  console.log(`Target:      ${result.targetServer}`);
  console.log(`Timestamp:   ${result.scanTimestamp}`);
  console.log(`Agent Model: ${result.agentModel}`);
  console.log(`Judge Model: ${result.judgeModel}`);
  console.log(`Runs/Payload: ${result.runsPerPayload}`);

  if (!result.baselineEnabled) {
    console.log(chalk.yellow('⚠ Baseline disabled. Findings may include false positives from natural agent behavior.'));
  }

  console.log(divider);

  if (result.findings.length === 0) {
    console.log(chalk.green('\n✓ No manipulation detected across all payloads.\n'));
  } else {
    console.log(`\n${chalk.red(`${result.findings.length} finding(s) detected`)}\n`);
    for (const finding of result.findings.slice().sort((a, b) => b.riskScore - a.riskScore)) {
      console.log(formatFinding(finding));
      console.log(divider);
    }
  }

  // result.summary is omitted from terminal output — counts are printed individually above
  console.log(chalk.bold('\nSummary'));
  console.log(`  Payloads tested: ${result.totalPayloadsTested}`);
  console.log(`  Findings:        ${result.totalFindings}`);
  console.log(
    `  ${chalk.red.bold('Critical:')} ${result.criticalCount}` +
    `  ${chalk.yellow.bold('High:')} ${result.highCount}` +
    `  ${chalk.cyan.bold('Medium:')} ${result.mediumCount}` +
    `  ${chalk.white.bold('Low:')} ${result.lowCount}`
  );
  console.log('');
}

function attackResultToScanResult(result: AttackResult): ScanResult {
  return {
    targetServer: result.targetServer,
    scanTimestamp: result.scanTimestamp,
    agentModel: result.agentModel,
    judgeModel: result.judgeModel,
    baselineEnabled: result.baselineEnabled,
    runsPerPayload: result.runsPerPayload,
    totalPayloadsTested: result.totalPayloadsTested,
    totalFindings: result.totalFindings,
    criticalCount: result.criticalCount,
    highCount: result.highCount,
    mediumCount: result.mediumCount,
    lowCount: result.lowCount,
    findings: result.findings.map(f => ({
      payloadId: f.payloadId,
      payloadName: f.payloadName,
      category: f.category,
      severity: f.severity,
      owaspRefs: f.owaspRefs,
      slowmistRef: f.slowmistRef,
      toolName: f.toolName,
      testSurface: f.testSurface,
      injectedPayload: f.injectedPayload,
      agentResponse: f.agentResponse,
      toolCallsMade: f.toolCallsMade,
      manipulated: f.manipulated,
      detectionMethod: f.detectionMethod,
      confidence: f.confidence,
      evidence: f.evidence,
      riskScore: f.riskScore,
      runs: f.runs,
      successCount: f.successCount,
      remediation: f.remediation,
      reproductionCommand: f.reproductionCommand,
    })),
    summary: result.summary,
  };
}

export function printReport(result: SentinelResult | ScanResult): void {
  if ('mode' in result && result.mode === 'inspect') {
    printInspectReport(result as InspectResult);
  } else if ('mode' in result && result.mode === 'attack') {
    printAttackReport(attackResultToScanResult(result as AttackResult));
  } else {
    printAttackReport(result as ScanResult);
  }
}

export function writeJsonReport(result: SentinelResult | ScanResult, outputPath: string): void {
  let toWrite: unknown = result;
  if ('mode' in result) {
    toWrite = toRedactedJson(result as SentinelResult);
  }
  fs.writeFileSync(outputPath, JSON.stringify(toWrite, null, 2), 'utf-8');
}
