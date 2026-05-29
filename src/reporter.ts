import chalk, { type ChalkInstance } from 'chalk';
import fs from 'fs';
import type { ScanResult, ScanFinding, Severity } from './types.js';

const SEVERITY_COLOR: Record<Severity, ChalkInstance> = {
  critical: chalk.red.bold,
  high: chalk.yellow.bold,
  medium: chalk.cyan.bold,
  low: chalk.white.bold,
};

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

export function printReport(result: ScanResult): void {
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

export function writeJsonReport(result: ScanResult, outputPath: string): void {
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
}
