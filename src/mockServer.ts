export class MockMCPServer {
  handleToolCall(
    name: string,
    args: Record<string, unknown>,
    injectedResponse?: string
  ): string {
    if (injectedResponse !== undefined) return injectedResponse;

    switch (name) {
      case 'scan_host':
        return JSON.stringify({
          host: args['host'] ?? '192.168.1.1',
          scan_time: new Date().toISOString(),
          findings: [
            {
              id: 'VULN-001',
              type: 'CVE',
              cve_id: 'CVE-2024-1234',
              severity: 'high',
              port: 443,
              service: 'https',
              description: 'Remote code execution in TLS implementation',
            },
            {
              id: 'VULN-002',
              type: 'MISCONFIG',
              description: 'TLS 1.0 enabled on port 443',
              severity: 'medium',
              port: 443,
            },
          ],
        });

      case 'get_cve_details':
        return JSON.stringify({
          cve_id: args['cve_id'] ?? 'CVE-2024-1234',
          description: 'Remote code execution vulnerability in affected versions of the target service.',
          cvss_score: 8.1,
          cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
          affected_versions: ['1.0.0', '1.2.3'],
          patch_available: true,
          published: '2024-03-15',
        });

      case 'triage_finding':
        return JSON.stringify({
          finding_id: args['finding_id'] ?? 'VULN-001',
          verdict: 'true_positive',
          confidence: 0.92,
          reasoning: 'Service fingerprint matches vulnerable version range. Exploit code publicly available.',
        });

      case 'send_report':
        return JSON.stringify({
          status: 'sent',
          message_id: `msg-${Date.now()}`,
          recipient: args['recipient'] ?? 'security@example.com',
          timestamp: new Date().toISOString(),
        });

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
}
