import { describe, it, expect } from 'vitest';
import { PAYLOADS } from '../src/payloads.js';

describe('PAYLOADS', () => {
  it('exports exactly 17 payloads', () => {
    expect(PAYLOADS).toHaveLength(17);
  });

  it('every payload has required fields', () => {
    for (const p of PAYLOADS) {
      expect(p.id, `${p.id ?? 'unknown'} missing id`).toBeTruthy();
      expect(p.name, `${p.id} missing name`).toBeTruthy();
      expect(p.category, `${p.id} missing category`).toBeTruthy();
      expect(p.severity, `${p.id} missing severity`).toMatch(/^(critical|high|medium|low)$/);
      expect(p.owaspRefs, `${p.id} missing owaspRefs`).toBeInstanceOf(Array);
      expect(p.owaspRefs.length, `${p.id} owaspRefs empty`).toBeGreaterThan(0);
      expect(p.description, `${p.id} missing description`).toBeTruthy();
      expect(p.priority, `${p.id} missing priority`).toBeTruthy();
      expect(p.slowmistRef, `${p.id} missing slowmistRef`).toBeTruthy();
      expect(p.testSurface, `${p.id} missing testSurface`).toBeTruthy();
      expect(p.payload, `${p.id} missing payload string`).toBeTruthy();
      expect(p.oracle, `${p.id} missing oracle`).toBeTruthy();
      expect(p.remediation, `${p.id} missing remediation`).toBeTruthy();
    }
  });

  it('every payload has at least one oracle check defined', () => {
    for (const p of PAYLOADS) {
      const oracle = p.oracle;
      const hasCheck =
        (oracle.successMarkers?.length ?? 0) > 0 ||
        (oracle.forbiddenToolCalls?.length ?? 0) > 0 ||
        (oracle.forbiddenArgumentPatterns?.length ?? 0) > 0 ||
        (oracle.forbiddenResponsePatterns?.length ?? 0) > 0;
      expect(hasCheck, `${p.id} oracle has no checks`).toBe(true);
    }
  });

  it('all payload IDs are unique', () => {
    const ids = PAYLOADS.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
