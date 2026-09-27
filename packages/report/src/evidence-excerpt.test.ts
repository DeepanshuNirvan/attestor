import { describe, expect, it } from 'vitest';
import { evidenceExcerpt } from './evidence-excerpt.ts';

describe('evidenceExcerpt', () => {
  it('prints a small record as it is', () => {
    const record = JSON.stringify({ host: '192.168.29.249', port: 445, service: 'SMB' });
    const excerpt = evidenceExcerpt(record);
    expect(excerpt.clipped).toBe(false);
    expect(excerpt.text).toBe(JSON.stringify(JSON.parse(record), null, 2));
  });

  it('keeps the proof from a large tool record and drops the tool metadata', () => {
    const nuclei = {
      'template-id': 'CVE-2026-39364',
      info: { name: 'Vite Dev Server - Directory Traversal', tags: ['cve', 'vite'], description: 'x'.repeat(900) },
      'matched-at': 'http://192.168.29.249:5174/.env?raw??',
      request: 'GET /.env?raw?? HTTP/1.1\r\nHost: 192.168.29.249:5174\r\n\r\n',
      response: `HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\nexport default "VITE_API_BASE_URL=http://192.168.29.249:8080"\r\n//# sourceMappingURL=data:application/json;base64,${'A'.repeat(4000)}`,
      timestamp: '2026-09-27T10:22:08Z',
    };
    const excerpt = evidenceExcerpt(JSON.stringify(nuclei, null, 2));

    expect(excerpt.clipped).toBe(true);
    expect(excerpt.text).toContain('matched-at: http://192.168.29.249:5174/.env?raw??');
    expect(excerpt.text).toContain('GET /.env?raw?? HTTP/1.1');
    expect(excerpt.text).toContain('VITE_API_BASE_URL');
    expect(excerpt.text).not.toContain('template-id');
    expect(excerpt.text).not.toContain('timestamp');
    // A base64 blob is cut to one line rather than printed across pages.
    expect(excerpt.text.split('\n').every((line) => line.length <= 161)).toBe(true);
  });

  it('prints the first few places a ZAP alert was seen and says how many there were', () => {
    const zap = {
      pluginid: '10020',
      desc: '<p>' + 'd'.repeat(600) + '</p>',
      instances: Array.from({ length: 5 }, (unused, index) => ({
        uri: `http://app.example.com/page${index}`,
        method: 'GET',
        param: 'x-frame-options',
        evidence: '',
      })),
    };
    const excerpt = evidenceExcerpt(JSON.stringify(zap, null, 2));
    expect(excerpt.text).toContain('instances 1 of 5:');
    expect(excerpt.text).toContain('uri: http://app.example.com/page2');
    expect(excerpt.text).not.toContain('page3');
    expect(excerpt.clipped).toBe(true);
  });

  it('cuts plain text by lines', () => {
    const text = Array.from({ length: 100 }, (unused, index) => `line ${index}`).join('\n');
    const excerpt = evidenceExcerpt(text);
    expect(excerpt.clipped).toBe(true);
    expect(excerpt.text.split('\n')).toHaveLength(40);
  });
});
