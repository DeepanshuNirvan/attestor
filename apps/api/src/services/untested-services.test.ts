import { describe, expect, it } from 'vitest';
import { untestedWebServices } from './report-service.ts';

/**
 * Web runs test the URLs in scope and nothing else. A front end on :5174 whose API is on :8080 had
 * its front end tested and its API not at all, and the report did not say so.
 */

const ports = [
  { host: '192.168.29.249', port: 5174, metadata: { service: 'http' } },
  { host: '192.168.29.249', port: 8080, metadata: { service: 'http', product: 'Golang net/http server' } },
  { host: '192.168.29.249', port: 445, metadata: { service: 'microsoft-ds' } },
  { host: '192.168.29.249', port: 8081, metadata: {} },
];

describe('untestedWebServices', () => {
  it('names an HTTP service on an in-scope host that no URL in scope points at', () => {
    expect(untestedWebServices(ports, ['http://192.168.29.249:5174'])).toEqual([
      'http://192.168.29.249:8080 (Golang net/http server)',
    ]);
  });

  it('says nothing once the service is in scope', () => {
    expect(
      untestedWebServices(ports, ['http://192.168.29.249:5174', 'http://192.168.29.249:8080/api']),
    ).toEqual([]);
  });

  it('matches the default port of a URL with none written', () => {
    const web = [{ host: 'app.example.com', port: 443, metadata: { service: 'https' } }];
    expect(untestedWebServices(web, ['https://app.example.com/login'])).toEqual([]);
  });
});
