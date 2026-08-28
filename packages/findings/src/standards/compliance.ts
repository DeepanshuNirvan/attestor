/**
 * Compliance mapping. This exists so a client can hand the report to an auditor and have the
 * evidence land against the right control. It is a convenience mapping and the report says so in
 * the disclaimer: it is not a compliance opinion and Attestor does not certify anything.
 */

export type ComplianceFramework = 'iso27001' | 'soc2' | 'pciDss' | 'dpdp' | 'asvs';

export interface ComplianceControl {
  framework: ComplianceFramework;
  id: string;
  title: string;
  /** What an auditor is looking for when they ask for this control's evidence. */
  evidenceExpectation: string;
}

export const COMPLIANCE_CONTROLS: ComplianceControl[] = [
  {
    framework: 'iso27001',
    id: 'A.8.8',
    title: 'Management of technical vulnerabilities',
    evidenceExpectation:
      'Evidence that technical vulnerabilities are identified, evaluated and remediated, with dates.',
  },
  {
    framework: 'iso27001',
    id: 'A.8.9',
    title: 'Configuration management',
    evidenceExpectation: 'Evidence that secure configuration baselines are defined and verified.',
  },
  {
    framework: 'iso27001',
    id: 'A.8.25',
    title: 'Secure development lifecycle',
    evidenceExpectation: 'Evidence that security is verified before a release reaches production.',
  },
  {
    framework: 'iso27001',
    id: 'A.8.26',
    title: 'Application security requirements',
    evidenceExpectation:
      'Evidence that application security requirements were defined and tested against.',
  },
  {
    framework: 'iso27001',
    id: 'A.8.28',
    title: 'Secure coding',
    evidenceExpectation: 'Evidence of secure coding verification, including static analysis output.',
  },
  {
    framework: 'iso27001',
    id: 'A.8.29',
    title: 'Security testing in development and acceptance',
    evidenceExpectation: 'An independent test report covering the release under review.',
  },
  {
    framework: 'iso27001',
    id: 'A.5.7',
    title: 'Threat intelligence',
    evidenceExpectation: 'Evidence that known exploited vulnerabilities are tracked and acted upon.',
  },
  {
    framework: 'soc2',
    id: 'CC4.1',
    title: 'Monitoring of controls',
    evidenceExpectation: 'Evidence of periodic evaluation of the effectiveness of controls.',
  },
  {
    framework: 'soc2',
    id: 'CC6.1',
    title: 'Logical access security',
    evidenceExpectation:
      'Evidence that logical access controls restrict access to authorised users only.',
  },
  {
    framework: 'soc2',
    id: 'CC6.6',
    title: 'Boundary protection',
    evidenceExpectation: 'Evidence that external threats to the system boundary are controlled.',
  },
  {
    framework: 'soc2',
    id: 'CC6.8',
    title: 'Unauthorised software prevention',
    evidenceExpectation: 'Evidence that unauthorised or malicious software is prevented.',
  },
  {
    framework: 'soc2',
    id: 'CC7.1',
    title: 'Vulnerability detection and monitoring',
    evidenceExpectation:
      'Evidence of vulnerability identification, including independent penetration testing.',
  },
  {
    framework: 'soc2',
    id: 'CC7.2',
    title: 'Security event monitoring',
    evidenceExpectation: 'Evidence that anomalies are detected and analysed.',
  },
  {
    framework: 'soc2',
    id: 'CC8.1',
    title: 'Change management',
    evidenceExpectation: 'Evidence that changes are tested and authorised before deployment.',
  },
  {
    framework: 'pciDss',
    id: '6.2',
    title: 'Bespoke and custom software developed securely',
    evidenceExpectation: 'Evidence that custom software is reviewed for vulnerabilities.',
  },
  {
    framework: 'pciDss',
    id: '6.4.1',
    title: 'Public-facing web application protection',
    evidenceExpectation:
      'Evidence of an annual review of public-facing web applications by a specialised party.',
  },
  {
    framework: 'pciDss',
    id: '11.3.1',
    title: 'Internal vulnerability scans',
    evidenceExpectation: 'Quarterly internal scan reports with remediation and rescans.',
  },
  {
    framework: 'pciDss',
    id: '11.4.2',
    title: 'Internal penetration testing',
    evidenceExpectation: 'An annual internal penetration test performed by a qualified party.',
  },
  {
    framework: 'pciDss',
    id: '11.4.3',
    title: 'External penetration testing',
    evidenceExpectation:
      'An annual external penetration test and after any significant infrastructure change.',
  },
  {
    framework: 'pciDss',
    id: '11.4.4',
    title: 'Correction of exploitable vulnerabilities',
    evidenceExpectation: 'Evidence that findings were corrected and testing repeated to verify.',
  },
  {
    framework: 'dpdp',
    id: 's8(5)',
    title: 'Reasonable security safeguards',
    evidenceExpectation:
      'Evidence that the data fiduciary takes reasonable security safeguards to prevent a personal data breach.',
  },
  {
    framework: 'dpdp',
    id: 's8(4)',
    title: 'Processor obligations under contract',
    evidenceExpectation:
      'A data processing agreement and evidence that processors are held to equivalent safeguards.',
  },
  {
    framework: 'dpdp',
    id: 's8(7)',
    title: 'Erasure on withdrawal or purpose completion',
    evidenceExpectation:
      'Evidence that personal data is erased when the purpose is served, including by processors.',
  },
  {
    framework: 'dpdp',
    id: 's8(6)',
    title: 'Breach intimation',
    evidenceExpectation:
      'Evidence of a process to intimate the Board and affected data principals of a breach.',
  },
];

export function controlsFor(framework: ComplianceFramework): ComplianceControl[] {
  return COMPLIANCE_CONTROLS.filter((control) => control.framework === framework);
}

export const FRAMEWORK_LABELS: Record<ComplianceFramework, string> = {
  iso27001: 'ISO/IEC 27001:2022',
  soc2: 'SOC 2 Trust Services Criteria',
  pciDss: 'PCI DSS 4.0',
  dpdp: 'Digital Personal Data Protection Act, 2023',
  asvs: 'OWASP ASVS 5.0',
};
