/**
 * Cloud provider testing policies, shown for acknowledgement before any cloud or network run.
 *
 * The summaries were checked on 2026-08-23. They are stored rather than fetched so a run cannot be
 * blocked by a provider's marketing site being down, and so the exact text the tester acknowledged
 * is recorded against the engagement.
 *
 * Re-check these at least annually; `checkedOn` is what the console shows when it prompts.
 */

export interface CloudTestingPolicy {
  provider: 'aws' | 'azure' | 'gcp';
  name: string;
  url: string;
  checkedOn: string;
  permitted: string[];
  prohibited: string[];
  formsRequired: string[];
}

export const CLOUD_TESTING_POLICIES: CloudTestingPolicy[] = [
  {
    provider: 'aws',
    name: 'AWS Customer Support Policy for Penetration Testing',
    url: 'https://aws.amazon.com/security/penetration-testing/',
    checkedOn: '2026-08-23',
    permitted: [
      'Security testing of your own resources on the permitted service list, without prior approval.',
      'Testing of applications you host on EC2, API Gateway, Lambda, Lightsail, Elastic Beanstalk and the other listed services.',
    ],
    prohibited: [
      'Denial of service, distributed denial of service, simulated DoS and simulated DDoS. Prohibited outright, with no exception process.',
      'Port flooding, protocol flooding and request flooding, including login request flooding.',
      'Testing of AWS-owned infrastructure or another customer\'s resources.',
    ],
    formsRequired: [
      'Simulated Events form, for covert red team exercises, command-and-control simulation and phishing simulation against your own users.',
    ],
  },
  {
    provider: 'azure',
    name: 'Microsoft Cloud Penetration Testing Rules of Engagement',
    url: 'https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement',
    checkedOn: '2026-08-23',
    permitted: [
      'Testing of your own resources and applications hosted in Azure, without prior notification.',
      'Fuzzing, port scanning and vulnerability scanning of your own endpoints.',
    ],
    prohibited: [
      'Denial-of-service testing of any kind, including load and stress testing that could degrade service.',
      'Testing of Microsoft-owned infrastructure or another tenant\'s resources.',
      'Moving beyond proof of concept into data exfiltration or persistence.',
    ],
    formsRequired: [
      'DDoS simulation is available only through the Azure DDoS simulation programme with approved partners. It is not part of an ordinary assessment.',
    ],
  },
  {
    provider: 'gcp',
    name: 'Google Cloud Platform — testing your own projects',
    url: 'https://support.google.com/cloud/answer/6262505',
    checkedOn: '2026-08-23',
    permitted: [
      'Testing your own projects and applications without notifying Google in advance.',
    ],
    prohibited: [
      'Anything that violates the Acceptable Use Policy.',
      'Testing that disrupts Google infrastructure or other tenants.',
      'Testing resources belonging to another customer.',
    ],
    formsRequired: [],
  },
];

export function cloudPolicyFor(provider: CloudTestingPolicy['provider']): CloudTestingPolicy {
  const found = CLOUD_TESTING_POLICIES.find((policy) => policy.provider === provider);
  if (!found) throw new Error(`no stored testing policy for provider "${provider}"`);
  return found;
}

/**
 * The platform contains no denial-of-service capability at all, so the prohibited class above is
 * unreachable rather than merely disallowed. This constant exists so the console can say so, and so
 * a reviewer looking for the DoS switch finds this comment instead of a flag.
 */
export const DENIAL_OF_SERVICE_CAPABILITY = false as const;
