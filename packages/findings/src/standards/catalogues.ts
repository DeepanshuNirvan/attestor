/**
 * Standards catalogues, as data. Editions and identifiers were verified in August 2026; see
 * docs/RESEARCH-NOTES.md for sources and dates.
 *
 * These drive the report's coverage matrix and the mapping appendix. A finding that references an
 * identifier absent from these tables fails validation rather than printing a broken reference.
 */

export interface StandardEntry {
  id: string;
  title: string;
}

export const OWASP_TOP_10_2025: StandardEntry[] = [
  { id: 'A01:2025', title: 'Broken Access Control' },
  { id: 'A02:2025', title: 'Security Misconfiguration' },
  { id: 'A03:2025', title: 'Software Supply Chain Failures' },
  { id: 'A04:2025', title: 'Cryptographic Failures' },
  { id: 'A05:2025', title: 'Injection' },
  { id: 'A06:2025', title: 'Insecure Design' },
  { id: 'A07:2025', title: 'Authentication Failures' },
  { id: 'A08:2025', title: 'Software or Data Integrity Failures' },
  { id: 'A09:2025', title: 'Logging and Alerting Failures' },
  { id: 'A10:2025', title: 'Mishandling of Exceptional Conditions' },
];

/** Server-Side Request Forgery was folded into A01 in the 2025 edition. */
export const OWASP_TOP_10_EDITION = '2025';

export const OWASP_API_TOP_10_2023: StandardEntry[] = [
  { id: 'API1:2023', title: 'Broken Object Level Authorization' },
  { id: 'API2:2023', title: 'Broken Authentication' },
  { id: 'API3:2023', title: 'Broken Object Property Level Authorization' },
  { id: 'API4:2023', title: 'Unrestricted Resource Consumption' },
  { id: 'API5:2023', title: 'Broken Function Level Authorization' },
  { id: 'API6:2023', title: 'Unrestricted Access to Sensitive Business Flows' },
  { id: 'API7:2023', title: 'Server Side Request Forgery' },
  { id: 'API8:2023', title: 'Security Misconfiguration' },
  { id: 'API9:2023', title: 'Improper Inventory Management' },
  { id: 'API10:2023', title: 'Unsafe Consumption of APIs' },
];

export const OWASP_LLM_TOP_10_2025: StandardEntry[] = [
  { id: 'LLM01:2025', title: 'Prompt Injection' },
  { id: 'LLM02:2025', title: 'Sensitive Information Disclosure' },
  { id: 'LLM03:2025', title: 'Supply Chain' },
  { id: 'LLM04:2025', title: 'Data and Model Poisoning' },
  { id: 'LLM05:2025', title: 'Improper Output Handling' },
  { id: 'LLM06:2025', title: 'Excessive Agency' },
  { id: 'LLM07:2025', title: 'System Prompt Leakage' },
  { id: 'LLM08:2025', title: 'Vector and Embedding Weaknesses' },
  { id: 'LLM09:2025', title: 'Misinformation' },
  { id: 'LLM10:2025', title: 'Unbounded Consumption' },
];

export const MASVS_CONTROLS: StandardEntry[] = [
  { id: 'MASVS-STORAGE-1', title: 'The app securely stores sensitive data' },
  { id: 'MASVS-STORAGE-2', title: 'The app prevents leakage of sensitive data' },
  { id: 'MASVS-CRYPTO-1', title: 'The app employs current strong cryptography' },
  { id: 'MASVS-CRYPTO-2', title: 'The app performs key management according to best practice' },
  { id: 'MASVS-AUTH-1', title: 'The app uses secure authentication and authorisation protocols' },
  { id: 'MASVS-AUTH-2', title: 'The app performs local authentication securely' },
  { id: 'MASVS-AUTH-3', title: 'The app secures sensitive operations with additional authentication' },
  { id: 'MASVS-NETWORK-1', title: 'The app secures all network traffic' },
  { id: 'MASVS-NETWORK-2', title: 'The app performs identity pinning for remote endpoints' },
  { id: 'MASVS-PLATFORM-1', title: 'The app uses IPC mechanisms securely' },
  { id: 'MASVS-PLATFORM-2', title: 'The app uses WebViews securely' },
  { id: 'MASVS-PLATFORM-3', title: 'The app uses the user interface securely' },
  { id: 'MASVS-CODE-1', title: 'The app requires an up-to-date platform version' },
  { id: 'MASVS-CODE-2', title: 'The app has a mechanism for enforcing updates' },
  { id: 'MASVS-CODE-3', title: 'The app only uses software components without known vulnerabilities' },
  { id: 'MASVS-CODE-4', title: 'The app validates and sanitises all untrusted inputs' },
  { id: 'MASVS-RESILIENCE-1', title: 'The app validates the integrity of the platform' },
  { id: 'MASVS-RESILIENCE-2', title: 'The app implements anti-tampering mechanisms' },
  { id: 'MASVS-RESILIENCE-3', title: 'The app implements anti-static-analysis mechanisms' },
  { id: 'MASVS-RESILIENCE-4', title: 'The app implements anti-dynamic-analysis techniques' },
  { id: 'MASVS-PRIVACY-1', title: 'The app minimises access to sensitive data and resources' },
  { id: 'MASVS-PRIVACY-2', title: 'The app prevents identification of the user' },
  { id: 'MASVS-PRIVACY-3', title: 'The app is transparent about data collection and usage' },
  { id: 'MASVS-PRIVACY-4', title: 'The app offers user control over their data' },
];

export const MASVS_VERSION = '2.1.0';

/** ASVS 5.0.0 chapters. Individual requirements are referenced as `v5.0.0-<chapter>.<section>.<n>`. */
export const ASVS_CHAPTERS: StandardEntry[] = [
  { id: 'V1', title: 'Encoding and Sanitization' },
  { id: 'V2', title: 'Validation and Business Logic' },
  { id: 'V3', title: 'Web Frontend Security' },
  { id: 'V4', title: 'API and Web Service' },
  { id: 'V5', title: 'File Handling' },
  { id: 'V6', title: 'Authentication' },
  { id: 'V7', title: 'Session Management' },
  { id: 'V8', title: 'Authorization' },
  { id: 'V9', title: 'Self-contained Tokens' },
  { id: 'V10', title: 'OAuth and OIDC' },
  { id: 'V11', title: 'Cryptography' },
  { id: 'V12', title: 'Secure Communication' },
  { id: 'V13', title: 'Configuration' },
  { id: 'V14', title: 'Data Protection' },
  { id: 'V15', title: 'Secure Coding and Architecture' },
  { id: 'V16', title: 'Security Logging and Error Handling' },
  { id: 'V17', title: 'WebRTC' },
];

export const ASVS_VERSION = '5.0.0';

/** WSTG 4.2 categories. Test ids are `WSTG-<CAT>-<NN>`. */
export const WSTG_CATEGORIES: StandardEntry[] = [
  { id: 'INFO', title: 'Information Gathering' },
  { id: 'CONF', title: 'Configuration and Deployment Management Testing' },
  { id: 'IDNT', title: 'Identity Management Testing' },
  { id: 'ATHN', title: 'Authentication Testing' },
  { id: 'ATHZ', title: 'Authorization Testing' },
  { id: 'SESS', title: 'Session Management Testing' },
  { id: 'INPV', title: 'Input Validation Testing' },
  { id: 'ERRH', title: 'Error Handling' },
  { id: 'CRYP', title: 'Weak Cryptography' },
  { id: 'BUSL', title: 'Business Logic Testing' },
  { id: 'CLNT', title: 'Client-side Testing' },
  { id: 'APIT', title: 'API Testing' },
];

export const WSTG_VERSION = '4.2';

const WSTG_ID = /^WSTG-(INFO|CONF|IDNT|ATHN|ATHZ|SESS|INPV|ERRH|CRYP|BUSL|CLNT|APIT)-\d{2}$/;
const ASVS_ID = /^v5\.0\.0-\d{1,2}\.\d{1,2}\.\d{1,2}$/;

export function isWstgId(value: string): boolean {
  return WSTG_ID.test(value);
}

export function isAsvsRequirement(value: string): boolean {
  return ASVS_ID.test(value);
}

export function isOwaspTop10Category(value: string): boolean {
  return OWASP_TOP_10_2025.some((entry) => entry.id === value);
}

export function isApiTop10Category(value: string): boolean {
  return OWASP_API_TOP_10_2023.some((entry) => entry.id === value);
}

export function isLlmTop10Category(value: string): boolean {
  return OWASP_LLM_TOP_10_2025.some((entry) => entry.id === value);
}

export function isMasvsControl(value: string): boolean {
  return MASVS_CONTROLS.some((entry) => entry.id === value);
}

export function titleFor(catalogue: StandardEntry[], id: string): string | undefined {
  return catalogue.find((entry) => entry.id === id)?.title;
}
