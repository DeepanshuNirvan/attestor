import type { Check } from './types.ts';

export const mobileChecks: Check[] = [
  {
    id: 'mobile-binary-composition',
    title: 'Binary composition and third-party components',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Inventory the libraries, SDKs and native components inside the shipped binary and correlate versions against known vulnerabilities.',
    example:
      'An analytics SDK two years out of date with a published remote code execution issue.',
    automation: 'automated',
    tools: ['mobsf', 'apktool', 'jadx'],
    standards: { masvs: ['MASVS-CODE-3'], owaspTop10: ['A03:2025'], cwe: [1104, 1035] },
  },
  {
    id: 'mobile-hardcoded-secrets',
    title: 'Hardcoded secrets in the application package',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Search resources, strings, native libraries, assets and build configuration for API keys, tokens, certificates and endpoints that were never meant to ship.',
    example:
      'A cloud storage key in a strings resource, granting write access to the media bucket.',
    automation: 'automated',
    tools: ['mobsf', 'trufflehog', 'jadx'],
    standards: { masvs: ['MASVS-STORAGE-1'], owaspTop10: ['A02:2025'], cwe: [798, 312] },
  },
  {
    id: 'mobile-insecure-local-storage',
    title: 'Insecure local data storage',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Inspect preferences, databases, cache, keychain and keystore use, external storage and backup inclusion for sensitive data stored without protection.',
    example:
      'Session tokens written to shared preferences in plain text and included in device backups.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-STORAGE-1', 'MASVS-STORAGE-2'], owaspTop10: ['A04:2025'], cwe: [312, 922] },
  },
  {
    id: 'mobile-logging-leakage',
    title: 'Sensitive data in logs and crash reports',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check what the application writes to system logs, crash reporters and third-party analytics, including in error paths.',
    example:
      'The full authentication response, including the refresh token, written to the device log on failure.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-STORAGE-2', 'MASVS-PRIVACY-1'], owaspTop10: ['A09:2025'], cwe: [532] },
  },
  {
    id: 'mobile-transport-security',
    title: 'Transport security configuration',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check the network security configuration and transport security settings for cleartext permissions, user-added certificate trust and per-domain exceptions.',
    example:
      'A cleartext exception for a legacy subdomain that the application still calls on first launch.',
    automation: 'automated',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-NETWORK-1'], owaspTop10: ['A04:2025'], cwe: [319] },
  },
  {
    id: 'mobile-certificate-pinning',
    title: 'Certificate pinning presence and resilience',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Determine whether pinning is implemented, whether it covers all hosts, and how much effort a bypass takes on an instrumented device.',
    example:
      'Pinning present on the main API host but absent on the payment host, which is the one that matters.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-NETWORK-2'], owaspTop10: ['A04:2025'], cwe: [295] },
  },
  {
    id: 'mobile-exported-components',
    title: 'Exported components and IPC surface',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Review exported activities, services, receivers, content providers, deep links and URL schemes for functionality another application can reach.',
    example:
      'An exported activity that displays account details when started with a user identifier, callable by any installed app.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-PLATFORM-1'], owaspTop10: ['A01:2025'], cwe: [926, 927] },
  },
  {
    id: 'mobile-deep-link-handling',
    title: 'Deep link and universal link handling',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Test whether deep links can trigger authenticated actions, carry unvalidated parameters into a WebView, or be claimed by another application.',
    example:
      'A deep link that opens an arbitrary URL inside the authenticated WebView, with the session cookie attached.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-PLATFORM-1', 'MASVS-PLATFORM-2'], owaspTop10: ['A01:2025'], cwe: [939, 601] },
  },
  {
    id: 'mobile-webview-configuration',
    title: 'WebView configuration',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check JavaScript enablement, JavaScript-to-native bridges, file access, mixed content handling and whether untrusted content can be loaded.',
    example:
      'A JavaScript bridge exposing a method that reads local files, reachable from any page the WebView loads.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-PLATFORM-2'], owaspTop10: ['A05:2025'], cwe: [749, 79] },
  },
  {
    id: 'mobile-authentication-flows',
    title: 'Mobile authentication and session handling',
    category: 'authentication',
    modules: ['mobile'],
    description:
      'Test login, token storage, refresh, logout, session expiry and whether authentication state can be restored from local data alone.',
    example:
      'A session restored from a locally stored flag, so editing that value signs the user back in without a token.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-AUTH-1'], owaspTop10: ['A07:2025'], cwe: [287, 603] },
  },
  {
    id: 'mobile-local-authentication',
    title: 'Local authentication and biometric gating',
    category: 'authentication',
    modules: ['mobile'],
    description:
      'Check whether biometric or PIN gating is enforced by the operating system with a cryptographic result, or only by an application-level boolean that can be patched.',
    example:
      'A biometric prompt whose success callback sets a variable, bypassable by hooking one method.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-AUTH-2', 'MASVS-AUTH-3'], owaspTop10: ['A07:2025'], cwe: [287] },
  },
  {
    id: 'mobile-cryptography-use',
    title: 'Cryptographic implementation review',
    category: 'cryptography',
    modules: ['mobile'],
    description:
      'Review algorithms, modes, initialisation vectors, key derivation and where keys are stored, including whether hardware-backed storage is used when available.',
    example:
      'AES in ECB mode with a key derived from the device identifier, so identical data produces identical ciphertext.',
    automation: 'assisted',
    tools: ['mobsf', 'jadx'],
    standards: { masvs: ['MASVS-CRYPTO-1', 'MASVS-CRYPTO-2'], owaspTop10: ['A04:2025'], cwe: [327, 321] },
  },
  {
    id: 'mobile-runtime-instrumentation',
    title: 'Runtime behaviour under instrumentation',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Run the application on an instrumented device to observe network calls, inspect objects in memory, and confirm what the static analysis suggested.',
    example:
      'A card number held in memory long after the payment screen closes, recoverable from a heap dump.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-RESILIENCE-4'], owaspTop10: ['A04:2025'], cwe: [316] },
  },
  {
    id: 'mobile-tamper-detection',
    title: 'Tamper, root and emulator detection',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Assess whether integrity checks exist, what they do when they fail, and how much effort a bypass takes. Reported as a resilience observation, not as a vulnerability in itself.',
    example:
      'Root detection that logs and continues, which provides no protection but does provide a false sense of it.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-2'], cwe: [693] },
  },
  {
    id: 'mobile-screen-and-clipboard-leakage',
    title: 'Screenshot, clipboard and keyboard leakage',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check task-switcher screenshots of sensitive screens, clipboard use for sensitive values, and whether sensitive fields disable predictive keyboards and caching.',
    example:
      'The account balance screen captured into the task-switcher snapshot, visible to anyone who picks up the device.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-PLATFORM-3', 'MASVS-PRIVACY-1'], cwe: [200] },
  },
  {
    id: 'mobile-permission-review',
    title: 'Permission and capability review',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Review requested permissions and background capabilities against what the application actually needs, and identify permissions requested by third-party SDKs.',
    example:
      'Precise location requested by an advertising SDK in an application that has no location feature.',
    automation: 'automated',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-PRIVACY-1'], cwe: [250] },
  },
  {
    id: 'mobile-data-safety-consistency',
    title: 'Store data-safety declaration consistency',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Compare what the application and its SDKs actually collect and transmit against the data-safety declaration published on the store listing.',
    example:
      'A declaration stating no data is shared, while an SDK transmits the advertising identifier and coarse location on launch.',
    automation: 'assisted',
    tools: ['mobsf', 'mitmproxy'],
    standards: { masvs: ['MASVS-PRIVACY-3', 'MASVS-PRIVACY-4'], cwe: [359] },
  },
  {
    id: 'mobile-update-enforcement',
    title: 'Update enforcement and minimum platform version',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check whether the application can force an update when a security fix ships, and what the minimum supported platform version is.',
    example:
      'No forced-update mechanism, so a client-side fix reaches only the users who choose to update.',
    automation: 'assisted',
    tools: ['mobsf'],
    standards: { masvs: ['MASVS-CODE-1', 'MASVS-CODE-2'], owaspTop10: ['A08:2025'], cwe: [1104] },
  },
  {
    id: 'mobile-input-validation',
    title: 'Input handling from untrusted sources',
    category: 'inputValidation',
    modules: ['mobile'],
    description:
      'Test how the application handles untrusted input from intents, deep links, QR codes, push payloads, clipboard content and files.',
    example:
      'A QR scanner that passes the decoded value straight into a WebView load.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-CODE-4'], owaspTop10: ['A05:2025'], cwe: [20] },
  },
  {
    id: 'mobile-backend-traffic-analysis',
    title: 'Backend traffic capture and analysis',
    category: 'mobileSpecific',
    modules: ['mobile', 'api'],
    description:
      'Intercept the application\'s traffic and feed the captured endpoints into the API module, so the backend is tested rather than only the client.',
    example:
      'A mobile-only endpoint returning the full user record where the app displays only the name.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-NETWORK-1'], apiTop10: ['API3:2023'], cwe: [213] },
  },
  {
    id: 'mobile-push-notification-handling',
    title: 'Push notification content and handling',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Check whether notifications carry sensitive content to the lock screen and whether notification payloads are trusted as instructions by the application.',
    example:
      'A one-time code delivered in full to the lock screen, readable without unlocking the device.',
    automation: 'manual',
    tools: [],
    standards: { masvs: ['MASVS-PLATFORM-3', 'MASVS-PRIVACY-2'], cwe: [200] },
  },
  {
    id: 'mobile-obfuscation-assessment',
    title: 'Code protection assessment',
    category: 'mobileSpecific',
    modules: ['mobile'],
    description:
      'Assess how readable the decompiled application is and whether business logic that should be server-side is recoverable from the client.',
    example:
      'A pricing algorithm fully readable in the decompiled code, including the internal discount thresholds.',
    automation: 'manual',
    tools: ['jadx', 'apktool'],
    standards: { masvs: ['MASVS-RESILIENCE-3'], cwe: [656] },
  },
];
