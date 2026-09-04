# Session checkpoint

**Purpose.** Pick up mid-stream without being told the story again. Read this after
`docs/PRODUCT-CONTEXT.md` (the stable picture) and `docs/BUILD-STATUS.md` (the live state).
This file is only ever about the work in flight; anything finished graduates into `BUILD-STATUS.md`
and is deleted from here.

**Last updated:** 2026-08-29, after the WSTG footprint was closed and the risk calculator built.

---

## What we are doing and why

The user supplied `OWASP_WSTG_Checklist.xlsx` (16 sheets) and asked a blunt question: is the product
actually covering these points, or is it a gimmick? The answer at the time was no on two counts, and
both are now closed:

1. **44 of 210 catalogue checks claimed a machine did the work while naming tools that do not
   exist.** Fixed by reclassification; the catalogue-integrity test fails the build on a recurrence.
2. **WSTG coverage was 73 of 109.** It is now **106 covered, 3 explained decisions, no unexplained
   gap**, and the gap is held at zero by a snapshot ratchet.

The user's standing instructions, which shape every decision here:

- **No gimmicks.** A check must not claim a machine does work no machine does. Verify a tool really
  covers something before claiming it. Four claims have turned out false so far: katana's
  `-known-files`, nuclei's `info` templates, schemathesis's whole existence, and six WSTG mappings
  that named the wrong test.
- **No redundancy.** Where a capability already exists, map it rather than adding a second check
  under a new name. Sixteen of the thirty-one gaps closed that way, with no new code at all.
- **Every client differs.** Nothing may error or invent a finding because a feature is absent.
- **Automate what can honestly be automated, and leave the rest manual.** Do not force either way.
- **Do not rebuild what exists, do not break what works.**
- Real end-to-end runs, not code review. See the `attestor-testing-preferences` memory.

---

## Where this stream stands

Everything previously listed as next is done. Defects found doing it are 51 to 67 in
`BUILD-STATUS.md`.

- **The WSTG footprint is closed.** 106 covered, 3 decisions, 0 gaps. Closed in three ways, in this
  order of preference: by correcting a mapping to a capability that already existed (16 tests), by
  naming the ZAP release rule that performs the test (9), and by holding the test as manual work a
  person does and the coverage matrix records (12 new checks).
- **A third probe.** `requestManipulationProbe` covers HTTP method handling and verb tampering
  (`CONF-06`, `INPV-03`), parameter pollution (`INPV-04`) and host header injection (`INPV-17`).
  Only GET, HEAD and OPTIONS, so it runs unchanged in read-only mode. Verified through the product:
  16 requests, four findings, and no host-header reflection on a target that has none.
- **ZAP's active scan runs, for the first time.** Defect 67: the denial-of-service exclusion was
  wrong in three independent ways and made every active scan exit non-zero, which the worker read as
  a failed run. Verified against the pinned image, exit zero with the rule genuinely off.
- **schemathesis runs, for the first time.** Three separate faults; see defect 59. Verified against
  a live VAmPI through the product: 19 raw findings, 18 in the database.
- **The OWASP Risk Rating calculator** is built beside CVSS, reproduces the worked example in the
  client's own workbook to the second decimal, is stored as the sixteen raw answers, renders in the
  report with the factors that produced it, and has a console form on a new per-finding page.
- **The catalogue is 235 checks: 91 automated, 75 assisted, 69 manual.** It was 212 (85/69/58). The
  manual count rose because twelve WSTG tests that were absent from the catalogue entirely are now
  held as work a person does — they were never automated and are not now reclassified.

---

## Next, in order

1. **A token is stored but never presented**, and **nothing verifies a credential before a run**.
   Both are in the `Not done` list and both matter before a real API engagement.
2. The eleven tool images that cannot be pulled. Each needs a working reference or removal from the
   catalogue; leaving them listed overstates what the platform does.
3. Mobile, cloud, code and LLM modules have never been driven end to end against a live target.

---

## Environment notes for this verification

Machine-level quirks are in the `attestor-dev-environment` memory. Specific to this stream:

- The stack runs under `infra/docker-compose.yml`. Rebuild after a source change:
  `docker compose build worker api console && docker compose up -d worker api console`. The
  `migrate` service builds from the same image and needs rebuilding before a new migration applies.
- **Two data packs are provisioned by init services** and mounted read-only into tool containers:
  the nuclei template pack and the httpx classification model. Neither is fetched during a run.
- The targets used here: a published Juice Shop on `:3012` and a VAmPI on `:3013`, both reached at
  the Docker Desktop gateway `192.168.65.254`, which is scoped with a `cidr` item.
- **Juice Shop falls over under a full nuclei or ZAP run** (exit 139). When a later tool reports
  connection refused, check the target is still up before believing the finding.
- The queue is serial and nuclei and ZAP are slow, so a probe can sit `queued` for twenty minutes
  behind them. That is not a hang.
- Scratch harnesses are `apps/api/tmp-verify.mjs` and `tmp-verify2.mjs`; both are gitignored because
  `tmp-e2e-state.json` beside them holds a real password and TOTP secret for the local stack.
