# How a test runs, in plain words

A client says "please test our app". This page is what happens next, with no jargon.

It is deliberately short. `docs/ENGAGEMENT-WALKTHROUGH.md` is the same journey worked through
against one application with every command and button; `docs/OPERATOR-HANDBOOK.md` §6 is the
same sequence with every detail; `docs/COMMANDS.md` §8 is the same sequence as `curl`. Read
this one first.

---

## The one-line version

**You write down what you are allowed to touch. The platform refuses to touch anything else. Tools
run in locked-down containers and produce suggestions. You decide which suggestions are real. The
report is built from what actually ran.**

Everything below is that sentence with the steps filled in.

---

## Part 1 — Before anything runs

Nothing technical happens here, and nothing can run until it is done.

| Step | What you do | Why it exists |
| --- | --- | --- |
| 1 | Scoping call, then send your notes back for the client to correct | Their reply is your evidence of what was agreed |
| 2 | Check the client actually owns the domain | Handbook §7. This is the step that keeps you out of court |
| 3 | Create the client and the engagement in the console | Generates the reference the client will quote for years |
| 4 | Type the scope: domains, IPs, URLs, and anything excluded | This becomes the list the platform enforces |
| 5 | Upload the signed authorisation | **Nothing runs until this exists. No one can override it** |
| 6 | Take credentials through the one-time vault link | Never email or chat |
| 7 | Pick a policy profile | Decides which checks run and how fast |

At step 5 the platform shows you a **diff** between the asset list written in the signed document and
the scope you typed. Read it. It is the cheapest protection you have against testing something
nobody signed for.

---

## Part 2 — What happens when you press run

You choose modules (recon, web, api, cloud, mobile, llm, code, network) and press run. Then:

**1. The scope guard checks every target.** It resolves each hostname to an IP address and checks
*that* against the scope, not just the name you typed. A domain the client owns can point at shared
hosting somebody else owns. If anything does not match, the run stops and asks you.

**2. Jobs go on a queue.** One job per tool per target. The rows exist before anything starts, so a
crash leaves a visible queued row rather than a silent gap.

**3. The worker starts each tool in its own container.** Each one runs as a non-root user, with a
read-only filesystem, no Linux capabilities, its own network, memory and CPU limits, and a hard time
limit. Tool versions are pinned to an exact digest, so the version named in your report is the
version that ran.

**4. Tools write output. The platform reads it.** Each tool has an adapter whose job is to turn that
output into candidate findings. The adapter never sees a password: secrets reach a tool through the
container's environment only, and never on the command line, because the audit log records every
command.

**5. Discovery feeds the next tools.** The crawler records the endpoints it finds. Later tools and
the built-in probes read that list, narrowed to the hosts this run is allowed to touch.

**6. If the target starts struggling, the run backs off.** Latency and error rates are watched
throughout. Degradation slows the testing down; more degradation aborts the run and tells you.

Nothing in this phase produces a finding a client will see. It produces a **queue of candidates**.

---

## Part 3 — What you do afterwards

**Triage.** Open the review queue. Every candidate is confirmed by reproducing it, or discarded. A
discarded one records why, and the same wrong result from the same tool is remembered so it does not
cost you the same minute next time.

**Manual testing.** The part no tool does: access control between every pair of roles, business
logic, multi-step flows, and working out what several small findings add up to.

**The report.** Press *Draft every section* in the report workbench. It writes the prose sections
from the findings you confirmed. Every section arrives as a **draft**: you read each one against the
evidence and approve it. Release stays blocked until you do.

**Release.** The server re-runs the whole release checklist. If it refuses, the response lists
exactly what is blocking. Nothing is emailed. The client reads it in the portal.

---

## What is automated and what is not

| Automated | Yours |
| --- | --- |
| Finding subdomains, ports, endpoints | Deciding whether a finding is real |
| Running the tools and capturing evidence | Access control and business logic testing |
| Masking secrets and personal data in evidence | Working out what small findings chain into |
| Turning tool output into candidate findings | Approving every word of the report |
| Spotting readable personal data in URLs | Judging whether a concurrent session is a problem |
| Writing the first draft of every prose section | Pressing release |
| Building the coverage matrix from what ran | |

The split is deliberate. A tool can tell you a header is missing. It cannot tell you that your
support role can read an enterprise customer's invoices.

---

## Two things people expect that work differently

**"If I give it a URL, does it test every endpoint?"** Yes for discovery and scanning. The crawler
finds the endpoints and the scanning tools and probes work through them, narrowed to the hosts this
run is allowed to touch.

**"Is the personal data in our requests encrypted?"** On an HTTPS site the request body
already is, by TLS, and we do not report a finding for the absence of a second layer of
encryption on top of it. What TLS does not cover is the URL, which is copied into the access
log, every proxy in between, browser history and the `Referer` header. So the personal-data
probe reads the endpoints the crawl found and reports readable personal data in a URL. It
sends no requests, and it reports the masked URL rather than the value.

**"Does it test rate limiting on all of them?"** No, and on purpose. Repeating a request thirty times
against a one-time-code endpoint costs the client money per message, and against a password reset it
emails a real person. So the endpoints to measure throttling on are named in the policy
(`checks.rateLimitEndpoints`), and the sign-in endpoint from the auth profile is included
automatically and probed with an address that cannot exist. If you configure none, the probe measures
nothing and says so in the report rather than implying throttling was tested.

---

## Where the AI fits

`AI_API_KEY` is only for **drafting report prose**. It is never used to test anything, and it is off
by default (`AI_ENABLED=false`).

LLM red teaming is a different thing entirely and needs no key of yours. garak and promptfoo run in
containers against **the client's** model endpoint, exactly like every other tool.
