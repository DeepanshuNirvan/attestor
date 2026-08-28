# Sales playbook

How to pitch this, what you are actually selling, what to say when someone pushes back, and the
three sentences you must never say no matter how much the deal is worth.

---

## 1. The positioning, in one paragraph

Most of the Indian market sells one of two things: a cheap automated scan with a PDF stapled to it,
or a large-firm engagement at a large-firm price. You are selling the middle — **a real
manually-verified assessment, at a published price, with a report a client's auditor accepts and
their engineers can actually act on**. The differentiators are all things a competitor could copy but
mostly does not: published prices, a public check catalogue, a real sample report, a coverage matrix
that admits what was not tested, and a client portal instead of an emailed PDF.

## 2. What you actually sell

| Package | INR | USD | For |
| --- | --- | --- | --- |
| External surface check | 12,000 | 600 | The first conversation. What an anonymous attacker sees |
| API assessment | 40,000 | 2,400 | REST or GraphQL, from an OpenAPI document or captured traffic |
| Cloud configuration review | 45,000 | 2,000 | Read-only role against AWS, Azure or GCP |
| Web application and API audit | 55,000 | 3,000 | The core product. Authenticated, grey box, per role |
| Mobile application assessment | 65,000 | 3,500 | Android and iOS, static and runtime, plus the API |
| Web application audit, complex | 95,000 | 5,500 | Multi-tenant, four or more roles, payment or approval flows |
| LLM and AI red teaming, add-on | 40,000 | 1,800 | Added to a web, API or mobile engagement |
| LLM and AI red teaming | 120,000 | 5,000 | Standalone, against a chatbot, RAG app or agent |
| Continuous testing retainer | 40,000/mo | 2,200/mo | Scheduled re-testing, surface monitoring, a quarterly review |
| Fractional security lead | 90,000/mo | 4,500/mo | For companies who need someone answering security questions |

Edit these in `apps/website/src/data/pricing.ts`. They are typed and tested; a half-edited price
fails the build rather than reaching the site.

**Every engagement includes**, and say all of it every time:

- Manual verification. A tool's opinion is a candidate, never a finding.
- Findings written in business terms as well as technical ones.
- A coverage matrix stating what was tested and what was not, with reasons.
- A prioritised remediation roadmap: 30, 60, 90 days, grouped by root cause rather than by severity.
- One retest within thirty days of the report, at no cost.
- A client portal, for as long as they want it.
- Questionnaire answers they can paste into their own customers' security reviews.
- A debrief call, offered to the engineers as well as the buyer.

## 3. Who buys, and what they are actually buying

| Buyer | What they say | What they mean | Lead with |
| --- | --- | --- | --- |
| Founder, 10–50 people | "An enterprise customer is asking for a pentest report" | I need this deal to close | Timeline and the sample report. They are buying a document that unblocks revenue |
| CTO, Series A/B | "We should probably get tested" | I know we have debt and I do not know how bad | The check catalogue and the coverage matrix. They are buying an honest map |
| Compliance lead | "We need this for ISO 27001 / SOC 2 / RBI" | An auditor gave me a list | Compliance mappings and the attestation letter. They are buying evidence |
| Head of engineering | "Our last report was useless" | The last vendor sent a scanner dump | Remediation specificity and the retest. They are buying fixes that land |
| AI product team | "We built a chatbot and nobody has attacked it" | We do not know what to even ask for | Success rates over attempts, and the teardown guarantee |

## 4. The first call

Twenty minutes. You are qualifying, not selling.

**Open:** "Tell me what prompted this — a customer asking, an auditor, or something you already
suspect?" The answer determines everything else.

**Then find out:**

1. What is the application, and who logs into it? *(Roles determine price more than page count.)*
2. Is there a staging environment that matches production?
3. Multi-tenant? Payment flows? Approval workflows?
4. Anything a test must never touch?
5. When do you need the report, and for whom?
6. Have you been tested before? May I see the report? *(Read it. Their disappointment with it is your brief.)*

**Close the call with a price.** Not a range and not "we'll get back to you". The prices are already
published on your own website — refusing to say one out loud is a strange thing for a firm that
publishes them.

## 5. The lines that work

**On published prices.** "Our prices are on the site. You already know what this costs before you
talk to us, and so does everyone else — which means we compete on the work rather than on who can
guess your budget."

**On the catalogue.** "Every check we run is listed publicly, mapped to WSTG and ASVS. Ask any other
firm for their list before you sign; most will not give it to you, and the reason is usually that it
is shorter than they would like."

**On the coverage matrix.** "Our report includes what we did **not** test and why. A report that
implies total coverage is lying, and the day something is found in an untested area, that lie is what
the conversation is about."

**On manual work.** "Anyone can run a scanner. What you cannot automate is one user reading another
user's order, a discount applied twice, an approval step skipped by going straight to step three.
Those are the findings you remember, and they are the reason a person does this."

**On the retest.** "One retest within thirty days is included. We want to write 'verified fixed' —
that is the sentence your auditor wants and the one that closes the loop."

**On the portal.** "Findings live in a portal, not a PDF in an inbox. You mark them fixed, we verify,
your auditor sees the trail, and nobody hunts through email for the latest version."

**On being small.** "There are two of us. That means the person who tests your application is the
person who writes your report and the person on your debrief call. It also means we book out — if the
date matters, take it now."

## 6. Objections

**"Why not the cheap ₹8,000 scan?"**
"That is a scan, and you should run one — you can run one yourself for free with the same tools. What
you are paying us for is the part a scanner cannot do: verifying every result, chaining them, and
testing the logic. Our reports name the tool that found each thing, so you can see exactly which
findings a scan would have given you and which it would not."

**"Big Four quoted us ₹8 lakh."**
"They will do good work, and a partner will present it. Ask two questions: who actually performs the
testing, and what happens after the report. Ours is the same person start to finish, with a retest
included and a portal that stays."

**"Are you CERT-In empanelled?"**
**Say this exactly:** "No, we are not empanelled." Then: "If your regulator specifically requires an
empanelled auditor, you need one, and I will point you at a firm that is. If what you need is a
credible security assessment your customers and auditors accept, that is what we do, and our sample
report will tell you in ten minutes whether it clears your bar."

Never soften this. Empanelment is checkable in thirty seconds, a false claim ends the firm in a small
market, and the build fails on any wording that implies it.

**"Can you guarantee we will be secure afterwards?"**
"No, and nobody can. What we guarantee is what we tested, how we tested it, and what we found — and
the report says all three, including what we did not cover."

**"Can you do it this week?"**
"Not properly. A week is what a scan takes. An engagement is five to ten working days, and rushing
it means the manual work is what gets cut, which is the part you are paying for."

**"Will it take our site down?"**
"Our tooling has no capacity to do load or stress testing — that is not a setting we turn off, it is
a thing our platform cannot express. We run inside a rate limit you agree, in a window you choose,
and there is a stop control we use first and diagnose second. If anything looks wrong, we stop and
call you the same day."

**"Send us the raw scanner output."**
"Happily, as an appendix. It will be less useful than you expect — that is the material we already
triaged for you, and about half of it is wrong."

**"Our developers say they already know the issues."**
"Then this is quick and cheap for you, and if they are right, the report says so, which is worth
something in itself. In my experience the access control and business-logic findings are the ones
nobody had on their list."

## 7. Proposal structure

One page, and only after the scoping call.

1. **What we understood** — their words, back to them. Wrong here means everything after it is wrong.
2. **Scope** — assets, roles, environments, explicit exclusions.
3. **Approach** — modules, the standards mapped, what is manual.
4. **Timeline** — start, testing window, draft report, debrief, retest window.
5. **What you receive** — report, coverage matrix, roadmap, portal, retest, attestation letter.
6. **Price** — the published price. If you discount, say why in writing, once.
7. **What we need from you** — asset list, signed authorisation, allowlisting, test accounts, contacts.
8. **What we will not do** — no DoS, no social engineering, no physical, no production data
   exfiltration. Putting it in the proposal is reassuring rather than limiting.

## 8. After the sale

Run `docs/CHECKLISTS.md` §1. It is not optional paperwork; it is the difference between a firm and a
person with scanners. In particular:

- Authorisation signed by someone with authority to sign it. **Nothing runs before this**, and the
  platform will not let you.
- Ownership confirmed in writing for every asset, including third-party hosting.
- Emergency contacts both ways, including out of hours.
- The never-touch list agreed in writing.
- Your egress IP given to them and allowlisted.
- A dry run before anything real. Read what it says it would do.

## 9. The three sentences you never say

1. **Never claim an empanelment or accreditation the firm does not hold** — not CERT-In, not CREST,
   not ISO certification of the firm itself, and no wording that lets a listener infer one. The build
   fails on it, and so should you.
2. **Anything promising an outcome** — a guarantee of safety, a percentage of certainty, a claim
   that they will be compliant with anything. No assessment can promise an outcome and no report can
   defend one. `pnpm check:claims` fails the build on the usual phrasings, which is a hint about how
   easily they slip out.
3. **"We found nothing"** — without immediately explaining what was tested and what was not. A clean
   result is a coverage statement, never a verdict.

## 10. Growing it

**The report is the marketing.** A client's auditor reads it, then that auditor's other clients ask
who wrote it. Optimise the report before optimising the funnel.

**Publish the sample.** A real report against Juice Shop, not a mock-up, is already on the site. It
does more selling than any brochure page.

**Write up the manual findings, anonymised.** The access-control and logic findings are what people
share, and they are the ones no scanner produces.

**Sell the retainer at the debrief**, not at the sale. They have just watched you find things; the
question "what happens when we ship next month?" answers itself.

**Track two numbers only**: how many findings were confirmed fixed at retest, and how many clients
renewed. Everything else is vanity, and the first one is the one that predicts the second.
