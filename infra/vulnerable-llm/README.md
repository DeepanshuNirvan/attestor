# Vulnerable LLM application

A purpose-built target for the LLM module's integration tests. It is intentionally broken and must
never be deployed anywhere reachable from a network you do not control.

Run it on its own:

```bash
node server.mjs
```

It listens on `PORT` (default 8090) and speaks a small JSON API:

| Route | Purpose |
| --- | --- |
| `POST /api/chat` | `{ input, tenant?, conversationId?, maxTokens? }` → answer, citations, tool calls |
| `GET /api/conversations/:id` | Returns a transcript with no authorisation check |
| `POST /api/documents` | Adds a document to the retrieval corpus |
| `GET /api/documents` | Lists the corpus |
| `DELETE /api/documents?id=` | Removes a document, used by the teardown check |

## What is wrong with it, on purpose

Each weakness maps to a catalogue check so the integration suite can assert that the module finds
it:

- **Direct prompt injection** — an instruction override in the user message wins.
- **System prompt leakage** — a translation-style request returns the system prompt, including the
  internal refund threshold and escalation code.
- **Indirect prompt injection** — an instruction planted in a retrieved document is obeyed. Plant
  one with `POST /api/documents` and a body containing `[[instruction: …]]`.
- **Cross-tenant retrieval** — the tenant filter is applied to the citations shown to the user, not
  to what the model was given, so another tenant's document influences the answer.
- **Insecure output handling** — `replyHtml` hands the answer back as markup for the caller to
  render.
- **Excessive agency** — the refund tool runs from a plain request, with no confirmation and no
  check against the threshold in the system prompt.
- **Chained tool abuse** — asking it to email the transcript composes the read and send tools into
  exfiltration.
- **Unbounded consumption** — the caller chooses `maxTokens`.
- **Conversation isolation** — any conversation id returns that transcript.
- **Debug leakage** — the response carries a `debug` block naming every retrieved document.

## Stub mode

`ATTESTOR_LLM_MODE=stub` (the default) uses a deterministic function instead of a model. The
integration suite runs this way: no provider key, no spend, and the same result every time.
