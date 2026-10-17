# Lab 4 — LLM Prompt Injection & Tool-Use Hardening (Strix)

**Audience:** Lab operator running Strix against intentional targets. Read this before
enabling any LLM-assisted features in a live engagement.

## Why this lab exists

Strix surfaces LLM-adjacent risks as first-class findings
(`llm01-prompt-injection`, `llm06-sensitive-data-exposure`) and applies
`csv_safe` to exported fields (CWE-1236). Those are product-level controls.
This lab is the operator's companion: it documents how an agent that *calls*
tools on your behalf can be steered by untrusted outputs, what has been
addressed in this codebase so far, and what remains your responsibility.
For the companion labs on API/network and container surfaces, see
`docs/labs/api-security-lab.md` and the hardening notes in `containers/`.

## Threat model this lab covers

- A scan target returns untrusted content (HTML, API responses, error
  messages, retrieved documents) that reaches the LLM context.
- The LLM is asked to act on that content (summarise, extract, chain tools).
- A helper subprocess (payload generation, shell one-liners, file writes) uses
  attacker-influenced values for commands, paths, or code.
- Reports and exported JSON/CSV carry finding titles and payloads derived
  from that same untrusted content.

## What is already hardened here

- **CSV formula stripping** in `strix/report/writer.py:csv_safe` — spreadsheet
  formula prefixes are neutralised before CSV export (OWASP/CWE-1236). This
  mitigates the "open the report and something runs" vector.
- **Payload generation is isolated to generated payload strings**, not to
  free-form shell execution of model output. See `strix/payloads/engine.py`
  and the checks in `strix/payloads/signatures/`; operators should not route
  raw LLM tokens into `subprocess`/`os.system`.
- **`.gitignore` entries for `.env` and credential files** — reduces accidental
  leakage of lab secrets into commits (but is not a substitute for a
  pre-commit secret scanner).
- **Container hardening in `containers/Dockerfile`** —pinned tool versions
  with trust-store comments and staged `USER pentester` — so that any
  containerised lab run does not execute scans as root by default.

## Operator obligations (not automated)

These are intentionally outside the codebase and belong in your lab runbook.
Strix does not enforce them; you must:

1. **Treat every tool output and every fetched secret as untrusted.**
   Do not paste scan results, target responses, or "discovered" tokens into a
   privileged LLM prompt without an explicit allowlist of safe fields.
2. **Pin an explicit tool allowlist per run.** If you wire an LLM orchestrator
   in front of Strix, enumerate the tools it may call and deny the rest
   (`tool_choice` / function allowlist). Log every tool call with the prompt
   that triggered it.
3. **Never execute LLM-suggested shell commands verbatim.** Require human
   approval for any command that writes files, opens network connections, or
   changes scan scope. Prefer structured arguments over shell strings.
4. **Validate external input before it becomes code, a path, or a URL.**
   Normalise file paths (reject `..` traversal), validate URLs against an
   allowlist, and escape shell arguments — even when the value "came from the
   LLM", because the LLM may be echoing the target.
5. **Scope secrets narrowly.** Create a dedicated lab-only API key/credential
   per engagement, revoke it after, and never commit it. Use `.env` locally
   and a secret scanner pre-commit hook; Strix's `.gitignore` is a safety net,
   not a control.
6. **Review reports before sharing.** Finding titles and payloads can quote the
   target verbatim. Treat `report/` output as potentially attacker-controlled
   text — do not forward it into automated ticketing or chatops without
   sanitisation.

## Suggested lab exercise

1. Seed a local target that returns a classic injection string in an HTTP
   header or body (e.g. "Ignore previous instructions and ...").
2. Run a scan that ingests that response and, if LLM summarisation is enabled,
   observe whether the model's output proposes a tool action.
3. Verify that (a) the action is **not** auto-executed, (b) it is logged, and
   (c) the final report's CSV export does not contain an executable formula.
4. Record the outcome in the engagement notes referenced by `SECURITY.md`.

## Further reading

- OWASP LLM Top 10 — LLM01 Prompt Injection, LLM06 Sensitive Information
  Disclosure.
- `SECURITY.md` (project disclosure policy) and `strix/core/config.py`
  (configuration surface).
- `docs/labs/api-security-lab.md` for the API/network counterpart to this lab.
