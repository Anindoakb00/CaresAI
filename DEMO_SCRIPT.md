# CareShield AI hackathon demo script

## Introduction

“CareShield AI is an intelligent patient privacy protection system. It helps a healthcare organization understand who is touching synthetic patient records, decide whether the action is permitted, detect unusual patterns, and stop a risky export before it leaves the application.”

## The privacy problem

Healthcare teams need fast access to records, but the same access paths can be abused or misconfigured. A useful privacy control needs more than a red dashboard: it needs server-side authorization, durable audit evidence, explainable risk, and an enforceable response.

## Architecture in one minute

“The browser is a React console. FastAPI owns authentication, patient policy, activity logging, the deterministic risk engine, the IsolationForest metadata detector, and the export gate. SQLite makes the demo self-contained; PostgreSQL is the shared deployment choice. Every scenario below calls a real backend endpoint.”

## Demonstration A — normal access

1. Sign in as `doctor@careshield.demo`.
2. Open Patient records and select an assigned synthetic record.
3. Explain: “The assignment check is performed by the backend, not just hidden in the UI.”
4. Switch to Demo center and run Normal authorized access.
5. Show the low score and the new activity event on the Overview page.

Expected message: allowed, low risk, persisted audit event.

## Demonstration B — suspicious mass access

1. Sign in as the security analyst.
2. Run Suspicious mass access.
3. Show the deterministic sequence, high volume, unrelated-record signal, and denied attempts.
4. Open Alert center and show the contributing signals and recommended response.
5. Acknowledge the alert with a note, then resolve it.
6. Open Risk analytics and separate the rules result from the ML anomaly signal.

Say: “The model is not accusing anyone. It prioritizes unusual metadata patterns for human review.”

## Demonstration C — unauthorized export

1. Run Unauthorized data export.
2. Show “Blocked by backend,” critical severity, and `no payload` behavior in the execution feedback.
3. Open Activity monitor and show the denied export event.
4. Open Alert center and show the critical alert.

Say: “This is an application-level simulated USB destination. A web app cannot detect physical USB or stop operating-system file transfers. Real endpoint protection would require device policy or OS/security-agent integration.”

## The role of AI

The baseline IsolationForest is trained on reproducible synthetic metadata with normal and suspicious examples. It uses volume, frequency, denied attempts, department mismatch, timing, bulk-operation, and export indicators. Model evaluation metrics are displayed with the synthetic-data limitation. Authorization remains a separate deterministic policy decision.

## Privacy protections

Synthetic-only records, masked directory identifiers, minimized security events, role and patient assignment checks, safe export serialization, no external AI provider, and no secrets in ordinary response payloads are all demonstrated in the application.

## IBM deployment story

“The app is intentionally portable: Python and TypeScript services, a database boundary, health checks, and container files. For IBM Z or LinuxONE we would verify the target Linux distribution, s390x support for every base image and native dependency, registry access, TLS termination, secrets management, persistent database storage, and rollback before claiming a deployment. No IBM credentials or connectivity are assumed here.”

## Limitations and future work

Versioned migrations, distributed rate limiting, managed PostgreSQL, endpoint/device controls, richer model evaluation, production observability, and an independently verified s390x build would be next steps.

