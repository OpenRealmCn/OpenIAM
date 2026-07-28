# ADR 0001: Start as a Modular Monolith

## Status

Accepted

## Decision

OpenIAM will begin as one Go deployment containing independently wired identity, RBAC, session, OAuth, and audit modules.

## Rationale

Identity operations require transactional consistency and share strict security infrastructure. A modular monolith reduces operational failure modes while retaining explicit boundaries that can later become services when scaling evidence justifies it.
