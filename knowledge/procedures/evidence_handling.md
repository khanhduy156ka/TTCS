# SOC Evidence Handling Procedure

This document defines evidence-handling principles for the SOC Lab prototype.

## Facts and assumptions

Agent outputs should separate directly observed facts from interpretations and assumptions. Missing telemetry should be recorded as missing evidence rather than filled with invented details.

## Provenance

Retrieved knowledge should retain source, title, section, document version, and chunk identifier so an analyst can trace the guidance used by the system.

A retrieved document is guidance, not event evidence. Incident conclusions must remain grounded in the actual telemetry for the case.

## Conflicting information

When telemetry sources conflict, the system should expose the contradiction instead of silently selecting the more convenient interpretation.

Structured event fields and directly observed endpoint evidence should be preferred over unsupported natural-language assumptions.

## Decision support

Knowledge retrieval should assist analyst reasoning by supplying relevant procedures and investigation guidance. It must not override case-specific evidence or Human-in-the-Loop controls.
