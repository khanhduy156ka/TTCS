# Human-in-the-Loop Remediation Approval Procedure

This document defines the internal approval policy used by the SOC Lab prototype.

## Approval boundary

A recommendation may be generated automatically, but an action that changes endpoint state must not be treated as executed merely because the recommendation exists.

Actions that restore, delete, quarantine, isolate, disable, terminate, or otherwise modify endpoint state require explicit analyst approval unless a separately defined deterministic policy authorizes them.

## Analyst review

Before approval, the analyst should review the observed evidence, proposed action, expected impact, verification method, and rollback considerations.

Approval confirms that the proposed action is authorized for controlled execution. Rejection records that the action must not proceed under the current decision.

## Audit requirements

The case should preserve whether approval was required, the analyst decision, analyst identifier, reason, decision timestamp, and corresponding audit event.

The approval state and execution state are separate concepts. An approved plan is not proof that endpoint execution occurred.

## Post-approval verification

After an authorized action is executed through an approved mechanism, verification should confirm the intended state change and preserve evidence of the result.

For file restoration, verification can include the restored content, cryptographic hash, and subsequent FIM telemetry.
