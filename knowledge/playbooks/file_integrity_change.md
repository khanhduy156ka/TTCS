# File Integrity Change Investigation Playbook

This document is an internal SOC Lab playbook for Wazuh File Integrity Monitoring events.

## Interpretation of FIM evidence

A Wazuh FIM event can establish that a monitored file changed and can provide integrity metadata such as hashes, timestamps, changed attributes, and content differences when configured.

FIM evidence alone does not establish the identity of the actor, the responsible process, authorization status, or malicious intent.

## Security-weakening configuration changes

A transition from a previously observed security-enabling configuration to a security-disabled configuration should receive additional investigation.

For the SOC Lab protected configuration, a change from `mode=secure` to `mode=disabled` is treated as a security-weakening change requiring analyst review.

The previous FIM-observed value is evidence of the prior observed state. It should not automatically be described as an organizationally approved baseline unless separate authorization or configuration-management evidence establishes that fact.

## Investigation guidance

Preserve the before and after hashes, modification times, content difference, monitored path, and Wazuh event metadata.

Where available, correlate the modification time with process activity, user activity, authentication events, file-access telemetry, or approved change records.

Do not invent an actor or process when no telemetry identifies one.

## Response guidance

When the current state is demonstrably weaker and restoration is technically clear, the system may propose restoration to the previous FIM-observed secure value.

Restoration remains a system-changing action and therefore requires Human-in-the-Loop approval in the SOC Lab prototype.

After an approved restoration, verify the restored content, compare its SHA-256 with the known pre-change value when available, and confirm continued FIM monitoring.
