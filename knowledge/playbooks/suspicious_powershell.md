# Suspicious PowerShell Investigation Playbook

This document is an internal SOC Lab playbook for the prototype environment. It guides investigation and does not by itself establish malicious intent.

## Initial assessment

PowerShell execution should be evaluated using the available command line, script-block telemetry, encoded content, parent process, user context, host context, and surrounding events. The use of PowerShell alone is not evidence of malicious activity.

Encoded or obfuscated content increases the need for investigation when the decoded result, execution context, or surrounding telemetry is inconsistent with expected administrative activity.

## Evidence collection

Preserve the original PowerShell command or script block when available. Record the host, user, process identifiers, timestamp, script-block identifier, decoded Base64 content, and relevant correlated endpoint events.

Decoded Base64 content should be treated as evidence derived from the original encoded value. Analysts should distinguish the decoded text from conclusions about intent.

## Investigation guidance

Correlate the PowerShell event with process creation, authentication activity, network connections, file changes, and relevant endpoint telemetry when those sources are available.

Validate any MITRE ATT&CK mapping against observed behavior. PowerShell execution may support a PowerShell technique mapping, while obfuscation-related mappings require evidence that obfuscation or encoding was actually used.

Do not infer a remote attacker, credential compromise, persistence, or lateral movement unless corresponding evidence exists.

## Response guidance

If the evidence is suspicious but no harmful system change requiring immediate reversal is established, continue monitoring and collect additional evidence rather than automatically performing disruptive remediation.

Any disruptive response should be based on the demonstrated impact and should follow the SOC approval procedure.
