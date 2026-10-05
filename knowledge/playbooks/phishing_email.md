# Phishing Email Investigation Playbook

This document is an internal SOC Lab playbook for investigating suspicious email events and correlating email evidence with threat intelligence. Retrieved guidance supports investigation but does not replace case-specific telemetry.

## Initial assessment

Evaluate the observed sender, Reply-To address, recipient, subject, message content, URLs, domains, attachments, and available email-authentication evidence.

A Sender or From address that differs from the Reply-To address is relevant evidence but does not by itself prove spoofing or malicious intent.

Brand-impersonating or lookalike addresses, urgent account or payment language, credential-verification requests, and unexpected login links increase suspicion when supported by the observed email content.

Do not claim SPF, DKIM, or DMARC failure unless corresponding authentication evidence is available.

## IOC and threat-intelligence correlation

Extract each URL, domain, IP address, and attachment hash as a separate IOC and preserve its exact value and source field.

Threat-intelligence findings must remain scoped to the IOC that was queried. Do not transfer categories, reputation, or detection counts from a URL to its domain, attachment hash, or another entity.

A VirusTotal object reported as malicious or categorized as phishing is supporting evidence about that IOC. It does not by itself prove that the recipient accessed the IOC or that an endpoint was compromised.

If VirusTotal returns no object or report for an attachment hash, record the hash as unknown to the provider at lookup time. Provider-unknown status is not evidence that the attachment is clean, benign, or safe.

## User interaction and compromise assessment

Separate email delivery from user interaction and compromise.

Delivery of a phishing email does not prove that the recipient clicked a link, opened or executed an attachment, submitted credentials, or experienced endpoint compromise.

Use browser, proxy, DNS, endpoint, authentication, identity, or other available telemetry to establish interaction when those sources are available.

If no reliable click, execution, or credential-use evidence is supplied, record the corresponding state as unknown rather than assuming that no interaction occurred.

Threat-intelligence reputation alone must not be used to claim credential theft, malware execution, persistence, or endpoint compromise.

## Attachment assessment

Treat an attachment and the URLs contained in or accompanying an email as separate evidence sources.

A benign, provider-unknown, or non-malicious attachment does not make an email benign when other evidence supports phishing.

Preserve the attachment file name, content type, cryptographic hash, and analysis results when available.

Additional static or sandbox analysis may be performed in a controlled environment when required. Do not execute an untrusted attachment on the analyst workstation or production endpoint for testing.

## Investigation guidance

Preserve the original message identifiers, sender and Reply-To values, recipient, subject, message content or bounded excerpt, IOC values, attachment metadata, timestamps, and threat-intelligence results.

Correlate the email with recipient endpoint and identity activity when available.

Distinguish directly observed evidence from provider reputation, analyst interpretation, laboratory ground truth, and missing telemetry.

When Sender and Reply-To differ, report the mismatch as observed evidence. Do not label the sender as spoofed unless header or authentication evidence establishes spoofing.

## Response guidance

When the email and IOC evidence support phishing but no user interaction or endpoint compromise is established, prioritize evidence preservation, IOC monitoring or blocking through approved controls, user verification where appropriate, and continued monitoring.

Do not automatically isolate an endpoint, terminate processes, reset credentials, delete files, or perform other disruptive remediation solely because a URL or domain has malicious threat-intelligence detections.

If later evidence establishes credential submission, malicious execution, or endpoint compromise, escalate response according to the demonstrated impact and require Human-in-the-Loop approval for system-changing remediation under the SOC Lab policy.
