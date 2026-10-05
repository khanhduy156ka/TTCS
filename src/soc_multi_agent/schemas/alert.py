from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: datetime

    agent_id: str
    agent_name: str
    agent_ip: str | None = None

    manager_name: str | None = None

    rule_id: str
    rule_level: int
    rule_description: str
    rule_groups: list[str] = Field(default_factory=list)

    event_id: str | None = None
    provider_name: str | None = None
    computer: str | None = None
    channel: str | None = None
    severity_value: str | None = None

    subject_user: str | None = None
    target_user: str | None = None

    source_ip: str | None = None
    source_port: str | None = None
    workstation_name: str | None = None

    logon_type: str | None = None
    authentication_package: str | None = None

    process_name: str | None = None

    status: str | None = None
    sub_status: str | None = None

    script_block_text: str | None = None
    script_block_id: str | None = None

    base64_decodings: dict[str, str] = Field(
        default_factory=dict
    )

    # Giu Windows event context cua provider de downstream agent khong bi gioi han boi bo field co dinh
    event_message: str | None = None
    event_data: dict[str, Any] = Field(
        default_factory=dict
    )

    # Giu full_log de audit, cac truong FIM/email da chuan hoa duoc dung cho downstream agent
    wazuh_location: str | None = None
    full_log: str | None = None

    # Du lieu File Integrity Monitoring cua Wazuh Syscheck/FIM
    fim_event: str | None = None
    fim_path: str | None = None
    fim_mode: str | None = None
    fim_diff: str | None = None
    fim_changed_attributes: list[str] = Field(
        default_factory=list
    )

    fim_size_before: str | None = None
    fim_size_after: str | None = None

    fim_md5_before: str | None = None
    fim_md5_after: str | None = None
    fim_sha1_before: str | None = None
    fim_sha1_after: str | None = None
    fim_sha256_before: str | None = None
    fim_sha256_after: str | None = None

    fim_mtime_before: str | None = None
    fim_mtime_after: str | None = None

    # Giu day du Syscheck object de audit/debug ma khong bat downstream phu thuoc moi raw key cua Wazuh
    syscheck_data: dict[str, Any] = Field(
        default_factory=dict
    )

    # Du lieu email security chi la telemetry quan sat duoc, khong tu khang dinh phishing, maliciousness hay compromise
    email_event_type: str | None = None
    email_message_id: str | None = None

    email_sender: str | None = None
    email_reply_to: str | None = None
    email_recipient: str | None = None
    email_subject: str | None = None
    email_body_excerpt: str | None = None

    email_urls: list[str] = Field(
        default_factory=list
    )
    email_domains: list[str] = Field(
        default_factory=list
    )

    email_attachment_name: str | None = None
    email_attachment_content_type: str | None = None
    email_attachment_sha256: str | None = None

    email_user_clicked: bool | None = None
    email_attachment_executed: bool | None = None

    # Gan related event vao cung case khi co correlation ID on dinh, vi du Defender detection ID noi Event 1116 voi 1117
    correlated_events: list[dict[str, Any]] = Field(
        default_factory=list
    )

    mitre_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
