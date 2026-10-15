# Lab Setup

This page records the **lab-specific network and Wazuh integration** for the SOC Multi-Agent prototype. VM, operating-system, Wazuh, and PostgreSQL installation steps are covered by their official documentation.

## Network

The VMware lab uses a private LAN segment (`SOC-LAB-NEW`) and a host-only network (`VMnet1`).

| Machine | Interface / Network | IPv4 | Role |
|---|---|---|---|
| Ubuntu VM | `ens37` · `SOC-LAB-NEW` | `10.10.10.10/24` | Wazuh Manager / Indexer |
| Windows 11 VM | `Ethernet1` · `SOC-LAB-NEW` | `10.10.10.20/24` | Wazuh Agent (`WIN-11`) |
| Kali Linux VM | `eth1` · `SOC-LAB-NEW` | `10.10.10.30/24` | Additional lab VM |
| Ubuntu VM | `ens38` · `VMnet1` | `192.168.41.10/24` | Indexer access from the host |
| Windows host | VMware `VMnet1` | `192.168.41.1/24` | SOC application workstation |

The VMs also have NAT adapters configured; those interfaces were **down** when this topology was checked. The internal lab connections shown above do not rely on them.

## Wazuh Agent

The Windows Agent is configured to connect to Wazuh Manager at `10.10.10.10`. Agent ID `001` (`WIN-11`) was confirmed **Active** using:

```bash
sudo /var/ossec/bin/agent_control -l
```

Observed `ossec.conf` log sources:

- Windows Event Channels: `Application`, `Security`, `System`
- `Microsoft-Windows-PowerShell/Operational`
- `Microsoft-Windows-Windows Defender/Operational`
- `active-response\\active-responses.log` (syslog format)

**File Integrity Monitoring (FIM)** directories were not confirmed by the inspected configuration output; enable and document the actual `syscheck` paths only if required by the lab. The list above does not establish email ingestion or custom Wazuh rules.

## SOC Connection

PostgreSQL was confirmed running on the Windows host (port `5432`). Ollama and `uv` are installed there; start Ollama, FastAPI, and Streamlit as described in the root [README](../README.md).

The Windows host successfully reached the Indexer TCP endpoint via `VMnet1`:

```powershell
Test-NetConnection 192.168.41.10 -Port 9200
```

Configure the project `.env` for this lab (example only; supply your own account credentials):

```dotenv
WAZUH_INDEXER_URL=https://192.168.41.10:9200
```

A successful TCP probe confirms network reachability, **not** HTTPS trust or Indexer authentication. Use the correct certificate trust configuration for `WAZUH_VERIFY_SSL`.

## Verification

1. Check that the Windows Agent is **Active** in Wazuh.
2. Confirm that relevant events appear in Wazuh Indexer.
3. Start the SOC API and Watcher (commands in the root README), then generate an authorized lab event.
4. Confirm the alert becomes a case in PostgreSQL and appears in Streamlit.

The Watcher starts at the newest indexed event on its first run without a checkpoint; start it **before** generating an event to test live ingestion.
