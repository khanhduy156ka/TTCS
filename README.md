# SOC Multi-Agent

He thong SOC da tac tu ho tro xu ly canh bao bao mat tu Wazuh bang cac AI agent chuyen biet cho Triage, Enrichment, Investigation va Remediation.

## Pipeline

```text
Wazuh
  -> Normalization / FastAPI
  -> Supervisor
  -> Triage
  -> Enrichment
  -> RAG
  -> Investigation
  -> Remediation khi can
  -> Human approval
  -> Monitoring / Approved / Rejected
```

## Thanh phan chinh

- Triage: danh gia canh bao va quyet dinh buoc xu ly tiep theo
- Enrichment: bo sung IOC va threat intelligence
- RAG: truy xuat playbook va procedure noi bo
- Investigation: tong hop bang chung va danh gia su co
- Remediation: tao ke hoach xu ly khi can
- Human review: analyst phe duyet cac hanh dong remediation khi workflow yeu cau
- Wazuh ingestion: lay alert moi tu Wazuh Indexer va dua vao pipeline

## Yeu cau

- Python >= 3.13
- PostgreSQL voi pgvector
- Ollama cho cac model local
- Wazuh Indexer khi xu ly alert thuc

Dependency Python duoc quan ly bang `uv` va khai bao trong `pyproject.toml`.

## Cai dat

```powershell
uv sync
```

Cau hinh local duoc doc tu `.env` theo cac truong trong `src/soc_multi_agent/config.py`.

File `.env` chi dung cho moi truong local va khong duoc commit vao Git.

## Khoi chay API

```powershell
uv run python -m uvicorn soc_multi_agent.api.app:app --host 127.0.0.1 --port 8000
```

## Theo doi alert tu Wazuh

```powershell
uv run python -m soc_multi_agent.wazuh_ingestion --watch --size 100 --min-level 5 --interval 15
```

## Kich ban da kiem chung

- Suspicious PowerShell
- File Integrity Monitoring
- Phishing email

## Nguyen tac xu ly

- RAG chi cung cap guidance va provenance, khong duoc xem la incident evidence
- Uu tien telemetry va bang chung goc hon noi dung do LLM suy dien
- Remediation can human approval khi workflow yeu cau
- He thong khong tu dong thuc thi endpoint remediation
