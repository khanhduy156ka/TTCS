# SOC Multi-Agent

Hệ thống SOC đa tác tử hỗ trợ xử lý cảnh báo bảo mật từ Wazuh bằng các AI agent chuyên biệt cho Triage, Enrichment, Investigation và Remediation.

## Pipeline

```text
Wazuh
  -> Normalization / FastAPI
  -> Supervisor
  -> Triage
  -> Enrichment
  -> RAG
  -> Investigation
  -> Remediation khi cần
  -> Human approval
  -> Monitoring / Approved / Rejected
```

## Thành phần chính

- Triage: đánh giá cảnh báo và quyết định bước xử lý tiếp theo
- Enrichment: bổ sung IOC và threat intelligence
- RAG: truy xuất playbook và procedure nội bộ
- Investigation: tổng hợp bằng chứng và đánh giá sự cố
- Remediation: tạo kế hoạch xử lý khi cần
- Human review: analyst phê duyệt các hành động remediation khi workflow yêu cầu
- Wazuh ingestion: lấy alert mới từ Wazuh Indexer và đưa vào pipeline

## Yêu cầu

- Python >= 3.13
- PostgreSQL với pgvector
- Ollama cho các model local
- Wazuh Indexer khi xử lý alert thực

Dependency Python được quản lý bằng `uv` và khai báo trong `pyproject.toml`.

## Cài đặt

```powershell
uv sync
```

Cấu hình local được đọc từ `.env` theo các trường trong `src/soc_multi_agent/config.py`.

File `.env` chỉ dùng cho môi trường local và không được commit vào Git.

## Khởi chạy API

```powershell
uv run python -m uvicorn soc_multi_agent.api.app:app --host 127.0.0.1 --port 8000
```

## Theo dõi alert từ Wazuh

```powershell
uv run python -m soc_multi_agent.wazuh_ingestion --watch --size 100 --min-level 5 --interval 15
```

## Kịch bản đã kiểm chứng

- Suspicious PowerShell
- File Integrity Monitoring
- Phishing email

## Nguyên tắc xử lý

- RAG chỉ cung cấp guidance và provenance, không được xem là incident evidence
- Ưu tiên telemetry và bằng chứng gốc hơn nội dung do LLM suy diễn
- Remediation cần human approval khi workflow yêu cầu
- Hệ thống không tự động thực thi endpoint remediation
