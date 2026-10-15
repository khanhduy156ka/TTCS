# SOC Multi-Agent

Hệ thống hỗ trợ phân tích cảnh báo bảo mật từ **Wazuh** bằng kiến trúc AI đa tác tử gồm **Triage, Enrichment, Investigation và Remediation**. **CrewAI Flow** điều phối các bước theo điều kiện; **PostgreSQL** lưu hồ sơ và lịch sử xử lý; **Streamlit** cung cấp giao diện cho chuyên viên SOC.

## Kiến trúc và luồng xử lý

```text
Wazuh Agent/Manager -> Wazuh Indexer
                         |
                    Wazuh Watcher
                         |
                Chuẩn hóa cảnh báo
                         |
                  POST /alerts (FastAPI)
                         |
                  SOCSupervisorFlow
                         |
                       Triage
                         |----> Monitoring (nếu không cần phân tích sâu)
                         v
                     Enrichment
                         |----> Monitoring (nếu không cần điều tra)
                         v
                  RAG -> Investigation
                                  |----> Monitoring (nếu không cần remediation)
                                  v
                           Remediation plan
                                  |----> Remediation Proposed (nếu không cần duyệt)
                                  v
                          Pending Human Approval
                                  |
                          Approve / Reject
                                  |
                    Approved / Rejected (lưu quyết định)
```

Các giai đoạn AI được gọi **tuần tự hoặc theo điều kiện**, không chạy song song trong pipeline chính. Supervisor là logic điều phối workflow, không phải một LLM độc lập. Khi RAG truy xuất lỗi, Investigation có thể tiếp tục mà không có ngữ cảnh RAG và lỗi được ghi trong audit.

## Thành phần chính

| Thành phần | Vai trò |
|---|---|
| Wazuh Watcher | Đọc cảnh báo mới từ Indexer, lọc và chuyển đến API |
| FastAPI | Tiếp nhận cảnh báo, cung cấp API truy vấn hồ sơ và ghi nhận review |
| Triage | Phân loại, xác định mức ưu tiên và nhu cầu phân tích tiếp |
| Enrichment | Trích xuất IOC, liên hệ MITRE ATT&CK và bổ sung threat intelligence |
| RAG | Truy xuất playbook/quy trình nội bộ làm ngữ cảnh cho Investigation |
| Investigation | Tổng hợp bằng chứng, đưa ra nhận định và xác định nhu cầu remediation |
| Remediation | Xây dựng kế hoạch khắc phục khi cần |
| PostgreSQL | Lưu case, trạng thái và audit trail; pgvector lưu embedding RAG |
| Streamlit | Xem hồ sơ, kết quả các bước và ghi nhận phê duyệt/từ chối khi hợp lệ |

## Yêu cầu

- Python **>= 3.13** và [uv](https://docs.astral.sh/uv/).
- PostgreSQL; bật extension **pgvector** nếu sử dụng RAG.
- Ollama và các mô hình phù hợp với cấu hình; embedding RAG dùng `qwen3-embedding:0.6b` (1024 chiều).
- Wazuh Indexer khi lấy cảnh báo thực; có thể xem các case **đã lưu** trên Streamlit mà không cần Watcher đang chạy.
- Thực hiện lệnh từ **thư mục gốc repository**; các lệnh dưới đây minh họa trên Windows PowerShell.

## 1. Cài đặt và cấu hình

```powershell
uv sync
```

Ứng dụng đọc cấu hình qua file `.env` tại thư mục gốc (xem `src/soc_multi_agent/config.py`). Sao chép `.env.example` thành `.env` (trên PowerShell: `Copy-Item .env.example .env`), sau đó thay toàn bộ giá trị mẫu. Các trường cấu hình bắt buộc khi khởi tạo Settings gồm kết nối Wazuh Indexer và mật khẩu PostgreSQL. Ví dụ:

```dotenv
WAZUH_INDEXER_URL=https://YOUR_INDEXER_HOST:9200
WAZUH_INDEXER_USER=YOUR_WAZUH_USER
WAZUH_INDEXER_PASSWORD=YOUR_WAZUH_PASSWORD

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=soc_multi_agent
POSTGRES_USER=soc_app
POSTGRES_PASSWORD=YOUR_POSTGRES_PASSWORD

LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen3.5:9b
```

Các model theo nhiệm vụ có thể được cấu hình riêng qua `OLLAMA_FAST_MODEL`, `OLLAMA_REASONING_MODEL` và các biến tương ứng. Các giá trị trên **không xác nhận cấu hình của một buổi thử nghiệm cụ thể**.

**Không commit hoặc chia sẻ file `.env` thật, mật khẩu, API key và dữ liệu nhạy cảm.**

PostgreSQL cần được tạo sẵn database/user tương ứng với cấu hình. Sau đó tạo bảng hồ sơ:

```powershell
psql -h localhost -U soc_app -d soc_multi_agent -f sql/schema.sql
```


### Chuẩn bị dữ liệu MITRE ATT&CK

Module `services/mitre_attack.py` đọc `data/mitre/enterprise-attack.json`. File dữ liệu này không được đưa vào repository; để chuẩn bị môi trường mới, chạy từ thư mục gốc:

```powershell
uv run python scripts/download_mitre.py
```

Script tải dataset Enterprise ATT&CK STIX công khai từ repository `mitre-attack/attack-stix-data`, kiểm tra JSON cơ bản rồi lưu đúng vị trí. Cần có kết nối Internet. Vì nguồn mặc định là nhánh `master`, nội dung có thể thay đổi theo thời điểm: muốn tái lập chính xác một phiên bản nghiên cứu, sử dụng URL tại một commit/tag cụ thể và lưu lại SHA-256 của file.

### Chuẩn bị Ollama

Bảo đảm dịch vụ Ollama đang chạy và tải các model đã chọn. Với cấu hình mặc định ở trên:

```powershell
ollama pull qwen3.5:9b
ollama pull qwen3-embedding:0.6b
```

Nếu `.env` chọn model khác, hãy tải model tương ứng.

### Khởi tạo và nạp dữ liệu RAG (khi sử dụng)

Bật extension `vector` trong database PostgreSQL (thao tác này có thể cần tài khoản đủ quyền):

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Sau đó thực hiện tại thư mục dự án:

```powershell
uv run python -m soc_multi_agent.rag.init_db
uv run python -m soc_multi_agent.rag.ingest --knowledge-dir knowledge
```

Nguồn tri thức nằm trong `knowledge/playbooks/` và `knowledge/procedures/`. Công cụ ingest in số tài liệu và số đoạn đang lưu trong database sau khi chạy. Có thể thêm `--force` khi chủ đích muốn tạo lại embedding cho tài liệu không đổi.

## 2. Chạy FastAPI

Mở terminal tại thư mục dự án:

```powershell
uv run python -m uvicorn soc_multi_agent.api.app:app --host 127.0.0.1 --port 8000
```

- API: http://127.0.0.1:8000
- Kiểm tra API **và kết nối PostgreSQL**: http://127.0.0.1:8000/health
- Giao diện tài liệu API (Swagger): http://127.0.0.1:8000/docs

Các endpoint có trong mã nguồn:

| Method | Endpoint | Mục đích |
|---|---|---|
| GET | `/health` | Kiểm tra API và PostgreSQL |
| GET | `/cases` | Danh sách case (hỗ trợ `limit`, `status`) |
| GET | `/cases/{case_id}` | Xem trạng thái đầy đủ của một case |
| POST | `/alerts` | Tiếp nhận cảnh báo chuẩn hóa và chạy workflow |
| POST | `/cases/{case_id}/approve` | Ghi nhận quyết định đồng ý |
| POST | `/cases/{case_id}/reject` | Ghi nhận quyết định từ chối |

`POST /alerts` nhận **đối tượng bao ngoài** gồm `alert` và `case_id` tùy chọn, không phải một `NormalizedAlert` đứng trực tiếp ở cấp cao nhất:

```json
{
  "case_id": "case-demo-001",
  "alert": {
    "alert_id": "demo-001",
    "timestamp": "2026-10-07T09:30:00+07:00",
    "agent_id": "001",
    "agent_name": "lab-host",
    "rule_id": "100001",
    "rule_level": 8,
    "rule_description": "Example alert for schema demonstration"
  }
}
```

Ví dụ trên chỉ minh họa định dạng; không phải một sự kiện thật hoặc kết quả thử nghiệm.

## 3. Chạy Streamlit Dashboard

**Đây là giao diện để xem các hồ sơ SOC đã lưu và thao tác Human-in-the-Loop.**

Mở **một terminal khác** tại thư mục gốc repository và chạy:

```powershell
uv run streamlit run src/soc_multi_agent/ui/streamlit_app.py
```

Mặc định Streamlit cung cấp địa chỉ cục bộ, thường là **http://localhost:8501**. Mở địa chỉ mà terminal thông báo nếu cổng đã thay đổi.

### Trước khi mở giao diện

1. Đảm bảo `uv sync` đã cài đặt dependencies và `.env` đã cấu hình.
2. Đảm bảo **PostgreSQL đang chạy**, database đã có bảng `soc_cases` (theo `sql/schema.sql`).
3. Để có dữ liệu hiển thị, cần có ít nhất một case đã được xử lý và lưu vào PostgreSQL.

**Lưu ý:** Streamlit trong repository **truy vấn PostgreSQL trực tiếp** qua `list_cases` và `load_case`; các nút Approve/Reject cũng gọi `human_review` trực tiếp. Do đó, **chỉ xem case đã lưu không yêu cầu FastAPI hoặc Wazuh Watcher đang chạy**. Tuy nhiên, để nhận và phân tích **cảnh báo Wazuh mới** theo luồng tích hợp, cần khởi chạy API và Watcher ở các terminal riêng.

### Cách sử dụng giao diện

- **Thanh bên trái:** chọn `case_id`, lọc theo trạng thái và bấm **Refresh cases** để cập nhật danh sách.
- **Case List và Case Summary:** xem tổng quan các hồ sơ và case đang chọn.
- **Các tab:** `Alert`, `Triage`, `Enrichment`, `Investigation`, `Remediation`, `Human Review`, `Audit Trail`, `Performance`.
- **Human Review:** với hồ sơ có kế hoạch đang chờ phê duyệt, nhập tên analyst (bắt buộc), reason (tùy chọn) và chọn **Approve remediation** hoặc **Reject remediation**. Quyết định được lưu vào PostgreSQL.
- **Performance:** hiển thị thời lượng các giai đoạn ứng dụng đã đo, không phải MTTR hoặc thời gian từ lúc Wazuh phát hiện đến khi xử lý hoàn tất.

**Approve/Reject chỉ lưu quyết định, không tự thực thi lệnh remediation trên endpoint.** Giao diện hiện chưa triển khai xác thực/phân quyền người dùng; chỉ sử dụng trong môi trường lab tin cậy.

### Nếu không thấy dữ liệu hoặc giao diện báo lỗi

- `No SOC cases are currently stored`: database hiện chưa có case để hiển thị.
- `Unable to load cases from PostgreSQL`: kiểm tra PostgreSQL, thông tin trong `.env`, bảng `soc_cases` và quyền kết nối.
- Lỗi import module/dependency: chạy lại `uv sync` tại đúng thư mục gốc dự án; dùng `uv run` như lệnh trên.
- Không thấy case mới: kiểm tra API, Watcher và trạng thái xử lý; sau đó bấm **Refresh cases**.

## 4. Theo dõi cảnh báo mới từ Wazuh

Chỉ chạy phần này khi Wazuh Indexer và FastAPI đã được cấu hình/kết nối. Mở một terminal khác:

```powershell
uv run python -m soc_multi_agent.wazuh_ingestion --watch --size 100 --min-level 5 --interval 15
```

Watcher lưu checkpoint mặc định tại `.runtime/wazuh_ingestion_state.json` để theo dõi cảnh báo mới. Ở lần chạy đầu tiên khi chưa có checkpoint, chương trình khởi tạo mốc dựa trên cảnh báo mới nhất và không tự phát lại toàn bộ lịch sử. Khi demo, nên khởi động Watcher **trước khi tạo sự kiện thử nghiệm**.

Không tùy tiện xóa checkpoint hoặc dùng `--reset-watermark`: thao tác reset có thể khiến cảnh báo cũ bị bỏ qua. Có thể dùng `--dry-run` để xem đánh giá ứng viên mà không gửi cảnh báo hoặc lưu checkpoint live.

## 5. Kiểm tra hệ thống sau cài đặt

- Truy cập `http://127.0.0.1:8000/health`: API và PostgreSQL phải kết nối thành công.
- Truy cập `http://127.0.0.1:8000/docs` để kiểm tra các endpoint.
- Mở Streamlit và xác nhận danh sách case có thể truy vấn từ PostgreSQL (ban đầu có thể trống).
- Khi kết nối Wazuh thực, chạy Watcher và quan sát log chuyển cảnh báo mới vào API. Chỉ kiểm thử bằng dữ liệu được phép sử dụng trong môi trường lab.
- Kiểm tra số tài liệu RAG sau khi ingest bằng `uv run python -c "from soc_multi_agent.rag.database import get_rag_schema_status; print(get_rag_schema_status())"`.

Các script nghiên cứu `benchmarks/`, bộ kiểm thử `tests/` và chương trình fixture thủ công đã được bỏ khỏi nhánh chính để repository tập trung vào hệ thống vận hành; có thể tra cứu trong lịch sử Git nếu cần.

## Giới hạn của nguyên mẫu

- RAG cung cấp tri thức tham khảo, không thay thế bằng chứng gốc của sự cố.
- Trạng thái `monitoring` không có nghĩa cảnh báo lành tính hoặc hồ sơ đã được đóng.
- Hệ thống chưa tự thực thi remediation trên endpoint.
- Chưa có cơ chế tự động tiếp tục workflow bị lỗi/chưa hoàn tất.
- Streamlit/API hiện chưa có xác thực và phân quyền người dùng hoàn chỉnh.

> **Lưu ý:** Đây là hướng dẫn cho môi trường phát triển/lab, không phải quy trình triển khai production.
