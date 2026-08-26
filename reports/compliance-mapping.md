# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement trong lab này — xem stretch goal #4 (`Guide.md` §Stretch goals: "Delete cascade: xoá 1 subject khỏi customers.json, giữ ledger nguyên vẹn"). Hiện tại `data/customers.json` không có endpoint/hàm xoá subject nào. | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho lời gọi LLM API (kể cả khi dùng `--model claude-...`, dữ liệu ticket đi qua API của Anthropic ở nước ngoài) | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-run identity tách quyền Run A/Run B qua field `agent_owner`/`delegation_depth` trong `PolicyContext`, ghi lại trong ledger qua field `run_id` (= `agent_owner`) cho mỗi tool call | `agent/policy.py:32-34` (field định nghĩa), `agent/runner.py:93-94,104-105,113,137-138,174-175,194-195` (Run A dùng `agent_owner="run-a", delegation_depth=0`; Run B dùng `agent_owner="run-b", delegation_depth=1` — Run B không bao giờ đứng tên `run-a` dù được Run A "gọi tới") |
| ASI01 — goal hijack | Trifecta split: Run A (đọc untrusted content) không bao giờ gọi `read_customer`/`http_post`; Run B (đọc private data + egress) chỉ nhận `ticket_id` kiểu `int` trích từ tên file, không bao giờ nhận nguyên văn free text — nên chỉ thị injection trong `corpus/` (mọi biến thể 1-5, kể cả biến thể phá filter chuỗi) không thể điều khiển được Run B | `agent/runner.py:152-161` (hàm `handle`: `ticket_ids` trích từ `_ticket_id_from_filename` — định nghĩa dòng 72 — không từ `injected.customer_ids`); bằng chứng chạy thật: `reports/attack-after.log`, `pytest tests/test_split.py` (1 passed), `pytest tests/test_injection.py` (5 passed) |
| ISO 42001 Clause 5-6 | Policy-as-code (`agent/policy.py`) có review qua git history — mỗi thay đổi logic policy là 1 commit riêng, có thể truy vết | `git log --oneline -- agent/policy.py` → commit `c5e3515` "Bước 3b: implement PEP tại tool call (agent/policy.py)" |
