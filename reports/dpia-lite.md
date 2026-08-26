# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent trong lab này chạm vào 2 nhóm dữ liệu:

- **Nội dung ticket** (`corpus/*.md`, qua tool `search_docs`) — văn bản tự
  do, có thể chứa PII nếu khách hàng tự viết vào (tên, số điện thoại...);
  không có cấu trúc, không được xác thực nguồn (untrusted content).
- **Hồ sơ khách hàng** (`data/customers.json`, qua tool `read_customer`) —
  dữ liệu cấu trúc, PII trực tiếp: `name`, `cccd` (CCCD 12 số), `phone`
  (SĐT), `bank_account` (số tài khoản ngân hàng), `email`.

`agent/pii.py` phát hiện 4 loại PII trong text tự do:
`VN_CCCD`, `VN_PHONE`, `VN_BANK_ACCOUNT`, `EMAIL` (recall/precision đo
được = 1.000 trên `tests/vn_pii_testset.jsonl`).

## 2. Mục đích gì

Agent đọc `corpus/` để trả lời yêu cầu tổng hợp/tóm tắt ticket của người
dùng nội bộ (nhân viên hỗ trợ). Việc đọc `data/customers.json` (PII) chỉ
xảy ra khi có một chỉ thị "đối soát" (reconciliation) được phát hiện
trong nội dung ticket — và chỉ đọc đúng khách hàng có ticket_id khớp với
`related_tickets` của họ (nguồn tin cậy), không đọc theo customer_id tự
do do bất kỳ ai viết trong văn bản. Việc gửi dữ liệu ra ngoài
(`http_post`) hiện bị `agent/policy.py` deny tuyệt đối với dữ liệu
`classification=restricted` — tức là trong thiết kế hiện tại, **không có
mục đích nghiệp vụ hợp lệ nào khiến PII thật sự rời khỏi hệ thống** qua
đường này; mọi lần gọi đều bị chặn và ghi log (xem
`reports/ledger.jsonl`, dòng `decision=deny` cho `http_post`).

## 3. Chảy đi đâu

- **`reports/sink.log`** — chỉ trong phạm vi lab, mô phỏng một đích exfil
  cục bộ (`localhost:9999`, hard-allowlist trong `agent/tools.py`); sau
  khi contain, log này rỗng với mọi biến thể tấn công đã thử (xem
  `reports/attack-after.log`).
- **`reports/ledger.jsonl`** — audit trail nội bộ, append-only,
  tamper-evident (`agent/ledger.py`); mỗi entry chỉ chứa `args_hash` (hash
  SHA-256 của tham số gọi tool), KHÔNG chứa PII thật ở dạng plaintext.
- **API của model provider (nếu dùng `--model claude-...` thay vì
  `--mock`)** — đây LÀ chuyển dữ liệu xuyên biên giới theo NĐ 356/2025:
  nội dung ticket (và có thể cả PII nếu chưa được redact trước khi đưa
  vào prompt) được gửi tới API của Anthropic, hạ tầng đặt ngoài Việt Nam.
  Lab này mặc định chấm bằng `--mock` (không gọi network thật, xem
  `Guide.md`/`README.md` §Model dùng cho lab này) chính xác để tránh vấn
  đề này khi demo/chấm điểm, nhưng nếu triển khai thật với `--model`, cần:
  (a) áp dụng `agent/pii.py::redact()` lên nội dung trước khi đưa vào
  prompt của model bên ngoài, và (b) ký hợp đồng xử lý dữ liệu
  (data processing agreement) với provider có điều khoản chuyển dữ liệu
  xuyên biên giới phù hợp NĐ 356/2025. Ở trạng thái hiện tại của
  `agent/runner.py`, `egress_enabled=True` chỉ được set cho tool
  `http_post` nội bộ (bị deny), KHÔNG áp dụng cho lời gọi tới model API —
  đây là một khoảng trống cần lưu ý nếu mở rộng ra ngoài phạm vi lab.
