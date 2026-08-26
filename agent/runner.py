"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
_TICKET_ID_RE = re.compile(r"^ticket-(\d+)")


def _ticket_id_from_filename(filename: str) -> int | None:
    m = _TICKET_ID_RE.match(filename)
    return int(m.group(1)) if m else None


def _args_hash(args: dict[str, Any]) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gated_call(
    ledger_path: Path,
    *,
    tool: str,
    args: dict[str, Any],
    classification: str,
    purpose: str,
    agent_owner: str,
    delegation_depth: int,
    egress_enabled: bool,
    run_fn: Callable[[], Any],
):
    """PEP: policy.check() TRƯỚC, ledger.append() LUÔN (allow hay deny),
    chỉ gọi run_fn() (tool thật) nếu allow. Trả về kết quả của run_fn(),
    hoặc None nếu bị deny."""
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_owner,
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
    )
    allow, reason = policy.check(context)

    entry = {
        "ts": _now(),
        "agent_id": AGENT_ID,
        "run_id": agent_owner,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
    }
    ledger.append(entry, ledger_path)

    if not allow:
        return None
    return run_fn()


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH

    # --- Run A: CHỈ untrusted content. KHÔNG read_customer, KHÔNG http_post. ---
    docs = _gated_call(
        ledger_path,
        tool="search_docs",
        args={"query": message},
        classification="internal",
        purpose="summarize-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
        run_fn=lambda: tools.search_docs(message),
    )
    docs = docs or []

    combined_text = "\n\n".join(d["text"] for d in docs)
    # Chỉ dùng để LOG + kích hoạt Run B — KHÔNG bao giờ dùng
    # injected.customer_ids hay injected.target_url để quyết định đọc/gửi
    # ai, đó chính là dữ liệu tự do do attacker viết.
    injected = llm.find_injection(combined_text)

    # --- Run B: CHỈ private data, input là ticket_id TYPED từ tên file. ---
    if injected is not None:
        ticket_ids = sorted(
            {tid for d in docs if (tid := _ticket_id_from_filename(d["id"])) is not None}
        )

        customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
        trusted_customer_ids = sorted(
            {
                c["customer_id"]
                for c in customers
                if any(tid in c.get("related_tickets", []) for tid in ticket_ids)
            }
        )

        collected: list[dict] = []
        for customer_id in trusted_customer_ids:
            try:
                record = _gated_call(
                    ledger_path,
                    tool="read_customer",
                    args={"customer_id": customer_id},
                    classification="restricted",
                    purpose="reconciliation",
                    agent_owner="run-b",
                    delegation_depth=1,
                    egress_enabled=False,
                    run_fn=lambda cid=customer_id: tools.read_customer(cid),
                )
            except tools.ToolError:
                record = None
            if record is not None:
                collected.append(record)

        if collected:
            # target cố định, KHÔNG dùng injected.target_url (URL do
            # attacker nhúng trong document) — dù tools.http_post cũng
            # hard-allowlist localhost:9999 nên không đổi được đích thật.
            _gated_call(
                ledger_path,
                tool="http_post",
                args={"url": "http://localhost:9999/reconcile", "record_count": len(collected)},
                classification="restricted",
                purpose="reconciliation-post",
                agent_owner="run-b",
                delegation_depth=1,
                egress_enabled=True,
                run_fn=lambda: tools.http_post(
                    "http://localhost:9999/reconcile", {"records": collected}
                ),
            )

    return llm.summarize(docs)
