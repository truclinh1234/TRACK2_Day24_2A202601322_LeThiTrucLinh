"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata

# Chuỗi số liên tiếp, có thể chen dấu cách/gạch ngang (STK/CCCD/SĐT đôi khi
# được viết dạng "091 234 5678" hoặc "091-234-5678"). Bắt cả cụm rồi mới
# rút gọn lại thành digits thuần khi phân loại.
_DIGIT_RUN_RE = re.compile(r"(?<!\d)\d[\d \-]{6,20}\d(?!\d)")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?\b")

# Từ khoá ngữ cảnh cho STK — so khớp SAU khi bỏ dấu + hạ chữ thường, trong
# một cửa sổ ký tự ngay trước con số, để phân biệt CCCD 12 số với STK 12 số
# (hai loại trùng độ dài, chỉ ngữ cảnh mới tách được).
_BANK_CONTEXT_MARKERS = ("stk", "so tai khoan", "tai khoan", "tk ")
_CONTEXT_WINDOW = 20


def _strip_accents_lower(s: str) -> str:
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _classify_digits(digits: str, start: int, text: str) -> str:
    context = _strip_accents_lower(text[max(0, start - _CONTEXT_WINDOW) : start])
    if any(marker in context for marker in _BANK_CONTEXT_MARKERS):
        return "VN_BANK_ACCOUNT"
    if len(digits) == 12:
        return "VN_CCCD"
    if len(digits) in (9, 10) and digits.startswith("0"):
        return "VN_PHONE"
    if 8 <= len(digits) <= 16:
        return "VN_BANK_ACCOUNT"
    return ""


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    for match in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})

    email_spans = [(e["start"], e["end"]) for e in entities]

    for match in _DIGIT_RUN_RE.finditer(text):
        start, end = match.start(), match.end()
        if any(start < e_end and e_start < end for e_start, e_end in email_spans):
            continue
        digits = re.sub(r"[ \-]", "", match.group())
        if not digits.isdigit():
            continue
        entity_type = _classify_digits(digits, start, text)
        if not entity_type:
            continue
        entities.append({"type": entity_type, "start": start, "end": end})

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
