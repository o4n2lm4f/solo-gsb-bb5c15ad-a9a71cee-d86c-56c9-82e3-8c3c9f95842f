"""证据封存包：样本元数据快照 + 审计报告 + 全部未损坏附件的 ZIP 导出，
以及不落库的封存包校验。

导出（``build_evidence_zip``）的一致性保证：

1. 在**同一个数据库读事务**（``BEGIN`` … ``COMMIT``）中固定样本、事件、
   签署、交接确认与附件记录等全部元数据，并计算快照指纹；
2. 写包前对全部待封入附件**逐项现场复算 SHA-256**（``verify_blob``），
   随后在同一读事务内**再次读取链路与附件记录并比对快照指纹**——期间
   事件链或附件记录发生任何增删改，指纹不一致即中止导出（绝不产出
   「半旧半新」的混合快照包）；
3. 写入 ZIP 时以内存 ZIP + 流式复制方式再次累加各附件摘要，复制结束
   后比对，期间实体被替换 / 截断同样中止。

SQLite 默认 rollback journal 模式下，读事务会阻塞写者提交（写者等待
``busy_timeout``），而附件删除的磁盘解引用发生在其写事务提交之后，
因此上述「复核 -> 比对 -> 写包」窗口内实体不会被合法流程移除。

校验（``verify_evidence_bytes``）**不访问数据库、不落任何记录**：
限制解压总量 / 单文件大小 / 文件数量（防 zip 炸弹），拒绝绝对路径与
路径穿越条目，随后逐项核对清单声明、缺失、多余与 SHA-256 摘要异常，
返回中文差异。
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime
from typing import Any, Optional
from sqlite3 import Connection

from .attachments import REASON_TEXT, verify_blob
from .audit import build_audit
from .handovers import build_handover_view
from .report import build_markdown

PACKAGE_FORMAT = "evidence-pack"
PACKAGE_VERSION = 1
MANIFEST_NAME = "manifest.json"
REPORT_NAME = "audit_report.md"
EVIDENCE_DIR = "evidence"

# 读事务固定快照时，写者最多等待的时间（毫秒）：读事务极短，5 秒足够
READ_BUSY_TIMEOUT_MS = 5000

# ---------- 校验入口的解压限制（防 zip 炸弹 / 路径穿越） ----------

MAX_UPLOAD_BYTES = 64 * 1024 * 1024          # 上传 ZIP 本身不超过 64 MiB
MAX_UNCOMPRESSED_TOTAL = 256 * 1024 * 1024   # 解压总量不超过 256 MiB
MAX_ENTRY_SIZE = 32 * 1024 * 1024            # 单个条目不超过 32 MiB
MAX_ENTRY_COUNT = 2048                       # 条目数不超过 2048
READ_CHUNK = 1024 * 1024

# 包内附件文件名：附件 id 保证唯一，原文件名做防御性清洗
_SAFE_NAME_RE = re.compile(r"[^\w一-鿿.\-]+")


class EvidenceError(Exception):
    """封存包生成 / 校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 快照读取（单一读事务内固定元数据） ----------

def _read_snapshot(conn: Connection, sample_id: int) -> dict[str, Any]:
    """在当前事务内读取封存所需的全部元数据（不含审计派生视图以外的写操作）。"""
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if row is None:
        raise EvidenceError("样本不存在", status_code=404)
    sample = {
        "id": row["id"],
        "code": row["code"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
    }

    events = [
        {
            "id": r["id"],
            "seq": r["seq"],
            "custodian": r["custodian"],
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "note": r["note"],
        }
        for r in conn.execute(
            "SELECT id, seq, custodian, start_time, end_time, note "
            "FROM events WHERE sample_id = ? ORDER BY id",
            (sample_id,),
        ).fetchall()
    ]

    signoff_rows = conn.execute(
        "SELECT * FROM signoffs WHERE sample_id = ? ORDER BY id", (sample_id,)
    ).fetchall()
    signoffs = [
        {
            "id": r["id"],
            "signer": r["signer"],
            "signed_at": r["signed_at"],
            "remark": r["remark"],
            "status": r["status"],
            "revoke_reason": r["revoke_reason"],
            "revoked_at": r["revoked_at"],
            "created_at": r["created_at"],
            "digest": r["digest"],
        }
        for r in signoff_rows
    ]

    handovers = build_handover_view(conn, sample_id)

    attachment_rows = conn.execute(
        "SELECT a.id, a.event_id, a.blob_digest, a.filename, a.size, a.media_type, "
        "       a.uploaded_by, a.uploaded_at, a.status, a.corruption_reason, "
        "       a.last_verified_at "
        "FROM attachments a JOIN events e ON e.id = a.event_id "
        "WHERE e.sample_id = ? ORDER BY a.id",
        (sample_id,),
    ).fetchall()
    attachments = [dict(r) for r in attachment_rows]

    audit = build_audit(events)
    return {
        "sample": sample,
        "events": events,
        "signoffs": signoffs,
        "handovers": handovers,
        "attachments": attachments,
        "audit": audit,
    }


def _snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """快照指纹：链路与附件记录的任一变化（含新增 / 删除）都会改变。

    只纳入数据库逻辑记录（样本 / 事件 / 签署 / 交接 / 附件记录的全部字段），
    不纳入审计派生视图与生成时间。
    """
    payload = {
        "sample": snapshot["sample"],
        "events": snapshot["events"],
        "signoffs": snapshot["signoffs"],
        "handovers": snapshot["handovers"],
        "attachments": [
            {
                "id": a["id"],
                "event_id": a["event_id"],
                "blob_digest": a["blob_digest"],
                "filename": a["filename"],
                "size": a["size"],
                "media_type": a["media_type"],
                "uploaded_by": a["uploaded_by"],
                "uploaded_at": a["uploaded_at"],
                "status": a["status"],
                "corruption_reason": a["corruption_reason"],
            }
            for a in snapshot["attachments"]
        ],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------- ZIP 导出 ----------

def _safe_attachment_name(attachment_id: int, filename: str) -> str:
    """生成包内安全文件名（附件 id 前缀保证唯一，其余字符白名单化）。"""
    cleaned = _SAFE_NAME_RE.sub("_", filename).strip("._") or "attachment"
    return f"att-{attachment_id}-{cleaned}"[:180]


def _canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def build_evidence_zip(conn: Connection, sample_id: int, *, now: Optional[str] = None) -> dict[str, Any]:
    """在单一读事务内固定元数据并生成证据封存 ZIP（内存中构建）。

    返回 ``{"filename", "content_type", "data": bytes, "manifest": dict}``。
    任何一致性 / 完整性问题都抛出 :class:`EvidenceError`，不产出包。
    """
    from .attachments import _blob_path  # 避免模块顶层暴露内部路径工具

    generated_at = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1) 单一读事务固定全部元数据
    conn.execute(f"PRAGMA busy_timeout = {READ_BUSY_TIMEOUT_MS}")
    conn.execute("BEGIN")
    try:
        snapshot = _read_snapshot(conn, sample_id)
        fingerprint_before = _snapshot_fingerprint(snapshot)

        included: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        for a in snapshot["attachments"]:
            if a["status"] != "ok":
                excluded.append(
                    {
                        "attachment_id": a["id"],
                        "event_id": a["event_id"],
                        "filename": a["filename"],
                        "reason": a["corruption_reason"] or "corrupt",
                        "reason_text": REASON_TEXT.get(a["corruption_reason"], "附件已标记为损坏"),
                    }
                )
                continue
            # 2) 写包前逐项复核附件摘要（实体缺失 / 不一致即中止）
            ok, reason = verify_blob(a["blob_digest"], a["size"])
            if not ok:
                raise EvidenceError(
                    f"附件「{a['filename']}」（附件记录 #{a['id']}）封存前复核失败："
                    f"{REASON_TEXT.get(reason, reason)}；请先在附件管理中处理或复核后再导出",
                    status_code=409,
                )
            included.append(a)

        # 3) 同事务再次读取并比对快照指纹：期间链路或附件记录变化则中止
        snapshot_after = _read_snapshot(conn, sample_id)
        fingerprint_after = _snapshot_fingerprint(snapshot_after)
        if fingerprint_after != fingerprint_before:
            raise EvidenceError(
                "封存元数据固定期间，样本交接链路或附件记录发生了变化（新增 / 编辑 / 删除），"
                "为避免生成混合快照已中止导出，请刷新页面后重试",
                status_code=409,
            )

        # 事件逻辑关系索引（清单中记录每个附件所属事件与审计排序）
        event_index = {e["id"]: e for e in snapshot_after["audit"]["events"]}
        sample = snapshot_after["sample"]
        audit = snapshot_after["audit"]

        entries: list[dict[str, Any]] = []
        attachment_records: list[dict[str, Any]] = []
        for a in included:
            path_in_pack = f"{EVIDENCE_DIR}/{_safe_attachment_name(a['id'], a['filename'])}"
            audited = event_index.get(a["event_id"])
            attachment_records.append(
                {
                    "attachment_id": a["id"],
                    "event_id": a["event_id"],
                    "event_seq": audited["seq"] if audited else None,
                    "event_custodian": audited["custodian"] if audited else None,
                    "filename": a["filename"],
                    "path": path_in_pack,
                    "size": a["size"],
                    "sha256": a["blob_digest"],
                    "media_type": a["media_type"],
                    "uploaded_by": a["uploaded_by"],
                    "uploaded_at": a["uploaded_at"],
                    "last_verified_at": a["last_verified_at"],
                    "note": (
                        "该附件所属事件未参与审计排序（时间不可解析或起止倒置）"
                        if audited is None
                        else None
                    ),
                }
            )
            entries.append({"path": path_in_pack, "digest": a["blob_digest"], "attachment": a})

        # 审计报告（含统计、发现、交接确认、签署与附件元数据章节）
        report_md = build_markdown(
            sample,
            audit,
            snapshot_after["signoffs"],
            snapshot_after["handovers"],
            _attachment_meta_for_report(snapshot_after["attachments"]),
            event_index,
        )
        report_bytes = report_md.encode("utf-8")
        report_sha256 = hashlib.sha256(report_bytes).hexdigest()

        manifest: dict[str, Any] = {
            "package_format": PACKAGE_FORMAT,
            "package_version": PACKAGE_VERSION,
            "generated_at": generated_at,
            "sample": sample,
            "events": snapshot_after["events"],
            "audit": {
                "status": audit["status"],
                "conclusion": audit["conclusion"],
                "summary": audit["summary"],
                "findings": audit["findings"],
            },
            "signoffs": snapshot_after["signoffs"],
            "handovers_summary": snapshot_after["handovers"]["summary"],
            "report": {
                "path": REPORT_NAME,
                "media_type": "text/markdown; charset=utf-8",
                "size": len(report_bytes),
                "sha256": report_sha256,
            },
            "attachments": attachment_records,
            "excluded_corrupt_attachments": excluded,
            "relations": {
                "sample_id": sample["id"],
                "sample_code": sample["code"],
                "events_ordered_by": ["start_time ASC", "id ASC"],
                "attachment_belongs_to_event": "attachments[].event_id -> events[].id",
                "evidence_dir": EVIDENCE_DIR,
            },
            "snapshot_fingerprint": fingerprint_after,
        }
        # 清单自身的封印摘要（canonical JSON，不含 manifest_digest 字段）
        manifest["manifest_digest"] = hashlib.sha256(
            _canonical_manifest_bytes(manifest)
        ).hexdigest()
        manifest_bytes = _canonical_manifest_bytes(manifest)

        # 4) 内存构建 ZIP；复制附件时再次流式累加摘要，实体被替换 / 截断即中止
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for item in entries:
                a = item["attachment"]
                src = _blob_path(a["blob_digest"])
                hasher = hashlib.sha256()
                size = 0
                try:
                    with zf.open(item["path"], "w", force_zip64=False) as out, open(src, "rb") as fh:
                        while True:
                            chunk = fh.read(READ_CHUNK)
                            if not chunk:
                                break
                            hasher.update(chunk)
                            size += len(chunk)
                            out.write(chunk)
                except FileNotFoundError:
                    raise EvidenceError(
                        f"写包过程中附件实体缺失：{a['filename']}（附件记录 #{a['id']}），导出已中止",
                        status_code=409,
                    )
                except OSError as exc:
                    raise EvidenceError(
                        f"读取附件实体失败：{a['filename']}（{exc}），导出已中止",
                        status_code=409,
                    )
                if size != a["size"] or hasher.hexdigest() != a["blob_digest"]:
                    raise EvidenceError(
                        f"写包过程中附件「{a['filename']}」（附件记录 #{a['id']}）"
                        "内容发生变化（大小或 SHA-256 不一致），为避免封存损坏内容导出已中止",
                        status_code=409,
                    )

            zf.writestr(REPORT_NAME, report_bytes, compress_type=zipfile.ZIP_DEFLATED)
            zf.writestr(MANIFEST_NAME, manifest_bytes, compress_type=zipfile.ZIP_DEFLATED)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    stem = re.sub(r"[^\w一-鿿-]+", "_", sample["code"]).strip("_") or "sample"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        "filename": f"evidence_pack_{stem}_{ts}.zip",
        "content_type": "application/zip",
        "data": buffer.getvalue(),
        "manifest": manifest,
    }


def _attachment_meta_for_report(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """转换为 build_markdown 附件章节所需的字段形态。"""
    from .attachments import human_size

    return [
        {
            "id": a["id"],
            "event_id": a["event_id"],
            "filename": a["filename"],
            "size": a["size"],
            "size_text": human_size(a["size"]),
            "media_type": a["media_type"],
            "uploaded_by": a["uploaded_by"],
            "uploaded_at": a["uploaded_at"],
            "digest": a["blob_digest"],
            "status": a["status"],
            "corruption_reason": a["corruption_reason"],
            "corruption_reason_text": REASON_TEXT.get(a["corruption_reason"])
            if a["corruption_reason"]
            else None,
            "last_verified_at": a["last_verified_at"],
        }
        for a in rows
    ]


# ---------- 不落库的封存包校验 ----------

def _is_safe_entry_name(name: str) -> bool:
    """拒绝绝对路径、盘符、路径穿越（..）与反斜杠条目。"""
    if not name or name in (".", ".."):
        return False
    if "\x00" in name or "\\" in name:
        return False
    if name.startswith("/") or name.startswith("~"):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return False
    return True


def _read_limited(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """读取单个条目，限制解压大小（含基础 zip 炸弹比率防护）。"""
    if info.file_size > MAX_ENTRY_SIZE:
        raise EvidenceError(
            f"包内文件「{info.filename}」解压后大小 "
            f"{info.file_size} 字节，超过单文件上限 {MAX_ENTRY_SIZE} 字节",
            status_code=422,
        )
    # 压缩率异常（>200 倍）的小条目视为 zip 炸弹
    if info.compress_size > 0 and info.file_size > info.compress_size * 200:
        raise EvidenceError(
            f"包内文件「{info.filename}」压缩率异常（疑似 zip 炸弹），拒绝解压",
            status_code=422,
        )
    total = 0
    chunks: list[bytes] = []
    with zf.open(info, "r") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ENTRY_SIZE:
                raise EvidenceError(
                    f"包内文件「{info.filename}」解压大小超过单文件上限 "
                    f"{MAX_ENTRY_SIZE} 字节",
                    status_code=422,
                )
            chunks.append(chunk)
    return b"".join(chunks)


def verify_evidence_bytes(data: bytes) -> dict[str, Any]:
    """校验上传的封存包 ZIP；不访问数据库、不写任何记录。

    返回结构：``valid``、包元信息、逐项核对结果与中文差异列表（按
    清单异常 / 缺失 / 多余 / 摘要异常 / 结构异常分类）。
    """
    result: dict[str, Any] = {
        "valid": False,
        "package_format": None,
        "package_version": None,
        "generated_at": None,
        "sample": None,
        "manifest_digest_ok": None,
        "counts": {},
        "diffs": [],
    }
    diffs: list[dict[str, str]] = []

    def add(kind: str, message: str, path: Optional[str] = None) -> None:
        diffs.append({"kind": kind, "path": path or "", "message": message})

    if len(data) > MAX_UPLOAD_BYTES:
        raise EvidenceError(
            f"封存包超过上传大小上限（{MAX_UPLOAD_BYTES // (1024 * 1024)} MiB）",
            status_code=413,
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        add("structure", "文件不是合法的 ZIP 封存包（无法打开）")
        result["counts"] = _empty_counts()
        return _finalize(result, diffs)

    entries: dict[str, bytes] = {}
    try:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ENTRY_COUNT:
            add("structure", f"包内文件数量 {len(infos)} 超过上限 {MAX_ENTRY_COUNT}")
            result["counts"] = _empty_counts()
            return _finalize(result, diffs)

        total_uncompressed = 0
        seen: set[str] = set()
        for info in infos:
            name = info.filename
            if not _is_safe_entry_name(name):
                add("structure", f"存在不安全的条目路径（绝对路径或路径穿越）：{name}", name)
                continue
            # ZipInfo 去重：同名条目重复出现
            norm = name.rstrip("/")
            if norm in seen:
                add("structure", f"包内存在重复条目：{name}", name)
                continue
            seen.add(norm)
            try:
                content = _read_limited(zf, info)
            except EvidenceError as exc:
                add("structure", exc.message, name)
                continue
            total_uncompressed += len(content)
            if total_uncompressed > MAX_UNCOMPRESSED_TOTAL:
                add(
                    "structure",
                    f"解压总量超过上限 {MAX_UNCOMPRESSED_TOTAL // (1024 * 1024)} MiB"
                    "（疑似 zip 炸弹）",
                )
                result["counts"] = _empty_counts()
                return _finalize(result, diffs)
            entries[norm] = content
    finally:
        zf.close()

    # 1) 清单必须存在且可解析
    if MANIFEST_NAME not in entries:
        add("manifest", f"封存包缺少清单文件 {MANIFEST_NAME}", MANIFEST_NAME)
        result["counts"] = _counts(diffs)
        return _finalize(result, diffs)

    try:
        manifest = json.loads(entries[MANIFEST_NAME].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        add("manifest", f"清单 {MANIFEST_NAME} 不是合法的 UTF-8 JSON：{exc}", MANIFEST_NAME)
        result["counts"] = _counts(diffs)
        return _finalize(result, diffs)
    if not isinstance(manifest, dict):
        add("manifest", "清单根节点必须是 JSON 对象", MANIFEST_NAME)
        result["counts"] = _counts(diffs)
        return _finalize(result, diffs)

    result["package_format"] = manifest.get("package_format")
    result["package_version"] = manifest.get("package_version")
    result["generated_at"] = manifest.get("generated_at")
    result["sample"] = manifest.get("sample") if isinstance(manifest.get("sample"), dict) else None

    if manifest.get("package_format") != PACKAGE_FORMAT:
        add(
            "manifest",
            f"清单 package_format 为 {manifest.get('package_format')!r}，"
            f"应为 {PACKAGE_FORMAT!r}",
        )

    # 2) 清单自身封印摘要
    declared_manifest_digest = manifest.get("manifest_digest")
    if isinstance(declared_manifest_digest, str) and declared_manifest_digest:
        without = {k: v for k, v in manifest.items() if k != "manifest_digest"}
        actual = hashlib.sha256(_canonical_manifest_bytes(without)).hexdigest()
        result["manifest_digest_ok"] = actual == declared_manifest_digest
        if actual != declared_manifest_digest:
            add(
                "digest",
                "清单自身封印摘要（manifest_digest）不一致：清单内容在封存后被改动或损坏",
                MANIFEST_NAME,
            )
    else:
        result["manifest_digest_ok"] = False
        add("manifest", "清单缺少 manifest_digest 封印摘要", MANIFEST_NAME)

    declared = manifest.get("attachments")
    if not isinstance(declared, list):
        add("manifest", "清单缺少 attachments 数组或类型错误")
        declared = []

    declared_paths: set[str] = set()
    checked_files = 0
    for i, item in enumerate(declared):
        label = f"attachments[{i}]"
        if not isinstance(item, dict):
            add("manifest", f"清单第 {i + 1} 个附件条目不是 JSON 对象")
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path:
            add("manifest", f"清单第 {i + 1} 个附件条目缺少 path", label)
            continue
        if not _is_safe_entry_name(path):
            add("structure", f"清单声明了不安全的附件路径：{path}", path)
            continue
        if path in declared_paths:
            add("manifest", f"清单中附件路径重复声明：{path}", path)
        declared_paths.add(path)

        expected_digest = item.get("sha256")
        expected_size = item.get("size")
        fname = item.get("filename") or path

        content = entries.get(path)
        if content is None:
            add("missing", f"清单声明的附件缺失：{fname}", path)
            continue
        checked_files += 1
        problems: list[str] = []
        if not isinstance(expected_size, int) or expected_size < 0:
            problems.append("清单缺少有效的 size")
        elif len(content) != expected_size:
            problems.append(f"大小不符：清单 {expected_size} 字节，实际 {len(content)} 字节")
        actual_digest = hashlib.sha256(content).hexdigest()
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            problems.append("清单缺少有效的 SHA-256（应为 64 位十六进制）")
        elif actual_digest != expected_digest:
            problems.append(f"SHA-256 不符：清单 {expected_digest[:12]}…，实际 {actual_digest[:12]}…")
        if problems:
            add("digest", f"附件「{fname}」" + "；".join(problems), path)

        # 逻辑关系字段完整性
        if not isinstance(item.get("event_id"), int):
            add("manifest", f"附件「{fname}」缺少有效的 event_id（样本-事件-附件逻辑关系断裂）", path)

    # 3) 审计报告核对
    report_info = manifest.get("report")
    if isinstance(report_info, dict) and isinstance(report_info.get("path"), str):
        rpath = report_info["path"]
        declared_paths.add(rpath)
        rcontent = entries.get(rpath)
        if rcontent is None:
            add("missing", "清单声明的审计报告缺失", rpath)
        else:
            checked_files += 1
            rproblems = []
            if isinstance(report_info.get("size"), int) and len(rcontent) != report_info["size"]:
                rproblems.append(
                    f"大小不符：清单 {report_info['size']} 字节，实际 {len(rcontent)} 字节"
                )
            rd = report_info.get("sha256")
            actual_rd = hashlib.sha256(rcontent).hexdigest()
            if isinstance(rd, str) and rd != actual_rd:
                rproblems.append("SHA-256 与清单不符")
            if rproblems:
                add("digest", "审计报告" + "；".join(rproblems), rpath)
    else:
        add("manifest", "清单缺少 report 声明（path / size / sha256）")

    # 清单文件本身也算包内声明文件
    declared_paths.add(MANIFEST_NAME)

    # 4) 多余文件：包内存在但清单未声明
    extra = sorted(p for p in entries if p not in declared_paths)
    for p in extra:
        add("extra", f"包内存在清单未声明的多余文件：{p}", p)

    # 5) 清单声明的损坏排除项只做形态核对（不参与存在性检查）
    excluded = manifest.get("excluded_corrupt_attachments")
    if excluded is not None and not isinstance(excluded, list):
        add("manifest", "清单 excluded_corrupt_attachments 字段类型错误（应为数组）")

    counts = _counts(diffs)
    counts.update(
        {
            "declared_attachments": len(declared),
            "checked_files": checked_files,
            "excluded_corrupt": len(excluded) if isinstance(excluded, list) else 0,
            "total_entries": len(entries),
        }
    )
    result["counts"] = counts
    return _finalize(result, diffs)


def _empty_counts() -> dict[str, int]:
    return {
        "declared_attachments": 0,
        "checked_files": 0,
        "missing": 0,
        "extra": 0,
        "digest_errors": 0,
        "manifest_errors": 0,
        "structure_errors": 0,
        "excluded_corrupt": 0,
        "total_entries": 0,
    }


def _counts(diffs: list[dict[str, str]]) -> dict[str, int]:
    c = _empty_counts()
    for d in diffs:
        if d["kind"] == "missing":
            c["missing"] += 1
        elif d["kind"] == "extra":
            c["extra"] += 1
        elif d["kind"] == "digest":
            c["digest_errors"] += 1
        elif d["kind"] == "manifest":
            c["manifest_errors"] += 1
        elif d["kind"] == "structure":
            c["structure_errors"] += 1
    return c


def _finalize(result: dict[str, Any], diffs: list[dict[str, str]]) -> dict[str, Any]:
    result["diffs"] = diffs
    result["valid"] = not diffs
    result["summary"] = (
        "校验通过：清单、审计报告与全部附件齐全，大小与 SHA-256 摘要均一致，无多余文件。"
        if result["valid"]
        else f"校验未通过：共发现 {len(diffs)} 处差异（详见差异列表）。"
    )
    return result
