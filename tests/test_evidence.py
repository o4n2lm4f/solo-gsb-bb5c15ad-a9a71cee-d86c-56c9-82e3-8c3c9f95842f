"""证据封存包测试。

覆盖：
* 导出 ZIP 结构（清单 / 审计报告 / evidence 附件），清单记录样本-事件-
  附件逻辑关系、包内路径、大小与 SHA-256；
* 元数据在单一读事务内固定，写包前逐项复核附件摘要（损坏即中止 409），
  两次快照指纹不一致即中止（防混合快照）；已标记损坏的附件不封入包而在
  清单列明；
* 不落库校验：往返校验通过；缺失 / 多余 / 摘要篡改 / 报告篡改 / 清单封印
  篡改 / 路径穿越 / zip 炸弹 / 条目数超限 / 非 ZIP 等差异逐项返回中文。
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile

_tmp = tempfile.mkdtemp(prefix="audit-evidence-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_evidence.db")
os.environ["ATTACHMENT_DIR"] = os.path.join(_tmp, "attachments")

import hashlib  # noqa: E402
import itertools  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import evidence  # noqa: E402
from app.attachments import attachment_dir  # noqa: E402
from app.db import get_connection, init_db  # noqa: E402
from app.main import app  # noqa: E402


def _blob_file(digest: str):
    return attachment_dir() / digest[:2] / digest[2:4] / digest

PDF_BYTES = b"%PDF-1.4\nevidence-pack-fixture\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x7e" * 48


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_seq = itertools.count(1)


@pytest.fixture()
def sample(client):
    code = f"UT-EVID-{next(_seq):03d}"
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "封存包测试样本", "description": "证据封存"},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture()
def events(client, sample):
    ids = []
    for i, custodian in enumerate(("张三", "李四"), start=9):
        resp = client.post(
            f"/api/samples/{sample['id']}/events",
            json={
                "custodian": custodian,
                "start_time": f"2026-09-20 {i:02d}:00:00",
                "end_time": f"2026-09-20 {i + 1:02d}:00:00",
                "note": f"{custodian}保管段",
            },
        )
        assert resp.status_code == 201
        ids.append(resp.json()["id"])
    return ids


def _upload(client, event_id, content, filename, uploaded_by="封存员"):
    content_type = "image/png" if filename.lower().endswith(".png") else "application/pdf"
    return client.post(
        f"/api/events/{event_id}/attachments",
        files={"file": (filename, content, content_type)},
        data={"uploaded_by": uploaded_by},
    ).json()


def _export(client, sample_id):
    resp = client.get(f"/api/samples/{sample_id}/evidence-package")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "evidence_pack_" in resp.headers["content-disposition"]
    return resp.content, zipfile.ZipFile(io.BytesIO(resp.content))


# ---------- 导出 ----------

def test_export_package_structure_and_manifest(client, sample, events):
    a1 = _upload(client, events[0], PDF_BYTES, "交接单.pdf")
    a2 = _upload(client, events[1], PNG_BYTES, "照片.png", "李四")
    data, zf = _export(client, sample["id"])
    names = zf.namelist()
    assert "manifest.json" in names
    assert "audit_report.md" in names
    assert sum(1 for n in names if n.startswith("evidence/")) == 2

    manifest = __import__("json").loads(zf.read("manifest.json"))
    assert manifest["package_format"] == "evidence-pack"
    assert manifest["package_version"] == 1
    assert manifest["sample"]["id"] == sample["id"]
    assert manifest["snapshot_fingerprint"]
    assert len(manifest["manifest_digest"]) == 64
    assert len({a["path"] for a in manifest["attachments"]}) == 2

    # 逻辑关系 + 路径 / 大小 / SHA-256
    first = manifest["attachments"][0]
    assert first["attachment_id"] == a1["id"]
    assert first["event_id"] == events[0]
    assert first["event_custodian"] == "张三"
    assert first["event_seq"]
    assert first["filename"] == "交接单.pdf"
    assert first["path"] == f"evidence/att-{a1['id']}-交接单.pdf"
    assert first["size"] == len(PDF_BYTES)
    assert first["sha256"] == hashlib.sha256(PDF_BYTES).hexdigest()
    assert zf.read(first["path"]) == PDF_BYTES

    # 审计报告与清单声明一致
    report_bytes = zf.read("audit_report.md")
    assert manifest["report"]["sha256"] == hashlib.sha256(report_bytes).hexdigest()
    assert manifest["report"]["size"] == len(report_bytes)
    assert "样本交接链路审计报告" in report_bytes.decode("utf-8")
    assert "交接单.pdf" in report_bytes.decode("utf-8")

    # 清单封印摘要自洽
    without = {k: v for k, v in manifest.items() if k != "manifest_digest"}
    canonical = __import__("json").dumps(
        without, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8")
    assert manifest["manifest_digest"] == hashlib.sha256(canonical).hexdigest()


def test_export_without_attachments(client, sample, events):
    _data, zf = _export(client, sample["id"])
    manifest = __import__("json").loads(zf.read("manifest.json"))
    assert manifest["attachments"] == []
    assert manifest["excluded_corrupt_attachments"] == []


def test_export_404_for_missing_sample(client):
    resp = client.get("/api/samples/999999/evidence-package")
    assert resp.status_code == 404


def test_corrupt_attachment_excluded_and_listed_in_manifest(client, sample, events):
    a = _upload(client, events[0], PDF_BYTES, "损坏件.pdf")
    _blob_file(a["digest"]).unlink()
    # 列表轻量检查把缺失实体标为损坏
    client.get(f"/api/events/{events[0]}/attachments")

    _data, zf = _export(client, sample["id"])
    names = zf.namelist()
    assert not any(n.startswith("evidence/") for n in names)
    manifest = __import__("json").loads(zf.read("manifest.json"))
    excluded = manifest["excluded_corrupt_attachments"]
    assert len(excluded) == 1
    assert excluded[0]["attachment_id"] == a["id"]
    assert excluded[0]["reason"] == "missing"
    assert "缺失" in excluded[0]["reason_text"]


def test_export_aborts_when_blob_tampered_before_write(client, sample, events):
    """状态仍为 ok 的附件在写包前复核失败 -> 409 中止，不产出包。"""
    a = _upload(client, events[0], PDF_BYTES, "被篡改.pdf")
    path = _blob_file(a["digest"])
    path.write_bytes(PDF_BYTES + b"TAMPERED")
    resp = client.get(f"/api/samples/{sample['id']}/evidence-package")
    assert resp.status_code == 409
    assert "封存前复核失败" in resp.json()["detail"]


def test_export_aborts_on_snapshot_fingerprint_drift(client, sample, events, monkeypatch):
    """模拟两次读事务间链路 / 附件记录变化（WAL 下可能发生）-> 409 中止。"""
    _upload(client, events[0], PDF_BYTES, "a.pdf")
    original = evidence._read_snapshot
    calls = {"n": 0}

    def flapping(conn, sid):
        snap = original(conn, sid)
        calls["n"] += 1
        if calls["n"] == 2:
            snap["sample"]["name"] = snap["sample"]["name"] + "（并发改动）"
        return snap

    monkeypatch.setattr(evidence, "_read_snapshot", flapping)
    resp = client.get(f"/api/samples/{sample['id']}/evidence-package")
    assert resp.status_code == 409
    assert "发生了变化" in resp.json()["detail"]


def test_snapshot_fingerprint_changes_with_record_changes(client, sample, events):
    conn = get_connection()
    try:
        s1 = evidence._read_snapshot(conn, sample["id"])
        f1 = evidence._snapshot_fingerprint(s1)
        # 附件记录变化（标记损坏）应改变指纹
        conn.execute(
            "UPDATE attachments SET status='corrupt', corruption_reason='missing' "
            "WHERE id = (SELECT a.id FROM attachments a JOIN events e ON e.id=a.event_id "
            "WHERE e.sample_id=? LIMIT 1)",
            (sample["id"],),
        )
        conn.commit()
        s2 = evidence._read_snapshot(conn, sample["id"])
        assert evidence._snapshot_fingerprint(s2) != f1
    finally:
        conn.close()


def test_export_during_write_hash_detects_swap(client, sample, events, monkeypatch):
    """写包过程中实体被替换 -> 流式复算不一致，409 中止。"""
    _upload(client, events[0], PDF_BYTES, "swap.pdf")
    real_verify = evidence.verify_blob

    def verify_then_swap(digest, size):
        # 先正常复核（通过），随即令实体内容被替换，模拟写包窗口内被改动
        ok, reason = real_verify(digest, size)
        _blob_file(digest).write_bytes(PDF_BYTES + b"SWAPPED-DURING-COPY")
        return ok, reason

    monkeypatch.setattr(evidence, "verify_blob", verify_then_swap)
    try:
        resp = client.get(f"/api/samples/{sample['id']}/evidence-package")
        assert resp.status_code == 409
        assert "写包过程中" in resp.json()["detail"]
    finally:
        # PDF_BYTES 被多个用例共享，还原实体避免污染后续上传 / 导出
        monkeypatch.setattr(evidence, "verify_blob", real_verify)
        digest = hashlib.sha256(PDF_BYTES).hexdigest()
        _blob_file(digest).write_bytes(PDF_BYTES)


# ---------- 不落库校验 ----------

@pytest.fixture()
def packaged(client, sample, events):
    _upload(client, events[0], PDF_BYTES, "交接单.pdf")
    _upload(client, events[1], PNG_BYTES, "照片.png", "李四")
    data, zf = _export(client, sample["id"])
    return data, zf, sample


def _repack(zf, mutate=None, extra=()):
    """解出再重打包，可替换条目内容 / 追加多余条目。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for info in zf.infolist():
            content = mutate(info.filename, zf.read(info.filename)) if mutate else zf.read(info.filename)
            out.writestr(info.filename, content)
        for name, content in extra:
            out.writestr(name, content)
    return buf.getvalue()


def test_verify_roundtrip_ok(client, packaged):
    data, _zf, sample = packaged
    resp = client.post("/api/evidence-packages/verify", content=data,
                       headers={"Content-Type": "application/zip"})
    assert resp.status_code == 200
    r = resp.json()
    assert r["valid"] is True
    assert r["sample"]["id"] == sample["id"]
    assert r["manifest_digest_ok"] is True
    assert r["diffs"] == []
    assert r["counts"]["declared_attachments"] == 2
    assert "校验通过" in r["summary"]


def test_verify_detects_missing_file(client, packaged):
    data, zf, _ = packaged
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for info in zf.infolist():
            if info.filename.startswith("evidence/"):
                continue  # 删掉附件
            out.writestr(info.filename, zf.read(info.filename))
    r = client.post("/api/evidence-packages/verify", content=buf.getvalue(),
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    missing = [d for d in r["diffs"] if d["kind"] == "missing"]
    assert len(missing) == 2
    assert "缺失" in missing[0]["message"]
    assert r["counts"]["missing"] == 2


def test_verify_detects_extra_file(client, packaged):
    data, zf, _ = packaged
    repacked = _repack(zf, extra=[("notes/额外文件.txt", "清单外的内容".encode())])
    r = client.post("/api/evidence-packages/verify", content=repacked,
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    extras = [d for d in r["diffs"] if d["kind"] == "extra"]
    assert len(extras) == 1
    assert "多余文件" in extras[0]["message"]
    assert extras[0]["path"] == "notes/额外文件.txt"


def test_verify_detects_digest_mismatch(client, packaged):
    data, zf, _ = packaged

    def mutate(name, content):
        return content + b"X" if name.startswith("evidence/") else content

    repacked = _repack(zf, mutate=mutate)
    r = client.post("/api/evidence-packages/verify", content=repacked,
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    digest_diffs = [d for d in r["diffs"] if d["kind"] == "digest"]
    assert digest_diffs and "SHA-256" in digest_diffs[0]["message"]


def test_verify_detects_report_tampering(client, packaged):
    data, zf, _ = packaged

    def mutate(name, content):
        return content.replace("审计".encode(), "检查".encode()) if name == "audit_report.md" else content

    repacked = _repack(zf, mutate=mutate)
    r = client.post("/api/evidence-packages/verify", content=repacked,
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    assert any(d["path"] == "audit_report.md" and d["kind"] == "digest" for d in r["diffs"])


def test_verify_detects_manifest_seal_tampering(client, packaged):
    """附件被改且清单中的声明被同步伪造 -> manifest_digest 封印仍应揭穿。"""
    data, zf, _ = packaged
    import json as _json

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for info in zf.infolist():
            content = zf.read(info.filename)
            if info.filename == "evidence/att-1-交接单.pdf":
                content = content + b"FORGED"
            if info.filename == "manifest.json":
                man = _json.loads(content)
                man["sample"]["name"] = "伪造样本名"  # 改清单但保留旧封印摘要
                content = _json.dumps(man, ensure_ascii=False).encode("utf-8")
            out.writestr(info.filename, content)
    r = client.post("/api/evidence-packages/verify", content=buf.getvalue(),
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    assert r["manifest_digest_ok"] is False
    assert any("封印摘要" in d["message"] for d in r["diffs"])


def test_verify_rejects_path_traversal(client, packaged):
    data, zf, _ = packaged
    repacked = _repack(zf, extra=[("../escape.txt", b"x"), ("/abs/path.bin", b"y")])
    r = client.post("/api/evidence-packages/verify", content=repacked,
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    structs = [d for d in r["diffs"] if d["kind"] == "structure"]
    assert any("路径穿越" in d["message"] or "不安全" in d["message"] for d in structs)
    # 穿越条目不得被当作「多余文件」正常接纳
    assert not any(d["path"] == "../escape.txt" and d["kind"] == "extra" for d in r["diffs"])


def test_verify_rejects_non_zip(client):
    resp = client.post("/api/evidence-packages/verify", content=b"not a zip at all",
                       headers={"Content-Type": "application/zip"})
    r = resp.json()
    assert r["valid"] is False
    assert any("不是合法的 ZIP" in d["message"] for d in r["diffs"])


def test_verify_missing_manifest(client, packaged):
    data, zf, _ = packaged
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for info in zf.infolist():
            if info.filename == "manifest.json":
                continue
            out.writestr(info.filename, zf.read(info.filename))
    r = client.post("/api/evidence-packages/verify", content=buf.getvalue(),
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    assert any("缺少清单" in d["message"] for d in r["diffs"])


def test_verify_rejects_oversized_total(client, monkeypatch):
    # 构造解压后超过总量上限的包：混入随机段把压缩率压到 200 倍以下，
    # 确保命中的是「解压总量」而非「单文件压缩率」防护
    payload = b"\x00" * (15 * 1024 * 1024 // 10) + os.urandom(220 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("manifest.json", b"{}")
        out.writestr("big.bin", payload)
    monkeypatch.setattr(evidence, "MAX_UNCOMPRESSED_TOTAL", 1024 * 1024)
    r = client.post("/api/evidence-packages/verify", content=buf.getvalue(),
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    assert any("解压总量" in d["message"] for d in r["diffs"])


def test_verify_rejects_too_many_entries(client, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for i in range(10):
            out.writestr(f"f{i}.bin", b"x")
    monkeypatch.setattr(evidence, "MAX_ENTRY_COUNT", 5)
    r = client.post("/api/evidence-packages/verify", content=buf.getvalue(),
                    headers={"Content-Type": "application/zip"}).json()
    assert r["valid"] is False
    assert any("文件数量" in d["message"] for d in r["diffs"])


def test_verify_rejects_upload_size(client, monkeypatch):
    cap = 1024 * 1024
    monkeypatch.setattr(evidence, "MAX_UPLOAD_BYTES", cap)
    resp = client.post("/api/evidence-packages/verify", content=b"x" * (cap + 1),
                       headers={"Content-Type": "application/zip"})
    assert resp.status_code == 413
    assert "超过上传大小上限" in resp.json()["detail"]


def test_verify_does_not_write_database(client, packaged):
    """校验入口不落库：校验前后附件 / 样本记录数不变。"""
    conn = get_connection()
    try:
        before = (
            conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM attachments").fetchone()[0],
        )
    finally:
        conn.close()
    client.post("/api/evidence-packages/verify", content=packaged[0],
                headers={"Content-Type": "application/zip"})
    conn = get_connection()
    try:
        after = (
            conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM attachments").fetchone()[0],
        )
    finally:
        conn.close()
    assert before == after
