"""Tests for AuditTrail hash chaining, integrity verification, and tamper detection."""

import json
from pathlib import Path
from sniffer.audit.trail import AuditTrail


def test_audit_trail_append_and_verify(tmp_path: Path):
    trail_file = tmp_path / "trail.jsonl"
    trail = AuditTrail(trail_file)

    trail.append("meta", {"action": "start", "operator": "auditor_1"})
    trail.append("event", {"rule": "cleartext_protocols", "severity": "HIGH", "src": "1.2.3.4"})
    trail.append("event", {"rule": "dns_anomaly", "severity": "MEDIUM", "src": "1.2.3.4"})
    trail.append("meta", {"action": "end"})
    trail.close()

    # Verify intact trail
    ok, errors = AuditTrail.verify(trail_file)
    assert ok is True
    assert len(errors) == 0


def test_audit_trail_tamper_detection(tmp_path: Path):
    trail_file = tmp_path / "trail_tampered.jsonl"
    trail = AuditTrail(trail_file)

    trail.append("meta", {"action": "start"})
    trail.append("event", {"rule": "cleartext_protocols", "severity": "HIGH", "src": "10.0.0.1"})
    trail.append("event", {"rule": "deprecated_tls", "severity": "HIGH", "src": "10.0.0.2"})
    trail.close()

    # Tamper with the second line (change src IP)
    lines = trail_file.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["src"] = "192.168.99.99"  # Tampered!
    lines[1] = json.dumps(entry)
    trail_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verification must catch this
    ok, errors = AuditTrail.verify(trail_file)
    assert ok is False
    assert len(errors) > 0
    assert any("mismatch" in e for e in errors)


def test_audit_trail_deletion_detection(tmp_path: Path):
    trail_file = tmp_path / "trail_deleted_entry.jsonl"
    trail = AuditTrail(trail_file)

    trail.append("event", {"n": 1})
    trail.append("event", {"n": 2})
    trail.append("event", {"n": 3})
    trail.close()

    # Delete line 2
    lines = trail_file.read_text(encoding="utf-8").splitlines()
    del lines[1]
    trail_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Sequence or prev_hash mismatch must trigger
    ok, errors = AuditTrail.verify(trail_file)
    assert ok is False
    assert len(errors) > 0
