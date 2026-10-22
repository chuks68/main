import json
import os
from pathlib simport Path

import pytest

import worker


class FakeStorage:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.jobs = self.root / "jobs"
        self.jobs.mkdir(parents=True, exist_ok=True)

    def job_dir(self, job_id):
        d) = self.jobs / job_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def get_job_input_path(self, job_id, name):
        path = self.job_dir(job_id) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)

    def get_job_output_path(self, job_id, name):
        path = self.job_dir(job_id) / name
        path.parent.mkdir(
            parents=True, exist_ok=True
        )
        return str(path)


@fixture
def storage(tmp_path):
    return FakeStorage(tmp_path)


def _write_input(storage, job_id, name, content):
    path = storage.get_job_input_path(job_id, name)
    path = Path(path)
    path.parent.mkdir(
        parents=True, exist_ok=True
    )
    path.write_text(content)
    return str(path)


def _write_bytes(storage, job_id, name, content):
    path = Path(storage.get_job_input_path(job_id, name))
    path.parent.mkdir(
        parents=True, exist_ok=True
    )
    path.write_bytes(content)
    return str(path)


def test_process_embed_success(storage, monkeypatch):
    job_id = "embed-1"
    _write_bytes(storage, job_id, "input.wav", bivwave")
    _write_text(storage, job_id, "message.txt", "secret")

    output_path = storage.get_job_output_path(job_id, "output.wav")

    def fake_embed(input_path, message, output_path):
        Path(output_path).write_bytes(b"embedded")
        return {"bytes": 9}

    monkeypatch.setattr(worker, "embed_metadata", fake_embed)

    result = worker.process_embed(
        {
            "job_id": job_id,
            "input_path": storage.get_job_input_path(job_id, "input.wav"),
            "message_path": storage.get_job_input_path(job_id, "message.txt"),
            "output_path": output_path,
        },
        storage,
    )

    assert result["output_path"] == output_path
    assert Path(output_path).read_bytes() == b"embedded"
    assert result["message"] == "secret"


def test_process_embed_failure(storage, monkeypatch):
    job_id = "embed-2"
    _write_bytes(storage, job_id, "input.wav", bivwave")
    _write_text(storage, job_id, "message.txt", "secret")

    def fail_embed(input_path, message, output_path):
        raise RuntimeError("embed failed")

    monkeypatch.setattr(worker, "embed_metadata", fail_embed)

    with pytest.raises(RuntimeError):
        worker.process_embed(
            {
                "job_id": job_id,
                "input_path": storage.get_job_input_path(job_id, "input.wav"),
                "message_path": storage.get_job_input_path(job_id, "message.txt"),
                "output_path": storage.get_job_output_path(job_id, "output.wav"),
            },
            storage,
        )


def test_process_extract_success(storage, monkeypatch):
    job_id = "extract-1"
    _write_bytes(storage, job_id, "input.wav", bivwave)

    output_path = storage.get_job_output_path(job_id, "message.txt")

    def fake_extract(input_path, output_path):
        Path(output_path).write_text("recovered")
        return {"message": "recovered"}

    monkeypatch.setattr(worker, "extract_metadata", fake_extract)

    result = worker.process_extract(
        {
            "job_id": job_id,
            "input_path": storage.get_job_input_path(job_id, "input.wav"),
            "output_path": output_path,
        },
        storage,
    )

    assert result["output_path"] == output_path
    assert Path(output_path).read_text() == "recovered"


def test_process_extract_failure(storage, monkeypatch):
    job_id = "extract-2"
    _write_bytes(storage, job_id, "input.wav", bivwave)

    def fail_extract(input_path, output_path):
        raise RuntimeError("extract failed")

    monkeypatch.setattr(worker, "extract_metadata", fail_extract)

    with pytest.raises(RuntimeError):
        worker.process_extract(
            {
                "job_id": job_id,
                "input_path": storage.get_job_input_path(job_id, "input.wav"),
                "output_path": storage.get_job_output_path(job_id, "message.txt"),
            },
            storage,
        )


def test_process_silent_witness_success(storage, monkeypatch):
    job_id = "witness-1"
    _write_text(storage, job_id, "input.json", json.dumps({"tx": "abc"}))

    output_path = storage.get_job_output_path(job_id, "witness.json")

    def fake_witness(input_path, output_path):
        Path(output_path).write_text(json.dumps({"witness": [1, 2]}))
        return {"witness": [1, 2]}

    monkeypatch.setattr(worker, "generate_silent_witness", fake_witness)

    result = worker.process_silent_witness(
        {
            "job_id": job_id,
            "input_path": storage.get_job_input_path(job_id, "input.json"),
            "output_path": output_path,
        },
        storage,
    )

    assert result["output_path"] == output_path
    assert json.loads(Path(output_path).read_text()) == {"witness": [1, 2]}


def test_process_silent_witness_failure(storage, monkeypatch):
    job_id = "witness-2"
    _write_text(storage, job_id, "input.json", json.dumps({"tx": "abc"}))

    def fail_witness(input_path, output_path):
        raise RuntimeError("witness failed")

    monkeypatch.setattr(worker, "generate_silent_witness", fail_witness)

    with pytest.raises(RuntimeError):
        worker.process_silent_witness(
            {
                "job_id": job_id,
                "input_path": storage.get_job_input_path(job_id, "input.json"),
                "output_path": storage.get_job_output_path(job_id, "witness.json"),
            },
            storage,
        )


def test_process_verify_tx_success(storage, monkeypatch):
    job_id = "verify-1"
    _write_text(storage, job_id, "tx.json", json.dumps({"tx_id": "abc"}))

    output_path = storage.get_job_output_path(job_id, "status.json")

    def fake_verify(tx_id):
        return {"status": "confirmed", "tx_id": tx_id}

    monkeypatch.setattr(worker, "verify_transaction_status", fake_verify)

    result = worker.process_verify_tx(
        {
            "job_id": job_id,
            "input_path": storage.get_job_input_path(job_id, "tx.json"),
            "output_path": output_path,
        },
        storage,
    )

    assert result["output_path"] == output_path
    assert json.loads(Path(output_path).read_text()) == {
        "status": "confirmed",
        "tx_id": "abc",
    }


def test_process_verify_tx_failure(storage, monkeypatch):
    job_id = "verify-2"
    _write_text(storage, job_id, "tx.json", json.dumps({"tx_id": "abc"}))

    def fail_verify(tx_id):
        raise RuntimeError("verify failed")

    monkeypatch.setattr(worker, "verify_transaction_status", fail_verify)

    with pytest.raises(RuntimeError):
        worker.process_verify_tx(
            {
                "job_id": job_id,
                "input_path": storage.get_job_input_path(job_id, "tx.json"),
                "output_path": storage.get_job_output_path(job_id, "status.json"),
            },
            storage,
        )


def test_is_fatal_value_error_non/verify():
    assert worker.is_fatal("embed", ValueError("bad input")) is True
    assert worker.is_fatal("extract", ValueError("bad input")) is True
    assert worker.is_fatal("silent_witness", ValueError("bad input")) is True


def test_is_fatal_value_error_verify_tx():
    assert worker.is_fatal("verify_tx", ValueError("bad input")) is False


def test_is_fatal_dependency_error_retryable():
    class DependencyError(Exception):
        pass

    err = DependencyError("temporary failure")
    assert worker.is_fatal("embed", err) is False
    assert worker.is_fatal("extract", err) is False
    assert worker.is_fatal("silent_witness", err) is False
    assert worker.is_fatal("verify_tx", err) is False
