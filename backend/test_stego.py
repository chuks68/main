import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

from envelope import canonical_metadata_hash
from metrics import collector as metrics_collector
from stego import (
    StegoError,
    StegoLimitExceededError,
    _init_stego_worker,
    _reset_stego_pool,
    embed_metadata,
    extract_metadata,
    sha256_file,
)

# Root directory for devx imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "devx"))
try:
    import generate_synthetic_media
except ImportError:
    generate_synthetic_media = None


class SteganographyTest(unittest.TestCase):
    def setUp(self) -> None:
        metrics_collector.reset()
        _reset_stego_pool()

    def tearDown(self) -> None:
        _reset_stego_pool()

    def test_embeds_and_extracts_metadata_from_encoded_video(self) -> None:
        if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
            self.skipTest("ffmpeg and ffprobe are required")

        with tempfile.TemporaryDirectory(prefix="harpocrates-stego-test-") as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "source.mp4"
            embedded = tmp_path / "embedded.mp4"
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-v",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    "testsrc=size=320x240:rate=30",
                    "-t",
                    "3",
                    "-pix_fmt",
                    "yuv420p",
                    str(source),
                ],
                check=True,
            )

            metadata = {
                "protocol": "harpocrates",
                "version": 1,
                "tier": "silent",
                "sourceHash": sha256_file(source),
                "proofId": "11" * 32,
                "timestamp": "2026-06-18T00:00:00.000Z",
                "fileName": "source.mp4",
            }

            embed_metadata(source, embedded, metadata)

            self.assertNotEqual(sha256_file(source), sha256_file(embedded))
            self.assertEqual(len(canonical_metadata_hash(metadata)), 64)
            self.assertEqual(extract_metadata(embedded), metadata)

    def test_synthetic_media_normal_roundtrip(self) -> None:
        if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
            self.skipTest("ffmpeg and ffprobe are required")
        if generate_synthetic_media is None:
            self.skipTest("generate_synthetic_media is required")

        with tempfile.TemporaryDirectory(prefix="harpocrates-synth-test-") as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "synthetic.mp4"
            embedded = tmp_path / "embedded.mp4"

            generate_synthetic_media.generate(
                source,
                width=320,
                height=240,
                duration=3,
                fps=30,
                seed=42,
            )

            metadata = {
                "protocol": "harpocrates",
                "version": 2,
                "tier": "silent",
                "sourceHash": sha256_file(source),
                "proofId": "22" * 32,
                "timestamp": "2026-06-18T00:00:00.000Z",
                "fileName": "synthetic.mp4",
            }

            embed_metadata(source, embedded, metadata)
            extracted = extract_metadata(embedded)
            self.assertEqual(extracted, metadata)

    def test_windows_fallback_warning_on_worker_init(self) -> None:
        with patch("stego.os.name", "nt"):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                _init_stego_worker(536_870_912, 60)
                self.assertTrue(
                    any(
                        issubclass(w.category, RuntimeWarning)
                        and "resource.setrlimit are not supported on Windows" in str(w.message)
                        for w in recorded
                    )
                )

    def test_posix_worker_init_sets_rlimit(self) -> None:
        mock_resource = MagicMock()
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        with patch("stego.os.name", "posix"), patch.dict("sys.modules", {"resource": mock_resource}):
            _init_stego_worker(1024 * 1024, 30)
            mock_resource.setrlimit.assert_any_call(mock_resource.RLIMIT_AS, (1024 * 1024, 1024 * 1024))
            mock_resource.setrlimit.assert_any_call(mock_resource.RLIMIT_CPU, (30, 30))

    def test_limit_breach_records_metric_and_raises_typed_error_embed(self) -> None:
        from concurrent.futures.process import BrokenProcessPool

        fake_future = MagicMock()
        fake_future.result.side_effect = BrokenProcessPool("Process terminated due to resource limit")
        fake_pool = MagicMock()
        fake_pool.submit.return_value = fake_future

        with patch("stego._get_stego_pool", return_value=fake_pool):
            with self.assertRaises(StegoLimitExceededError):
                embed_metadata("source.mp4", "out.mp4", {"protocol": "harpocrates"})

        prom_metrics = metrics_collector.generate_prometheus_metrics()
        self.assertIn('harpocrates_stego_limit_breaches_total{operation="embed"} 1', prom_metrics)

    def test_limit_breach_records_metric_and_raises_typed_error_extract(self) -> None:
        from concurrent.futures.process import BrokenProcessPool

        fake_future = MagicMock()
        fake_future.result.side_effect = BrokenProcessPool("Process terminated due to resource limit")
        fake_pool = MagicMock()
        fake_pool.submit.return_value = fake_future

        with patch("stego._get_stego_pool", return_value=fake_pool):
            with self.assertRaises(StegoLimitExceededError):
                extract_metadata("source.mp4")

        prom_metrics = metrics_collector.generate_prometheus_metrics()
        self.assertIn('harpocrates_stego_limit_breaches_total{operation="extract"} 1', prom_metrics)

    def test_memory_error_records_metric_and_raises_typed_error(self) -> None:
        fake_future = MagicMock()
        fake_future.result.side_effect = MemoryError("Worker memory exhausted")
        fake_pool = MagicMock()
        fake_pool.submit.return_value = fake_future

        with patch("stego._get_stego_pool", return_value=fake_pool):
            with self.assertRaises(StegoLimitExceededError):
                embed_metadata("source.mp4", "out.mp4", {"protocol": "harpocrates"})

        prom_metrics = metrics_collector.generate_prometheus_metrics()
        self.assertIn('harpocrates_stego_limit_breaches_total{operation="embed"} 1', prom_metrics)

    def test_api_stego_limit_exceeded_error_response(self) -> None:
        from flask import Flask
        from errors import STEGO_LIMIT_EXCEEDED, error_response

        app = Flask(__name__)

        @app.errorhandler(StegoLimitExceededError)
        def handle_limit(error):
            return error_response(
                code=STEGO_LIMIT_EXCEEDED,
                message="steganography resource limit exceeded",
                status=413,
            )

        @app.route("/extract", methods=["POST"])
        def mock_extract():
            raise StegoLimitExceededError("Resource limit exceeded")

        client = app.test_client()
        response = client.post("/extract")
        self.assertEqual(response.status_code, 413)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], STEGO_LIMIT_EXCEEDED)


if __name__ == "__main__":
    unittest.main()
