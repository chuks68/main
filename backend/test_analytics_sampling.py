"""Tests for deterministic sampling in backend/analytics/sampling.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from analytics.sampling import (
    SAMPLING_DOMAIN_VERSION,
    Sampler,
    SamplingDecision,
    SamplingOutcome,
    compute_sampling_token,
    deterministic_sample_decision,
)


class TestComputeSamplingToken(unittest.TestCase):
    """Tests for compute_sampling_token determinism, format, and privacy."""

    def test_token_determinism(self) -> None:
        """Assert the same inputs always give the exact same token."""
        test_cases = [
            ("user_123", "event_page_view", "sess_abc", "salt_xyz"),
            ("user_456", "button_click", None, None),
            (None, "app_start", None, None),
            ("", "error_log", "", ""),
            ("acct_999", "checkout_completed", "session_alpha", None),
        ]
        for account, event, session, salt in test_cases:
            token_first = compute_sampling_token(account, event, session, salt)
            token_second = compute_sampling_token(account, event, session, salt)
            token_third = compute_sampling_token(account, event, session, salt)
            self.assertEqual(token_first, token_second)
            self.assertEqual(token_second, token_third)

    def test_token_format(self) -> None:
        """Assert token has the expected prefix, length, and hexadecimal payload."""
        token = compute_sampling_token("acc", "evt", "sess", "salt")
        self.assertTrue(token.startswith("st-v1:"))
        self.assertEqual(len(token), 14)
        hex_suffix = token[len("st-v1:"):]
        self.assertEqual(len(hex_suffix), 8)
        # Suffix must be valid hexadecimal
        int(hex_suffix, 16)

    def test_tokens_never_contain_raw_input_id(self) -> None:
        """Acceptance criteria: tokens never contain the raw input id."""
        raw_account_ids = [
            "user_secret_uuid_99999",
            "acc_sensitive_customer_48291048",
            "admin@organization.internal",
            "GAAZI4TCR3TYBCPO7JNV52OB2O6CQWOFU7CX2S5J322V7P7M4Z",
        ]
        raw_session_ids = [
            "session_token_xyz987654321",
            "bearer_jwt_auth_session_id",
        ]
        salt = "pepper_vault_seed_998877"
        event = "sensitive_transaction_commit"

        for raw_acc in raw_account_ids:
            for raw_sess in raw_session_ids:
                token = compute_sampling_token(raw_acc, event, raw_sess, salt)
                self.assertNotIn(raw_acc, token)
                self.assertNotIn(raw_sess, token)
                self.assertNotIn(salt, token)
                self.assertNotIn(event, token)
                # Verify prefix substrings do not leak into token
                self.assertNotIn(raw_acc[:8], token)
                self.assertNotIn(raw_sess[:8], token)

    def test_distinct_inputs_produce_distinct_tokens(self) -> None:
        """Assert varying each input dimension produces distinct tokens."""
        base_token = compute_sampling_token("acct_a", "evt_a", "sess_a", "salt_a")
        self.assertNotEqual(
            base_token,
            compute_sampling_token("acct_b", "evt_a", "sess_a", "salt_a"),
        )
        self.assertNotEqual(
            base_token,
            compute_sampling_token("acct_a", "evt_b", "sess_a", "salt_a"),
        )
        self.assertNotEqual(
            base_token,
            compute_sampling_token("acct_a", "evt_a", "sess_b", "salt_a"),
        )
        self.assertNotEqual(
            base_token,
            compute_sampling_token("acct_a", "evt_a", "sess_a", "salt_b"),
        )

    def test_default_and_empty_argument_handling(self) -> None:
        """Assert None and empty string defaults map consistently to anon."""
        token_none = compute_sampling_token(None, "page_view")
        token_empty = compute_sampling_token("", "page_view")
        token_anon = compute_sampling_token("anon", "page_view")
        self.assertEqual(token_none, token_anon)
        self.assertEqual(token_empty, token_anon)

        token_explicit_empty = compute_sampling_token("user1", "evt", "", "")
        token_none_defaults = compute_sampling_token("user1", "evt", None, None)
        self.assertEqual(token_explicit_empty, token_none_defaults)

    def test_known_token_hash_regression_vectors(self) -> None:
        """Assert exact hashing output matches locked vectors to prevent silent drift."""
        # payload = "user123|login|sess456|salt789"
        self.assertEqual(
            compute_sampling_token("user123", "login", "sess456", "salt789"),
            "st-v1:40c95a82",
        )
        # payload = "anon|page_view||"
        self.assertEqual(
            compute_sampling_token(None, "page_view"),
            "st-v1:6d4f3364",
        )


class TestDeterministicSampleDecision(unittest.TestCase):
    """Tests for deterministic_sample_decision boundary ratios and distribution."""

    def test_decision_determinism(self) -> None:
        """Assert the same inputs always give the same decision and bucket."""
        tokens = [
            compute_sampling_token("user_1", "event_a"),
            compute_sampling_token("user_2", "event_b"),
            "st-v1:40c95a82",
        ]
        rates = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]

        for tok in tokens:
            for rate in rates:
                decision1 = deterministic_sample_decision(tok, rate)
                decision2 = deterministic_sample_decision(tok, rate)
                decision3 = deterministic_sample_decision(tok, rate)
                self.assertEqual(decision1, decision2)
                self.assertEqual(decision2, decision3)

    def test_boundary_ratio_zero_keeps_nothing(self) -> None:
        """Assert ratio 0.0 keeps nothing across all tokens."""
        synthetic_tokens = [
            compute_sampling_token(f"user_{i}", "event")
            for i in range(200)
        ]
        for tok in synthetic_tokens:
            sampled_in, bucket = deterministic_sample_decision(tok, 0.0)
            self.assertFalse(sampled_in)
            self.assertEqual(bucket, 0)

    def test_boundary_ratio_one_keeps_everything(self) -> None:
        """Assert ratio 1.0 keeps everything across all tokens."""
        synthetic_tokens = [
            compute_sampling_token(f"user_{i}", "event")
            for i in range(200)
        ]
        for tok in synthetic_tokens:
            sampled_in, bucket = deterministic_sample_decision(tok, 1.0, bucket_max=1_000_000)
            self.assertTrue(sampled_in)
            self.assertEqual(bucket, 1_000_000)

    def test_out_of_bounds_ratios_clamping(self) -> None:
        """Assert rates < 0.0 clamp to 0.0 and rates > 1.0 clamp to 1.0."""
        tok = "st-v1:40c95a82"
        # Negative rates must behave like 0.0
        self.assertEqual(deterministic_sample_decision(tok, -0.001), (False, 0))
        self.assertEqual(deterministic_sample_decision(tok, -10.0), (False, 0))

        # Rates > 1.0 must behave like 1.0
        self.assertEqual(deterministic_sample_decision(tok, 1.001, bucket_max=1_000_000), (True, 1_000_000))
        self.assertEqual(deterministic_sample_decision(tok, 99.0, bucket_max=100), (True, 100))

    def test_bucket_max_clamping(self) -> None:
        """Assert bucket_max < 1 is clamped to 1 without division-by-zero errors."""
        tok = "st-v1:40c95a82"
        self.assertEqual(deterministic_sample_decision(tok, 0.0, bucket_max=0), (False, 0))
        self.assertEqual(deterministic_sample_decision(tok, 0.0, bucket_max=-5), (False, 0))
        self.assertEqual(deterministic_sample_decision(tok, 1.0, bucket_max=0), (True, 1))
        self.assertEqual(deterministic_sample_decision(tok, 1.0, bucket_max=-5), (True, 1))

    def test_ratio_025_over_10000_synthetic_ids(self) -> None:
        """For ratio 0.25 over 10,000 synthetic ids, assert the kept fraction is within tolerance."""
        num_ids = 10_000
        target_ratio = 0.25
        tolerance = 0.02  # 2% tolerance: kept fraction must be within [0.23, 0.27]

        kept_count = 0
        for i in range(num_ids):
            token = compute_sampling_token(f"synthetic_user_{i}", "metric_event")
            sampled_in, bucket = deterministic_sample_decision(token, target_ratio, bucket_max=1_000_000)
            self.assertGreaterEqual(bucket, 0)
            self.assertLess(bucket, 1_000_000)
            if sampled_in:
                kept_count += 1

        kept_fraction = kept_count / num_ids
        self.assertAlmostEqual(kept_fraction, target_ratio, delta=tolerance)


class TestSampler(unittest.TestCase):
    """Tests for Sampler class configuration, overrides, and decide determinism."""

    def test_sampler_initialization_defaults(self) -> None:
        """Assert default configuration values of Sampler."""
        sampler = Sampler()
        self.assertTrue(sampler.enabled)
        self.assertEqual(sampler.default_rate, 1.0)
        self.assertEqual(sampler.allowlist_overrides, {})
        self.assertEqual(sampler.bucket_max, 1_000_000)

    def test_sampler_custom_initialization(self) -> None:
        """Assert custom configuration values of Sampler."""
        overrides = {"heavy_event": 0.05, "critical_event": 1.0}
        sampler = Sampler(
            enabled=False,
            default_rate=0.4,
            allowlist_overrides=overrides,
            bucket_max=50_000,
        )
        self.assertFalse(sampler.enabled)
        self.assertEqual(sampler.default_rate, 0.4)
        self.assertEqual(sampler.allowlist_overrides, overrides)
        self.assertEqual(sampler.bucket_max, 50_000)

    def test_sampler_invalid_default_rate_raises(self) -> None:
        """Assert invalid default_rate (< 0.0 or > 1.0) raises ValueError."""
        with self.assertRaises(ValueError):
            Sampler(default_rate=-0.01)
        with self.assertRaises(ValueError):
            Sampler(default_rate=1.01)

    def test_sampler_decide_determinism(self) -> None:
        """Assert Sampler.decide returns the exact same decision for the same inputs."""
        sampler = Sampler(default_rate=0.35)
        decision1 = sampler.decide(
            event_name="order_placed",
            account_tag="acct_42",
            session_tag="sess_99",
            extra_salt="salt_1",
        )
        decision2 = sampler.decide(
            event_name="order_placed",
            account_tag="acct_42",
            session_tag="sess_99",
            extra_salt="salt_1",
        )
        self.assertEqual(decision1, decision2)

    def test_sampler_boundary_ratio_zero_keeps_nothing(self) -> None:
        """Assert Sampler with default_rate=0.0 keeps nothing."""
        sampler = Sampler(default_rate=0.0)
        for i in range(100):
            decision = sampler.decide(
                event_name="heartbeat",
                account_tag=f"user_{i}",
            )
            self.assertFalse(decision.sampled_in)
            self.assertEqual(decision.rate_applied, 0.0)
            self.assertEqual(decision.outcome, SamplingOutcome.SAMPLED_OUT)
            self.assertEqual(decision.bucket_value, 0)
            self.assertEqual(decision.token_version, SAMPLING_DOMAIN_VERSION)

    def test_sampler_boundary_ratio_one_keeps_everything(self) -> None:
        """Assert Sampler with default_rate=1.0 keeps everything."""
        sampler = Sampler(default_rate=1.0)
        for i in range(100):
            decision = sampler.decide(
                event_name="heartbeat",
                account_tag=f"user_{i}",
            )
            self.assertTrue(decision.sampled_in)
            self.assertEqual(decision.rate_applied, 1.0)
            self.assertEqual(decision.outcome, SamplingOutcome.SAMPLED_IN)
            self.assertEqual(decision.bucket_value, 1_000_000)
            self.assertEqual(decision.token_version, SAMPLING_DOMAIN_VERSION)

    def test_sampler_disabled_treats_all_as_in(self) -> None:
        """Assert disabled sampler admits all events with NOT_ENABLED outcome."""
        sampler = Sampler(enabled=False, default_rate=0.0)
        decision = sampler.decide("event_x", account_tag="user_123")
        self.assertTrue(decision.sampled_in)
        self.assertEqual(decision.rate_applied, 1.0)
        self.assertEqual(decision.outcome, SamplingOutcome.NOT_ENABLED)
        self.assertEqual(decision.reason, "sampling_disabled_treated_as_in")

    def test_sampler_force_overrides(self) -> None:
        """Assert force=True and force=False override rates and disabled state."""
        sampler_off = Sampler(enabled=False, default_rate=0.0)
        forced_true = sampler_off.decide("evt", force=True)
        self.assertTrue(forced_true.sampled_in)
        self.assertEqual(forced_true.rate_applied, 1.0)
        self.assertEqual(forced_true.outcome, SamplingOutcome.OVERRIDDEN_FORCE)
        self.assertEqual(forced_true.reason, "force_true")

        sampler_on = Sampler(default_rate=1.0)
        forced_false = sampler_on.decide("evt", force=False)
        self.assertFalse(forced_false.sampled_in)
        self.assertEqual(forced_false.rate_applied, 0.0)
        self.assertEqual(forced_false.outcome, SamplingOutcome.OVERRIDDEN_FORCE)
        self.assertEqual(forced_false.reason, "force_false")

    def test_sampler_allowlist_overrides(self) -> None:
        """Assert events in allowlist_overrides apply their specific rate and outcome."""
        sampler = Sampler(
            default_rate=0.0,
            allowlist_overrides={
                "always_kept_event": 1.0,
                "always_dropped_event": 0.0,
            },
        )
        # Default rate applies to unlisted event
        d_unlisted = sampler.decide("regular_event", account_tag="user_1")
        self.assertFalse(d_unlisted.sampled_in)
        self.assertEqual(d_unlisted.rate_applied, 0.0)
        self.assertEqual(d_unlisted.outcome, SamplingOutcome.SAMPLED_OUT)
        self.assertIsNone(d_unlisted.allowlist_event_name)

        # Allowlist 1.0 override keeps event
        d_kept = sampler.decide("always_kept_event", account_tag="user_1")
        self.assertTrue(d_kept.sampled_in)
        self.assertEqual(d_kept.rate_applied, 1.0)
        self.assertEqual(d_kept.outcome, SamplingOutcome.IN_ALLOWLIST_OVERRIDE)
        self.assertEqual(d_kept.allowlist_event_name, "always_kept_event")

        # Allowlist 0.0 override drops event even when default_rate=1.0
        sampler_all_in = Sampler(
            default_rate=1.0,
            allowlist_overrides={"always_dropped_event": 0.0},
        )
        d_dropped = sampler_all_in.decide("always_dropped_event", account_tag="user_1")
        self.assertFalse(d_dropped.sampled_in)
        self.assertEqual(d_dropped.rate_applied, 0.0)
        self.assertEqual(d_dropped.outcome, SamplingOutcome.OUT_ALLOWLIST_OVERRIDE)
        self.assertEqual(d_dropped.allowlist_event_name, "always_dropped_event")

    def test_sampler_ratio_025_over_10000_synthetic_ids(self) -> None:
        """For ratio 0.25 over 10,000 synthetic ids through Sampler, assert kept fraction within tolerance."""
        sampler = Sampler(default_rate=0.25)
        num_ids = 10_000
        tolerance = 0.02
        kept_count = 0

        for i in range(num_ids):
            decision = sampler.decide(
                event_name="api_request",
                account_tag=f"tenant_{i}",
                session_tag=f"sess_{i % 100}",
            )
            self.assertEqual(decision.rate_applied, 0.25)
            self.assertEqual(decision.bucket_max, 1_000_000)
            self.assertEqual(decision.token_version, SAMPLING_DOMAIN_VERSION)
            if decision.sampled_in:
                self.assertEqual(decision.outcome, SamplingOutcome.SAMPLED_IN)
                self.assertLess(decision.bucket_value, 250_000)
                kept_count += 1
            else:
                self.assertEqual(decision.outcome, SamplingOutcome.SAMPLED_OUT)
                self.assertGreaterEqual(decision.bucket_value, 250_000)

        kept_fraction = kept_count / num_ids
        self.assertAlmostEqual(kept_fraction, 0.25, delta=tolerance)

    def test_sampler_decisions_never_contain_raw_input_ids(self) -> None:
        """Acceptance criteria: decision outcomes and reasons never contain raw input IDs."""
        sensitive_account = "super_confidential_tenant_id_9999"
        sensitive_session = "jwt_bearer_token_string_here"
        sampler = Sampler(default_rate=0.5)

        decision = sampler.decide(
            event_name="user_action",
            account_tag=sensitive_account,
            session_tag=sensitive_session,
        )
        self.assertNotIn(sensitive_account, decision.outcome)
        self.assertNotIn(sensitive_session, decision.outcome)
        if decision.reason:
            self.assertNotIn(sensitive_account, decision.reason)
            self.assertNotIn(sensitive_session, decision.reason)


if __name__ == "__main__":
    unittest.main()
