"""Offline approval (DIV §5a) behaviour the shared vectors do not pin: single use, the pending
records, unsafe nonces, key input forms, the bundle directory, and — the property the whole mechanism
rests on — that the client falls back ONLY when the gateway could not be asked.

Uses the committed vector bundle and seed-derived keys (see test_offline_approval_vectors.py); every
call that checks time pins `as_of` inside the bundle's validity. Transport is stubbed at
intyga_sdk.client._async_request, so nothing here touches the network.
"""

import asyncio
import base64
import json
import os
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import intyga_sdk.client as client_mod
from intyga_sdk import (
    FileRedemptionStore,
    decode_challenge_envelope,
    IntygaClient,
    OfflineApprovalOptions,
    approver_anchor,
    clear_pending_approval,
    create_offline_challenge,
    decode_signature_envelope,
    encode_signature_envelope,
    load_trust_bundle,
    pending_approvals,
    read_pending_approvals,
    save_trust_bundle,
    sign_challenge_envelope,
    use_offline_approval,
    verify_approval_receipt,
)
import httpx
from intyga_sdk.errors import (
    GatewayRefused,
    GatewayResponseUnreadable,
    GatewayUnreachable,
    OfflineApprovalFailed,
)
from test_client import FailingBody, patched_transport
from test_offline_approval_vectors import V, at, key_from_seed, key_of, person, sign

AS_OF = at("2026-10-06T12:00:00.123Z")
ACTION = {
    "target": "prod-db-cluster-01",
    "actionType": "db.restart",
    "display": "Restart the primary database",
    "params": {"cluster": "primary"},
}
ISO_MS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
POSIX = os.name == "posix"


def witness_for(pid, kind, payload, claim=None):
    return encode_signature_envelope(
        {
            "signerDid": person(claim or pid)["did"],
            "signerPublicKey": key_of(pid, kind)["spki"],
            "signature": sign(pid, kind, payload),
            "sigAlg": "ES256",
        }
    )


def collect_from(*signers):
    calls = []

    def collect(challenge):
        calls.append(challenge)
        return [witness_for(pid, kind, challenge["canonicalPayload"]) for pid, kind in signers]

    collect.calls = calls
    return collect


class BundleDirCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="intyga-offline-")
        self.dir = os.path.join(self.root, "bundle")
        save_trust_bundle(self.dir, V["bundleJws"], V["gatewayJwk"])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def options(self, collect, **extra):
        return OfflineApprovalOptions(
            bundle_dir=self.dir,
            requester_did=V["requesterDid"],
            collect_signatures=collect,
            as_of=AS_OF,
            warn=lambda _m: None,
            **extra,
        )

    def run_offline(self, collect, action=ACTION, **extra):
        return asyncio.run(use_offline_approval(action, self.options(collect, **extra)))


class TestTrustBundleDirectory(BundleDirCase):
    def test_save_then_load_round_trips_with_private_modes(self):
        r = load_trust_bundle(self.dir, as_of=AS_OF)
        self.assertTrue(r["ok"], r.get("reason"))
        self.assertEqual(r["bundle"], V["bundle"])
        with open(os.path.join(self.dir, "gateway-key.jwk.json"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.read()), V["gatewayJwk"])
        with open(os.path.join(self.dir, "trust-bundle.jws"), encoding="utf-8") as f:
            self.assertEqual(f.read(), V["bundleJws"])
        if POSIX:
            self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
            for name in ("trust-bundle.jws", "gateway-key.jwk.json"):
                self.assertEqual(os.stat(os.path.join(self.dir, name)).st_mode & 0o777, 0o600, name)

    def test_missing_bundle_names_the_remedy(self):
        r = load_trust_bundle(os.path.join(self.root, "nowhere"), as_of=AS_OF)
        self.assertFalse(r["ok"])
        self.assertIn("intyga trust-bundle export", r["reason"])

    def test_missing_pinned_key_is_refused(self):
        os.unlink(os.path.join(self.dir, "gateway-key.jwk.json"))
        r = load_trust_bundle(self.dir, as_of=AS_OF)
        self.assertFalse(r["ok"])
        self.assertIn("no pinned gateway key", r["reason"])

    def test_anchor_purpose_is_one_of_two_values(self):
        with self.assertRaises(ValueError):
            approver_anchor(V["bundle"], None, "offline")  # a typo must not silently mean "ordinary"


class TestRedemptionStore(BundleDirCase):
    def test_a_nonce_redeems_exactly_once_across_store_instances(self):
        store_dir = os.path.join(self.root, "redeemed")
        first = FileRedemptionStore(store_dir)
        self.assertTrue(first.redeem("off_once"))
        self.assertFalse(first.redeem("off_once"))
        # A second process opening the same directory sees the claim: state is the file, not memory.
        self.assertFalse(FileRedemptionStore(store_dir).redeem("off_once"))
        marker = os.path.join(store_dir, "off_once.used")
        with open(marker, encoding="utf-8") as f:
            self.assertRegex(f.read(), ISO_MS)
        if POSIX:
            self.assertEqual(os.stat(marker).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(store_dir).st_mode & 0o777, 0o700)

    def test_an_unsafe_nonce_is_never_used_as_a_path(self):
        store_dir = os.path.join(self.root, "redeemed")
        store = FileRedemptionStore(store_dir)
        for nonce in ("../escape", "a/b", "", "x" * 201, None):
            self.assertFalse(store.redeem(nonce), repr(nonce))
        self.assertFalse(os.path.exists(os.path.join(self.root, "escape.used")))
        self.assertEqual(os.listdir(store_dir), [])

    def test_a_symlinked_marker_is_not_followed(self):
        if not POSIX:
            self.skipTest("symlinks")
        store_dir = os.path.join(self.root, "redeemed")
        store = FileRedemptionStore(store_dir)
        outside = os.path.join(self.root, "outside")
        os.symlink(outside, os.path.join(store_dir, "off_link.used"))
        self.assertFalse(store.redeem("off_link"))
        self.assertFalse(os.path.exists(outside))

    def test_a_store_that_refuses_clears_the_pending_record_and_refuses(self):
        class AlreadyRedeemed:
            def redeem(self, nonce):
                return False

        r = self.run_offline(collect_from(("alice", "offline"), ("bob", "offline")), store=AlreadyRedeemed())
        self.assertFalse(r["ok"])
        self.assertIn("already been redeemed", r["reason"])
        self.assertEqual(pending_approvals(self.dir), [])


class TestPendingRecords(BundleDirCase):
    def test_a_completed_approval_is_buffered_then_cleared(self):
        r = self.run_offline(collect_from(("alice", "offline"), ("bob", "offline")))
        self.assertTrue(r["ok"], r.get("reason"))
        self.assertEqual(sorted(r["signers"]), ["did:intyga:alice", "did:intyga:bob"])
        self.assertIsNone(r["viaDelegation"])
        self.assertTrue(os.path.exists(os.path.join(self.dir, ".redeemed", f"{r['nonce']}.used")))

        records = pending_approvals(self.dir)
        self.assertEqual(len(records), 1)
        rec = records[0]
        # Exactly the documented record; no delegationNonce key when no delegation was used.
        self.assertEqual(set(rec), {"nonce", "target", "actionType", "display", "usedAt", "receipt"})
        self.assertEqual(rec["nonce"], r["nonce"])
        self.assertEqual(
            (rec["target"], rec["actionType"], rec["display"]),
            (ACTION["target"], ACTION["actionType"], ACTION["display"]),
        )
        self.assertRegex(rec["usedAt"], ISO_MS)
        self.assertEqual(rec["receipt"], r["receipt"])
        record_path = os.path.join(self.dir, ".pending", f"{r['nonce']}.json")
        if POSIX:
            self.assertEqual(os.stat(record_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.dirname(record_path)).st_mode & 0o777, 0o700)

        # The buffered receipt is the full proof: it re-verifies with no Intyga secret.
        check = verify_approval_receipt(
            rec["receipt"],
            {**{k: ACTION[k] for k in ("target", "actionType", "params")}, "nonce": rec["nonce"],
             "approvers": approver_anchor(V["bundle"], None, "offline-intent")},
            allow_offline=True,
            as_of=AS_OF,
        )
        self.assertTrue(check["ok"], check.get("reason"))

        clear_pending_approval(r["nonce"], self.dir)
        self.assertEqual(pending_approvals(self.dir), [])
        clear_pending_approval(r["nonce"], self.dir)  # already gone: no error

    def test_buffer_dir_overrides_the_default(self):
        buffer_dir = os.path.join(self.root, "elsewhere")
        r = self.run_offline(collect_from(("alice", "offline"), ("bob", "offline")), buffer_dir=buffer_dir)
        self.assertTrue(r["ok"], r.get("reason"))
        self.assertEqual(pending_approvals(self.dir), [])
        self.assertEqual([p["nonce"] for p in pending_approvals(self.dir, buffer_dir)], [r["nonce"]])

    def test_a_delegated_approval_records_the_delegation_nonce(self):
        delegation_dir = os.path.join(self.root, "delegations")
        os.mkdir(delegation_dir)
        with open(os.path.join(delegation_dir, "seal.json"), "w", encoding="utf-8") as f:
            json.dump(V["delegations"]["sealed-ordinary"], f)
        action = {**ACTION, **{k: V["offlineApproval"][0]["action"][k] for k in ("display", "params")}}
        r = self.run_offline(
            collect_from(("carol", "ordinary"), ("dave", "ordinary")), action=action, delegation_dir=delegation_dir
        )
        self.assertTrue(r["ok"], r.get("reason"))
        self.assertEqual(r["viaDelegation"], "dlg-sealed-ordinary")
        self.assertEqual(pending_approvals(self.dir)[0]["delegationNonce"], "dlg-sealed-ordinary")

    def test_an_unreadable_record_is_named_and_does_not_hide_the_others(self):
        r = self.run_offline(collect_from(("alice", "offline"), ("bob", "offline")))
        for name, text in (("aaa-corrupt.json", "{not json"), ("bbb-array.json", "[]"),
                           ("ccc-no-nonce.json", '{"target": "x"}')):
            with open(os.path.join(self.dir, ".pending", name), "w", encoding="utf-8") as f:
                f.write(text)
        self.assertEqual([p["nonce"] for p in pending_approvals(self.dir)], [r["nonce"]])
        read = read_pending_approvals(self.dir)
        self.assertEqual([p["nonce"] for p in read["records"]], [r["nonce"]])
        self.assertEqual(read["unreadable"], ["aaa-corrupt.json", "bbb-array.json", "ccc-no-nonce.json"])

    def test_a_failing_collector_fails_the_approval_and_leaves_nothing_behind(self):
        class Unreachable(RuntimeError):
            pass

        def collect(_challenge):
            raise Unreachable("approver line dropped")

        with self.assertRaises(Unreachable):
            self.run_offline(collect)
        self.assertEqual(read_pending_approvals(self.dir), {"records": [], "unreadable": []})
        self.assertFalse(os.path.exists(os.path.join(self.dir, ".redeemed")))

    def test_clearing_an_unsafe_nonce_touches_nothing(self):
        bystander = os.path.join(self.dir, "x.json")
        with open(bystander, "w", encoding="utf-8") as f:
            f.write("{}")
        clear_pending_approval("../x", self.dir)
        self.assertTrue(os.path.exists(bystander))

    def test_no_signatures_is_not_an_approval_and_buffers_nothing(self):
        r = self.run_offline(lambda _c: [])
        self.assertFalse(r["ok"])
        self.assertIn("no signatures were collected", r["reason"])
        self.assertEqual(pending_approvals(self.dir), [])

    def test_an_async_collector_is_awaited(self):
        inner = collect_from(("alice", "offline"), ("bob", "offline"))

        async def collect(challenge):
            await asyncio.sleep(0)
            return inner(challenge)

        self.assertTrue(self.run_offline(collect)["ok"])


class TestChallenge(unittest.TestCase):
    def base(self, **over):
        return {
            "bundle": V["bundle"],
            "target": ACTION["target"],
            "action_type": ACTION["actionType"],
            "display": ACTION["display"],
            "params": ACTION["params"],
            "requester": {"did": V["requesterDid"], "attestation": None},
            "as_of": AS_OF,
            **over,
        }

    def test_a_blank_target_is_refused_by_javascript_trim_rules(self):
        for target in ("", "  ", "\ufeff", "\u3000\t\u2028"):
            r = create_offline_challenge(**self.base(target=target))
            self.assertEqual(r, {"ok": False, "reason": "target is required (DIV Target Isolation)"}, repr(target))
        # U+0085 is not ECMAScript whitespace (Python's str.strip would remove it), so not blank.
        self.assertTrue(create_offline_challenge(**self.base(target="\u0085"))["ok"])

    def test_unsafe_nonces_are_refused(self):
        for nonce in ("../escape", "a/b", "", "x" * 201, "a b"):
            r = create_offline_challenge(**self.base(nonce=nonce))
            self.assertFalse(r["ok"], repr(nonce))
            self.assertEqual(r["reason"], "nonce must be a safe path segment")

    def test_default_nonce_is_fresh_and_path_safe(self):
        a = create_offline_challenge(**self.base())["challenge"]["nonce"]
        b = create_offline_challenge(**self.base())["challenge"]["nonce"]
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"off_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")

    def test_timestamps_are_javascript_iso_strings(self):
        as_of = datetime(2026, 10, 6, 12, 0, 0, 123999, tzinfo=timezone.utc)
        c = create_offline_challenge(**self.base(as_of=as_of, window_minutes=7))["challenge"]
        self.assertEqual(c["challengedAt"], "2026-10-06T12:00:00.123Z")  # truncated, not rounded
        self.assertEqual(c["expiresAt"], "2026-10-06T12:07:00.123Z")

    def test_the_window_is_a_whole_number_of_minutes(self):
        self.assertTrue(create_offline_challenge(**self.base(window_minutes=7.0))["ok"])  # JSON 7.0 is 7
        for window in (7.5, float("nan"), float("inf"), True, "5"):
            r = create_offline_challenge(**self.base(window_minutes=window))
            self.assertFalse(r["ok"], repr(window))
            self.assertEqual(r["reason"], "windowMinutes must be a whole number of minutes")

    def test_a_non_json_param_is_a_refusal_not_an_exception(self):
        from decimal import Decimal

        r = create_offline_challenge(**self.base(params={"amount": Decimal("1.00")}))
        self.assertFalse(r["ok"])
        self.assertIn("cannot be canonicalized", r["reason"])


class TestChallengeShapes(unittest.TestCase):
    """A challenge payload whose bytes ARE canonical but whose fields have the wrong JSON types must
    still be refused: `"target": 5` re-serializes identically, and the approver would then sign
    something no relying party builds."""

    def envelope_with(self, **changes):
        from intyga_sdk.crypto import base64url_encode, stable_stringify

        payload = json.loads(V["createChallenge"][0]["expect"]["canonicalPayload"])
        payload.update(changes)
        return "DIV1:" + base64url_encode(stable_stringify(payload).encode("utf-8"))

    def test_well_typed_but_wrong_shapes_are_refused_before_the_bytes(self):
        for field, value in (
            ("target", 5), ("target", True), ("target", None), ("actionType", 1), ("display", None),
            ("nonce", 7), ("challengedAt", 1), ("expiresAt", False), ("params", []), ("params", "x"),
            ("requester", {"did": 5, "attestation": None}),
        ):
            with self.subTest(field=field, value=value):
                r = decode_challenge_envelope(self.envelope_with(**{field: value}))
                self.assertFalse(r["ok"])
                self.assertRegex(r["reason"], r"^challenge payload .* — refusing to sign it$")
                self.assertNotIn("not canonical", r["reason"])

    def test_the_unchanged_payload_still_decodes(self):
        self.assertTrue(decode_challenge_envelope(self.envelope_with())["ok"])


class TestSigningKeyForms(unittest.TestCase):
    def setUp(self):
        self.key = key_from_seed(key_of("alice", "offline")["seed"])
        self.envelope = V["signChallenge"][0]["envelope"]

    def sign_with(self, private_key, signer_did="did:intyga:alice"):
        return sign_challenge_envelope(self.envelope, private_key=private_key, signer_did=signer_did, as_of=AS_OF)

    def test_pem_der_and_key_object_all_sign_as_the_same_key(self):
        pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        der = self.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        for form in (self.key, pem, pem.decode("ascii"), der):
            r = self.sign_with(form)
            self.assertTrue(r["ok"], r.get("reason"))
            w = decode_signature_envelope(r["envelope"])["witness"]
            self.assertEqual(w["signerPublicKey"], key_of("alice", "offline")["spki"])

    def test_sig1_json_is_byte_identical_to_the_reference(self):
        r = self.sign_with(self.key)
        text = base64.urlsafe_b64decode(r["envelope"][5:] + "==").decode("utf-8")
        w = json.loads(text)
        self.assertEqual(
            text,
            '{"did":"did:intyga:alice","key":"%s","sig":"%s","alg":"ES256"}' % (w["key"], w["sig"]),
        )
        self.assertEqual(
            base64.urlsafe_b64decode(
                encode_signature_envelope(
                    {"signerDid": "did:intyga:åäö", "signerPublicKey": "k", "signature": "s"}
                )[5:] + "=="
            ).decode("utf-8"),
            '{"did":"did:intyga:åäö","key":"k","sig":"s","alg":"ES256"}',
        )

    def test_a_sec1_pem_signs_as_the_same_key(self):
        # `openssl ecparam -genkey` writes SEC1 ("EC PRIVATE KEY"), not PKCS#8.
        sec1 = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
        self.assertTrue(sec1.startswith(b"-----BEGIN EC PRIVATE KEY-----"))
        for form in (sec1, sec1.decode("ascii")):
            r = self.sign_with(form)
            self.assertTrue(r["ok"], r.get("reason"))
            w = decode_signature_envelope(r["envelope"])["witness"]
            self.assertEqual(w["signerPublicKey"], key_of("alice", "offline")["spki"])

    def test_refuses_another_curve_garbage_and_a_non_did(self):
        r = self.sign_with(ec.generate_private_key(ec.SECP384R1()))
        self.assertFalse(r["ok"])
        self.assertIn("P-256", r["reason"])
        r = self.sign_with(b"not a key")
        self.assertFalse(r["ok"])
        self.assertIn("could not read the private key", r["reason"])
        r = self.sign_with(self.key, signer_did="alice")
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "signerDid must be a DID")


class FakeGateway:
    """Scripted transport: `authorize` and `status` are lists consumed per call, each entry a
    (status, body) pair or an exception to raise. Records reconcile bodies."""

    def __init__(self, authorize=None, status=None, reconcile=None):
        self.authorize = list(authorize or [])
        self.status = list(status or [])
        self.reconcile = list(reconcile or [])
        self.reconciled = []
        self.headers = []

    @staticmethod
    def _answer(entry):
        if isinstance(entry, Exception):
            raise entry
        status, body = entry
        return status, body if isinstance(body, str) else json.dumps(body)

    async def __call__(self, url, method="GET", headers=None, json_body=None):
        self.headers.append(headers)
        if url.endswith("/offline-approval/reconcile"):
            self.reconciled.append(json_body)
            return self._answer(self.reconcile.pop(0))
        if method == "POST":
            return self._answer(self.authorize.pop(0) if self.authorize else (200, {"nonce": "n1"}))
        return self._answer(self.status.pop(0))


def unreachable():
    return GatewayUnreachable("Connection failed: ECONNREFUSED")


class TestFallbackGating(BundleDirCase):
    """The fallback is reachable ONLY when the gateway could not be asked. A DENIED or EXPIRED result
    means a human was reached and did not approve, and a 4xx means the gateway refused: letting an
    out-of-band approval override either is worse than having no gate at all."""

    def require(self, gateway, offline=True, collect=None, **kwargs):
        collect = collect or collect_from(("alice", "offline"), ("bob", "offline"))
        client = IntygaClient("https://gw.example", token="t", target=ACTION["target"])
        with mock.patch.object(client_mod, "_async_request", gateway):
            return asyncio.run(
                client.require_approval(
                    ACTION["display"],
                    action_type=ACTION["actionType"],
                    params=ACTION["params"],
                    interval_ms=1,
                    offline=self.options(collect) if offline else None,
                    **kwargs,
                )
            )

    def assert_offline_approved(self, r):
        self.assertEqual(r["status"], "OFFLINE_APPROVED")
        self.assertNotEqual(r["status"], "APPROVED")
        self.assertEqual([p["nonce"] for p in pending_approvals(self.dir)], [r["nonce"]])
        check = verify_approval_receipt(
            r["receipt"],
            {**{k: ACTION[k] for k in ("target", "actionType", "params")}, "nonce": r["nonce"],
             "approvers": approver_anchor(V["bundle"], None, "offline-intent")},
            allow_offline=True,
            as_of=AS_OF,
        )
        self.assertTrue(check["ok"], check.get("reason"))

    def fresh_state(self):
        """Subtests share one bundle dir; start each from no pending or redeemed state."""
        for name in (".pending", ".redeemed"):
            shutil.rmtree(os.path.join(self.dir, name), ignore_errors=True)

    def assert_nothing_attempted(self, collect):
        self.assertEqual(collect.calls, [])
        self.assertEqual(pending_approvals(self.dir), [])

    def test_transport_failure_raising_the_challenge_falls_back(self):
        self.assert_offline_approved(self.require(FakeGateway(authorize=[unreachable()])))

    def test_a_5xx_raising_the_challenge_falls_back(self):
        self.assert_offline_approved(self.require(FakeGateway(authorize=[(503, "upstream down")])))

    def test_repeated_polling_failures_fall_back(self):
        gw = FakeGateway(status=[unreachable()] * client_mod.MAX_POLL_ERRORS)
        self.assert_offline_approved(self.require(gw))

    def test_a_4xx_is_never_routed_offline(self):
        for code in (400, 401, 403, 429):
            with self.subTest(code=code):
                self.fresh_state()
                collect = collect_from(("alice", "offline"), ("bob", "offline"))
                with self.assertRaises(GatewayRefused) as ctx:
                    self.require(FakeGateway(authorize=[(code, "no")]), collect=collect)
                self.assertEqual(ctx.exception.status, code)
                self.assert_nothing_attempted(collect)

    def test_repeated_4xx_polls_are_not_routed_offline(self):
        collect = collect_from(("alice", "offline"), ("bob", "offline"))
        gw = FakeGateway(status=[(404, "unknown nonce")] * client_mod.MAX_POLL_ERRORS)
        with self.assertRaises(GatewayRefused) as ctx:
            self.require(gw, collect=collect)
        self.assertEqual(ctx.exception.status, 404)
        self.assert_nothing_attempted(collect)

    def test_a_refusal_anywhere_in_the_failure_streak_is_raised_not_routed_offline(self):
        # The gateway answered 404 once and then went quiet: it was reached, so its answer wins over
        # the 5xx that ended the streak.
        fail_5xx = (503, "upstream down")
        for streak in (
            [(404, "unknown nonce")] + [fail_5xx] * 4,
            [fail_5xx, (404, "unknown nonce"), unreachable(), fail_5xx, unreachable()],
            [fail_5xx] * 4 + [(404, "unknown nonce")],
        ):
            with self.subTest(streak=[getattr(e, "args", e)[0] for e in streak]):
                self.fresh_state()
                collect = collect_from(("alice", "offline"), ("bob", "offline"))
                with self.assertRaises(GatewayRefused) as ctx:
                    self.require(FakeGateway(status=list(streak)), collect=collect)
                self.assertEqual(ctx.exception.status, 404)
                self.assert_nothing_attempted(collect)

    def test_a_successful_poll_resets_the_streak_and_its_refusal(self):
        gw = FakeGateway(
            status=[(404, "unknown nonce")] + [(503, "down")] * 3 + [(200, {"status": "PENDING"})]
            + [unreachable()] * client_mod.MAX_POLL_ERRORS
        )
        self.assert_offline_approved(self.require(gw))

    def require_over_http(self, handler, collect):
        """require_approval on the client's real httpx path (streamed body), not a stubbed request."""
        client = IntygaClient("https://gw.example", token="t", target=ACTION["target"])
        with patched_transport(handler):
            return asyncio.run(
                client.require_approval(
                    ACTION["display"],
                    action_type=ACTION["actionType"],
                    params=ACTION["params"],
                    interval_ms=1,
                    offline=self.options(collect),
                )
            )

    def test_an_unreadable_response_body_is_never_routed_offline(self):
        # Headers arrived, then the connection dropped: the gateway was asked. Only "no HTTP response"
        # and a 5xx may route offline — a 5xx whose body is lost included in neither.
        def authorize_answers_then_drops(status):
            def handler(request):
                return httpx.Response(status, stream=FailingBody())

            return handler

        def polls_answer_then_drop(request):
            if request.method == "POST":
                return httpx.Response(200, json={"nonce": "n1"})
            return httpx.Response(200, stream=FailingBody())

        for name, handler in (
            ("authorize 200", authorize_answers_then_drops(200)),
            ("authorize 503", authorize_answers_then_drops(503)),
            ("five polls", polls_answer_then_drop),
        ):
            with self.subTest(name):
                self.fresh_state()
                collect = collect_from(("alice", "offline"), ("bob", "offline"))
                with self.assertRaises(GatewayResponseUnreadable):
                    self.require_over_http(handler, collect)
                self.assert_nothing_attempted(collect)

    def test_an_unreadable_body_in_the_failure_streak_is_raised_not_routed_offline(self):
        collect = collect_from(("alice", "offline"), ("bob", "offline"))
        lost = GatewayResponseUnreadable(200, "the gateway answered 200, but its response body could not be read")
        gw = FakeGateway(status=[lost] + [(503, "down")] * (client_mod.MAX_POLL_ERRORS - 1))
        with self.assertRaises(GatewayResponseUnreadable) as ctx:
            self.require(gw, collect=collect)
        self.assertIs(ctx.exception, lost)
        self.assert_nothing_attempted(collect)

    def test_denied_and_expired_are_returned_not_routed_offline(self):
        for status in ("DENIED", "EXPIRED"):
            with self.subTest(status=status):
                self.fresh_state()
                collect = collect_from(("alice", "offline"), ("bob", "offline"))
                r = self.require(FakeGateway(status=[(200, {"status": status})]), collect=collect)
                self.assertEqual(r["status"], status)
                self.assertEqual(r["nonce"], "n1")
                self.assert_nothing_attempted(collect)

    def test_a_transient_poll_failure_does_not_end_the_wait(self):
        collect = collect_from(("alice", "offline"), ("bob", "offline"))
        gw = FakeGateway(
            status=[unreachable()] * (client_mod.MAX_POLL_ERRORS - 1) + [(200, {"status": "APPROVED"})]
        )
        r = self.require(gw, collect=collect)
        self.assertEqual(r["status"], "APPROVED")
        self.assert_nothing_attempted(collect)

    def test_without_offline_options_the_typed_error_is_raised(self):
        with self.assertRaises(GatewayUnreachable):
            self.require(FakeGateway(authorize=[unreachable()]), offline=False)
        with self.assertRaises(GatewayRefused) as ctx:
            self.require(FakeGateway(authorize=[(502, "bad gateway")]), offline=False)
        self.assertEqual(ctx.exception.status, 502)

    def test_agent_continuity_requests_never_fall_back(self):
        collect = collect_from(("alice", "offline"), ("bob", "offline"))
        with self.assertRaises(OfflineApprovalFailed) as ctx:
            self.require(
                FakeGateway(authorize=[unreachable()]), collect=collect, agent_context={"agent": {}}
            )
        self.assertIn("agent continuity", ctx.exception.reason)
        self.assertIsInstance(ctx.exception.__cause__, GatewayUnreachable)
        self.assert_nothing_attempted(collect)

    def test_an_offline_ceremony_that_does_not_complete_raises(self):
        with self.assertRaises(OfflineApprovalFailed) as ctx:
            self.require(FakeGateway(authorize=[unreachable()]), collect=lambda _c: [])
        self.assertIn("no signatures were collected", ctx.exception.reason)
        self.assertIn("could not reach Intyga", str(ctx.exception))


class TestReconcile(BundleDirCase):
    def write_record(self, nonce, **extra):
        pending = os.path.join(self.dir, ".pending")
        os.makedirs(pending, exist_ok=True)
        record = {
            "nonce": nonce,
            "target": ACTION["target"],
            "actionType": ACTION["actionType"],
            "display": ACTION["display"],
            "usedAt": "2026-10-06T12:01:00.000Z",
            "receipt": {"canonicalPayload": "{}", "actionDescription": ACTION["display"]},
            **extra,
        }
        with open(os.path.join(pending, f"{nonce}.json"), "w", encoding="utf-8") as f:
            json.dump(record, f)

    def reconcile(self, gateway):
        client = IntygaClient("https://gw.example", token="t", target=ACTION["target"])
        with mock.patch.object(client_mod, "_async_request", gateway):
            return asyncio.run(client.reconcile_offline_approvals(self.dir))

    def test_clears_only_what_the_gateway_acknowledged(self):
        self.write_record("off_a")
        self.write_record("off_b", delegationNonce="dlg-1")
        self.write_record("off_c")
        gw = FakeGateway(reconcile=[(200, ""), (500, "boom"), unreachable()])
        r = self.reconcile(gw)
        self.assertEqual((r["reported"], r["failed"]), (1, 2))
        self.assertEqual(len(r["reasons"]), 2)
        self.assertTrue(r["reasons"][0].startswith("off_b: "))
        self.assertEqual([p["nonce"] for p in pending_approvals(self.dir)], ["off_b", "off_c"])
        # The body is the record, with no null standing in for an absent delegationNonce (the
        # gateway's schema takes it as an optional string).
        self.assertNotIn("delegationNonce", gw.reconciled[0])
        self.assertEqual(gw.reconciled[1]["delegationNonce"], "dlg-1")
        self.assertEqual(
            set(gw.reconciled[0]), {"nonce", "usedAt", "target", "actionType", "display", "receipt"}
        )
        self.assertEqual(gw.headers[0]["authorization"], "Bearer t")

    def test_an_unreadable_record_is_counted_named_and_kept(self):
        self.write_record("off_a")
        broken = os.path.join(self.dir, ".pending", "off_broken.json")
        with open(broken, "w", encoding="utf-8") as f:
            f.write("{truncated")
        gw = FakeGateway(reconcile=[(200, "")])
        r = self.reconcile(gw)
        self.assertEqual((r["reported"], r["failed"]), (1, 1))
        self.assertEqual(r["reasons"], ["off_broken.json: unreadable pending record — report it by hand"])
        self.assertEqual(len(gw.reconciled), 1)
        self.assertTrue(os.path.exists(broken))

    def test_a_retry_reports_what_failed_before(self):
        self.write_record("off_a")
        self.assertEqual(self.reconcile(FakeGateway(reconcile=[(503, "")]))["failed"], 1)
        self.assertEqual(self.reconcile(FakeGateway(reconcile=[(204, "")]))["reported"], 1)
        self.assertEqual(pending_approvals(self.dir), [])


if __name__ == "__main__":
    unittest.main()
