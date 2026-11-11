"""Unit tests for the bytecode scanner and scoring. Run: python -m pytest -q"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.dex import MethodRef, iter_instructions, method_is_trivial, scan_method_calls  # noqa: E402
from scanner.engine import security_score  # noqa: E402


def test_const_true_reaches_watched_call():
    # const/4 v1, #1 ; invoke-virtual {v0, v1}, method@5 ; return-void
    code = [0x1112, 0x206E, 0x0005, 0x0010, 0x000E]
    hits = scan_method_calls(code, {5: ("wv_js", False, ("Z",))}, [], {})
    assert hits == [("wv_js", [1])]


def test_const_string_argument_static_call():
    # const-string v0, string@0 ; invoke-static {v0}, method@2
    code = [0x001A, 0x0000, 0x1071, 0x0002, 0x0000, 0x000E]
    hits = scan_method_calls(code, {2: ("cipher", True, ("Ljava/lang/String;",))}, ["AES/ECB/PKCS5Padding"], {})
    assert hits == [("cipher", [("str", "AES/ECB/PKCS5Padding")])]


def test_register_overwrite_clears_constant():
    # const/4 v1,#1 ; iget v1, v0, field@0 (22c, writes vA=1) ; invoke-virtual {v0,v1}, m@5
    code = [0x1112, 0x0152, 0x0000, 0x206E, 0x0005, 0x0010, 0x000E]
    hits = scan_method_calls(code, {5: ("wv_js", False, ("Z",))}, [], {})
    assert hits == [("wv_js", [None])]


def test_string_getbytes_becomes_key_bytes():
    # const-string v0,"k3y" ; invoke-virtual {v0}, getBytes@1 ; move-result-object v1 ;
    # invoke-direct {v2, v1, v0}, SecretKeySpec.<init>@3
    code = [0x001A, 0x0000, 0x106E, 0x0001, 0x0000, 0x010C, 0x3070, 0x0003, 0x0012, 0x000E]
    hits = scan_method_calls(code, {3: ("secret_key", False, ("[B", "Ljava/lang/String;"))}, ["k3y"], {1: "getBytes"})
    assert hits[0][1][0] == ("bytes", "k3y")


def test_payload_skipping():
    # goto +0 placeholder, then packed-switch-payload of size 1, then return-void
    code = [0x000E, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x000E]
    ops = [op for _, op in iter_instructions(code)]
    assert ops == [0x0E, 0x0E]


def test_trust_all_detection():
    methods = [MethodRef("Lkotlin/jvm/internal/Intrinsics;", "checkNotNullParameter", ("Ljava/lang/Object;", "Ljava/lang/String;"), "V")]
    # const-string v0 ; invoke-static {v1, v0}, Intrinsics@0 ; return-void
    empty_kotlin = [0x001A, 0x0000, 0x2071, 0x0000, 0x0001, 0x000E]
    assert method_is_trivial(empty_kotlin, methods)[0] is True
    # throw v0
    assert method_is_trivial([0x0027], methods)[0] is False


def test_hostname_verifier_returns_true():
    # const/4 v0,#1 ; return v0
    assert method_is_trivial([0x1012, 0x000F], []) == (True, 1)


def test_security_score_bounds():
    assert security_score([])["score"] == 100
    bad = [{"severity": "Critical", "confidence": "High"}] * 10
    s = security_score(bad)
    assert s["score"] < 10 and s["grade"] == "F"


SAMPLE = os.environ.get("APK_SAMPLE")


@pytest.mark.skipif(not SAMPLE, reason="set APK_SAMPLE=/path/to/InsecureShop.apk to run")
def test_insecureshop_end_to_end():
    from scanner.engine import analyze
    r = analyze(SAMPLE)
    ids = {v["id"] for v in r["vulnerabilities"]}
    for expected in ("MAN-001", "NET-001", "COMP-004", "FP-001", "WV-002", "WV-009", "IPC-002", "SIG-002"):
        assert expected in ids, expected
