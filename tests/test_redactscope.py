"""Tests for redactscope."""

import json

import pytest

from redactscope import (
    DEFAULT_PATTERNS,
    Finding,
    SecretLeak,
    assert_clean,
    audit,
    redact,
    redact_text,
)

OPENAI = "sk-proj-8fJ2kLm4Qz7Vn1Xy3Wb6"
GITHUB = "ghp_1234567890abcdefghij"
AWS = "AKIAIOSFODNN7EXAMPLE"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


class TestRedactText:
    def test_an_openai_key(self):
        assert redact_text(f"key={OPENAI}") == "key=***"

    def test_a_github_token(self):
        assert redact_text(f"token {GITHUB} here") == "token *** here"

    def test_an_aws_key(self):
        assert redact_text(f"AKIA {AWS}") == "AKIA ***"

    def test_a_jwt(self):
        assert redact_text(f"cookie: {JWT}") == "cookie: ***"

    def test_a_bearer_header(self):
        assert redact_text("Authorization: Bearer abcdefgh12345678") == "Authorization: Bearer ***"

    def test_basic_auth(self):
        header = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        assert redact_text(header) == "Authorization: Basic ***"

    def test_credentials_in_a_url(self):
        assert redact_text("postgres://user:hunter2@db:5432/x") == "postgres://user:***@db:5432/x"

    def test_a_private_key_block(self):
        block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
        assert redact_text(f"before\n{block}\nafter") == "before\n***\nafter"

    def test_ordinary_text_is_untouched(self):
        text = "the quick brown fox reads a.txt at 12:00"
        assert redact_text(text) == text

    def test_a_short_sk_prefix_is_not_a_key(self):
        assert redact_text("sk-1") == "sk-1"

    def test_the_mask_can_be_chosen(self):
        assert redact_text(OPENAI, mask="[redacted]") == "[redacted]"

    def test_several_secrets_in_one_string(self):
        text = f"{OPENAI} and {GITHUB}"
        assert redact_text(text) == "*** and ***"


class TestRedactStructures:
    def test_a_secret_key_is_masked(self):
        assert redact({"password": "hunter2"}) == {"password": "***"}

    def test_key_matching_is_substring_and_case_insensitive(self):
        redacted = redact({"X-API-Key": "abc", "AUTHORIZATION": "Bearer x"})
        assert redacted == {"X-API-Key": "***", "AUTHORIZATION": "***"}

    def test_nested_dicts(self):
        redacted = redact({"outer": {"token": "t", "keep": 1}})
        assert redacted == {"outer": {"token": "***", "keep": 1}}

    def test_lists(self):
        assert redact([{"secret": "s"}, OPENAI]) == [{"secret": "***"}, "***"]

    def test_a_tuple_becomes_a_list(self):
        assert redact(("password", "x")) == ["password", "x"]

    def test_numbers_and_booleans_survive(self):
        assert redact({"count": 3, "ok": True, "nothing": None}) == {
            "count": 3,
            "ok": True,
            "nothing": None,
        }

    def test_a_secret_inside_a_string_value(self):
        redacted = redact({"content": f"curl -H 'Authorization: Bearer {OPENAI}'"})
        assert "***" in redacted["content"]
        assert OPENAI not in redacted["content"]

    def test_the_input_is_not_modified(self):
        original = {"password": "hunter2"}
        redact(original)
        assert original == {"password": "hunter2"}

    def test_extra_markers(self):
        assert redact({"visa": "4111"}, markers=("visa",)) == {"visa": "***"}

    def test_a_custom_mask(self):
        assert redact({"password": "x"}, mask="[x]") == {"password": "[x]"}

    def test_an_agent_message_shape(self):
        message = {
            "role": "tool",
            "content": f"connected with {AWS}",
            "metadata": {"api_key": "abc", "trace": OPENAI},
        }
        redacted = redact(message)
        assert redacted["metadata"] == {"api_key": "***", "trace": "***"}
        assert AWS not in redacted["content"]
        assert json.dumps(redacted).count("***") == 3


class TestAudit:
    def test_a_clean_payload(self):
        assert audit({"path": "a.txt", "count": 2}) == []

    def test_a_secret_key_is_reported_with_its_path(self):
        findings = audit({"metadata": {"api_key": "abc"}})
        assert [(finding.path, finding.kind) for finding in findings] == [
            ("metadata.api_key", "secret-key")
        ]

    def test_a_pattern_match_is_reported(self):
        findings = audit({"content": f"key {OPENAI}"})
        assert findings[0].kind == "openai-key"
        assert findings[0].path == "content"

    def test_a_list_index_appears_in_the_path(self):
        findings = audit({"messages": [{"content": f"x {GITHUB}"}]})
        assert findings[0].path == "messages[0].content"

    def test_the_preview_does_not_leak_the_value(self):
        findings = audit({"password": "hunter2"})
        assert "hunter2" not in findings[0].preview

    def test_audit_finds_but_does_not_change(self):
        payload = {"password": "hunter2"}
        audit(payload)
        assert payload == {"password": "hunter2"}

    def test_every_pattern_can_be_found(self):
        samples = {
            "openai-key": OPENAI,
            "github-token": GITHUB,
            "aws-access-key": AWS,
            "jwt": JWT,
        }
        for kind, sample in samples.items():
            kinds = [finding.kind for finding in audit({"content": sample})]
            assert kind in kinds, kind

    def test_a_finding_prints(self):
        assert str(Finding("a.b", "jwt", "***")) == "a.b: jwt"


class TestAssertClean:
    def test_clean_values_pass(self):
        assert_clean({"path": "a.txt"})

    def test_a_secret_raises(self):
        with pytest.raises(SecretLeak) as caught:
            assert_clean({"password": "x"})
        assert len(caught.value.findings) == 1
        assert "1 secret(s) found" in str(caught.value)

    def test_it_is_a_runtime_error(self):
        assert issubclass(SecretLeak, RuntimeError)


class TestPatterns:
    def test_every_pattern_has_a_name_and_is_compiled(self):
        for kind, pattern in DEFAULT_PATTERNS:
            assert isinstance(kind, str) and kind
            assert hasattr(pattern, "search")

    def test_patterns_can_be_restricted(self):
        only_jwt = tuple(item for item in DEFAULT_PATTERNS if item[0] == "jwt")
        assert audit({"c": OPENAI}, patterns=only_jwt) == []
        assert audit({"c": JWT}, patterns=only_jwt)

    def test_no_patterns_means_only_keys_are_checked(self):
        assert audit({"c": OPENAI}, patterns=()) == []
        assert audit({"password": "x"}, patterns=())


class TestCommandLine:
    def run(self, argv):
        from redactscope.__main__ import main

        return main(argv)

    def write(self, tmp_path, payload):
        path = tmp_path / "message.json"
        path.write_text(payload, encoding="utf-8")
        return str(path)

    def test_json_is_redacted(self, tmp_path, capsys):
        path = self.write(
            tmp_path,
            json.dumps({"role": "tool", "content": f"token={OPENAI}", "api_key": "abc"}),
        )
        assert self.run([path]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload == {"role": "tool", "content": "token=***", "api_key": "***"}

    def test_check_mode_exits_one(self, tmp_path, capsys):
        path = self.write(tmp_path, json.dumps({"content": OPENAI}))
        assert self.run([path, "--check"]) == 1
        assert "openai-key" in capsys.readouterr().err

    def test_check_mode_on_a_clean_file(self, tmp_path, capsys):
        path = self.write(tmp_path, json.dumps({"content": "hello"}))
        assert self.run([path, "--check"]) == 0
        assert "0 secret(s) found" in capsys.readouterr().err

    def test_a_text_file(self, tmp_path, capsys):
        path = tmp_path / "trace.txt"
        path.write_text(f"GET /x\nAuthorization: Bearer {GITHUB}\n", encoding="utf-8")
        assert self.run([str(path)]) == 0
        assert "***" in capsys.readouterr().out

    def test_a_missing_file_exits_two(self, tmp_path, capsys):
        assert self.run([str(tmp_path / "nope.json")]) == 2
        assert "cannot read" in capsys.readouterr().err

    def test_a_custom_mask(self, tmp_path, capsys):
        path = self.write(tmp_path, json.dumps({"password": "x"}))
        assert self.run([path, "--mask", "[x]"]) == 0
        assert json.loads(capsys.readouterr().out)["password"] == "[x]"

    def test_malformed_json_falls_back_to_text(self, tmp_path, capsys):
        path = self.write(tmp_path, '{"content": ' + f'"{OPENAI}"' + " oops")
        assert self.run([path]) == 0
        assert "***" in capsys.readouterr().out
