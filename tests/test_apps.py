import pytest
import vuln_app
import secure_app


def test_use_insecure_hash():
    assert vuln_app.use_insecure_hash("a") == "0cc175b9c0f1b6a831c399e269772661"


def test_use_secure_hash():
    assert secure_app.use_secure_hash("a") == "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"


def test_safe_eval_ok():
    assert secure_app.safe_eval("[1, 2, 3]") == [1, 2, 3]


def test_safe_eval_bad():
    with pytest.raises(ValueError):
        secure_app.safe_eval("__import__('os').system('echo hi')")


def test_run_shell_command_safe_ok():
    result = secure_app.run_shell_command_safe(["echo", "hello"])
    assert result.returncode == 0


def test_run_shell_command_safe_disallowed():
    with pytest.raises(ValueError, match="not permitted"):
        secure_app.run_shell_command_safe(["rm", "-rf", "/tmp/test"])


def test_run_shell_command_safe_rejects_string():
    with pytest.raises(ValueError, match="must be a non-empty list"):
        secure_app.run_shell_command_safe("echo hello")


def test_run_untrusted_code_evaluates():
    assert vuln_app.run_untrusted_code("1 + 1") == 2


def test_print_demo_secrets_no_error():
    vuln_app.print_demo_secrets()
