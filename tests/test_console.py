from io import StringIO
from pathlib import Path

from rich.console import Console

from secretscanner.reporters.console import print_console
from secretscanner.scanner.engine import SecretScanner


def test_console_is_chinese_and_masked(scanner: SecretScanner, tmp_path: Path) -> None:
    secret = "ghp_" + "Z9y8" * 9  # secretscanner: allow
    target = tmp_path / "secret.py"
    target.write_text(secret, encoding="utf-8")
    result = scanner.scan_path(target)
    stream = StringIO()

    print_console(result, console=Console(file=stream, color_system=None, width=120))

    rendered = stream.getvalue()
    assert "检测结果" in rendered
    assert "已扫描" in rendered
    assert secret not in rendered
