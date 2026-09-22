from __future__ import annotations

import json
from pathlib import Path

from secretscanner.reporters.json_reporter import json_report
from secretscanner.reporters.sarif import sarif_report
from secretscanner.scanner.engine import SecretScanner


def test_json_and_sarif_do_not_leak_secret(scanner: SecretScanner, tmp_path: Path) -> None:
    secret = "sk_live_" + "9Az" * 8  # secretscanner: allow
    target = tmp_path / "payment.py"
    target.write_text(secret, encoding="utf-8")
    result = scanner.scan_path(target)

    json_text = json_report(result)
    sarif_text = sarif_report(result)

    assert secret not in json_text
    assert secret not in sarif_text
    assert json.loads(json_text)["findings"]
    assert json.loads(sarif_text)["version"] == "2.1.0"
