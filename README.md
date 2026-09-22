# SecretScanner

[![Tests](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml/badge.svg)](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SecretScanner ��һ���������С�Ĭ��������������Ϣɨ��������������˿����ߡ��γ���Ŀ�Ϳ�Դ�ֿ⣬��ɨ���ļ���Ŀ¼��Git ���������ݴ��������к����޵��ύ��ʷ���������նˡ�JSON �� SARIF ���档

���м����ڱ�����ɡ����߲���������֤ƾ�ݣ������ϴ��ļ���Ҳ���᳢�Ե�¼�κη���

## ����

- ���� AWS��GitHub��GitLab��Slack��Stripe��Google��JWT��˽Կ�����ݿ� URL��`.env` ��ͨ���������
- Shannon �ؼ�⣬�Զ��ų����� UUID ��ɢ��ֵ
- Ĭ������ƥ��ֵ��JSON��SARIF����־�� baseline ��ʹ����������
- ֧�� `.secretscannerignore`��·��/����/ָ�ư���������������
- ֧�� YAML/TOML ���á����򿪹ء����ؼ��𸲸Ǻ��Զ����������
- ������ CLI��pre-commit hook �� GitHub Actions ���
- �ȶ��˳��룺`0` ����Ϸ��֣�`1` �ﵽ��ֵ��`2` ���û����д���

## ��װ

��Ҫ Python 3.11 ����߰汾��

```bash
pipx install secretscanner
```

��Դ�밲װ�����汾��

```bash
git clone https://github.com/aidileide/SecretScanner.git
cd SecretScanner
python -m venv .venv
python -m pip install -e ".[dev]"
```

## ����ʹ��

```bash
# �ݹ�ɨ�赱ǰĿ¼
secretscanner scan .

# ɨ�赥���ļ������ JSON
secretscanner scan settings.py --format json --output result.json

# ɨ�� Git �Ѹ����ļ���������δ�����ļ�
secretscanner git . --include-untracked

# ֻɨ���ݴ��������У��ʺ��ύǰ���
secretscanner staged .

# ɨ����� 50 ���ύ��������
secretscanner history . --max-commits 50

# ���� GitHub Code Scanning �ɶ��� SARIF
secretscanner scan . --format sarif --output secrets.sarif

# �鿴�������������
secretscanner rules
secretscanner config .
```

Ĭ���� `high` �����Ϸ���ʱ�����˳��� `1`���ɵ�����ֵ��

```bash
secretscanner scan . --fail-on medium
```

## ����

SecretScanner ���Ŀ��·�����ϲ��� `.secretscanner.yml`��`.secretscanner.yaml` �� `.secretscanner.toml`������ʾ���� [`.secretscanner.example.yml`](.secretscanner.example.yml)��

```yaml
scan:
  max_file_size_mb: 5
  entropy: true
  follow_symlinks: false

exclude:
  - "fixtures/**"
  - "*.min.js"

rules:
  jwt:
    enabled: false
  generic-password:
    severity: medium

allowlist:
  paths:
    - "docs/examples/**"
  rules: []
  fingerprints: []

custom_rules:
  - id: internal-token
    name: Internal Token
    regex: "\\bINT_[A-Z0-9]{24}\\b"
    category: internal
    severity: high
    confidence: high
    remediation: Rotate this token and store it outside source control.
```

����������д�� `.secretscannerignore`���﷨�� `.gitignore` ���ƣ�

```gitignore
tests/fixtures/
docs/generated/
*.snapshot
```

��ȷ�ϰ�ȫ�ĵ���ʾ������ʹ�þ�ȷ���ƣ�

```python
example = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # secretscanner: allow

# secretscanner: allow-next-line
example_two = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Baseline

Baseline ֻ���淢��ָ�ƣ����������Ļ��������ƥ�����ݣ�

```bash
secretscanner baseline create . --output .secretscanner-baseline.json
secretscanner scan . --baseline .secretscanner-baseline.json
```

����ֻ�����˹�ȷ�ϵ���ʷ���ֽ��� baseline�����ڴ�������м�� baseline �仯��

## pre-commit

```yaml
repos:
  - repo: https://github.com/aidileide/SecretScanner
    rev: v0.1.0
    hooks:
      - id: secretscanner
```

hook Ĭ��ִ�� `secretscanner staged .`��ֻ���׼���ύ�������С�

## GitHub Actions

�ֿ��Դ� [������Ϣɨ�蹤����](.github/workflows/secrets.yml)�������� SARIF ���ϴ��� GitHub Code Scanning��˽�вֿ��δ���� Code Scanning ʱ����ɾ���ϴ����裬CLI �����Ȼ��Ч��

## ��ȫ�߽�

- ������ؼ����ܲ����󱨻�©�������������Կ�ֻ�����������ר�����ܹ���ϵͳ��
- Ĭ�����ֻ������β�����ַ���`--show-secrets` ���ƥ��ֵд���ն˻򱨸��У������ܿر��ػ���ʹ�á�
- ���߲������Զ�� API ��֤ƾ�ݣ�����ִ��ɨ�赽�Ĵ��룬Ҳ�����Զ��޸�Ŀ���ļ���
- ����ʵ��Կ������ Git ��ʷ����ɾ���ļ�������Ӧ�����������ֻ���Կ����������ʷ��

���ְ�ȫ�������Ķ� [SECURITY.md](SECURITY.md)�����뿪�����Ķ� [CONTRIBUTING.md](CONTRIBUTING.md)��

## ����

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
pytest
python -m build
twine check dist/*
```

## ����֤

[MIT](LICENSE)
