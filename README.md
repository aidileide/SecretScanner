# SecretScanner

> Find secrets before they reach your repository.

[![Tests](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml/badge.svg)](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/secretscanner?label=PyPI)](https://pypi.org/project/secretscanner/)

SecretScanner ��һ���������С�Ĭ��������������Ϣɨ��������������˿����ߡ��γ���Ŀ�Ϳ�Դ�ֿ⣬��ɨ���ļ���Ŀ¼��Git ���������ݴ��������к����޵��ύ��ʷ���������նˡ�JSON �� SARIF ���档

���м����ڱ�����ɡ����߲���������֤ƾ�ݣ������ϴ��ļ���Ҳ���᳢�Ե�¼�κη���

## Ϊʲôʹ�� SecretScanner

������Ϣ���ʺ����뿪�����ߵ���ǰ�����֡�SecretScanner �ṩһ��������Ƶ� Python CLI����Ŀ¼ɨ�衢�ݴ�����顢������ʷɨ�衢baseline �� SARIF ����ͬһ�����ع����С�Ĭ����������ȷ���˳���ʹ�����ʺϸ���ʹ�ã�Ҳ�ʺϽ��� CI��

## ����

- ���� AWS��GitHub��GitLab��Slack��Stripe��Google��JWT��˽Կ�����ݿ� URL��`.env` ��ͨ���������
- Shannon �ؼ�⣬�Զ��ų����� UUID ��ɢ��ֵ
- Ĭ������ƥ��ֵ��JSON��SARIF����־�� baseline ��ʹ����������
- ֧�� `.secretscannerignore`��·��/����/ָ�ư���������������
- ֧�� YAML/TOML ���á����򿪹ء����ؼ��𸲸Ǻ��Զ����������
- ������ CLI��pre-commit hook �� GitHub Actions ���
- �ȶ��˳��룺`0` ����Ϸ��֣�`1` �ﵽ��ֵ��`2` ���û����д���

## ֧�ֵ�������Ϣ

| ��� | ʾ�� | Ĭ�ϼ��� |
| --- | --- | --- |
| ��ƾ�� | AWS Access Key��AWS Secret Key��Google API Key | high / critical |
| �����й� | GitHub PAT/OAuth��GitLab Token | high / critical |
| ��Ϣ��֧�� | Slack Token��Stripe live key | high / critical |
| ��Կ���� | PEM��RSA��OpenSSH��EC ˽Կͷ | critical |
| Ӧ��ƾ�� | ���ݿ� URL��`.env` ���б�����ͨ�����븳ֵ | high / critical |
| Token | JWT | medium |
| ����ʽ | ��������ַ��� | medium |

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

��ȫ��ʾֵ��**Example only �� not a real credential**����

```text
DEMO_API_KEY = "DEMO_NOT_REAL_123456789"
```

���������

```text
SecretScanner
HIGH  GitHub Token  src/config.py:18:9
ghp_****************************9xyz
Recommendation: Revoke or rotate this credential and move it to a secret manager.

Scanned files: 842  High: 1  Total: 1  Elapsed: 1.28s
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

## JSON �� SARIF

JSON �ʺϽű�������SARIF 2.1.0 �ɹ� GitHub Code Scanning ʹ�á����ָ�ʽĬ��ֻ��������ƥ��ֵ���Ҳ��ḽ������Դ�����У�

```bash
secretscanner scan . --format json --output secrets.json
secretscanner scan . --format sarif --output secrets.sarif
```

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

## ��˽

ɨ�衢���ˡ�����ָ�ƺͱ�����ڱ�����ɡ�SecretScanner ������ң�⡢Զ����֤���ϴ��߼���GitHub Actions �е� SARIF �ϴ��ǲֿ⹤������ʽִ�е� GitHub �ٷ����裻����Ҫ Code Scanning ʱ��ɾ���ò��衣

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

## Roadmap

- **v0.1**���ļ�ϵͳ��Git ���������ݴ�������ʷ���ؼ�⡢baseline��allowlist��JSON��SARIF��pre-commit
- **v0.2**���������Git ��ʷ�����Ż����ɹ��������
- **v0.3**��IDE ���ɡ�VS Code ��չ����ѡ GitHub App
- **v0.4**����ѡ�ı��� Web UI

## ����֤

[MIT](LICENSE)
