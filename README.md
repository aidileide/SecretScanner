# SecretScanner

> Find secrets before they reach your repository.

[![Tests](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml/badge.svg)](https://github.com/aidileide/SecretScanner/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/secretscanner?label=PyPI)](https://pypi.org/project/secretscanner/)

SecretScanner 是一个本地运行、默认脱敏的敏感信息扫描器。它面向个人开发者、课程项目和开源仓库，可扫描文件、目录、Git 工作区、暂存区新增行和有限的提交历史，并生成终端、JSON 或 SARIF 报告。

所有检测均在本机完成。工具不会联网验证凭据，不会上传文件，也不会尝试登录任何服务。

## 为什么使用 SecretScanner

敏感信息最适合在离开开发者电脑前被发现。SecretScanner 提供一个容易审计的 Python CLI，把目录扫描、暂存区检查、有限历史扫描、baseline 和 SARIF 放在同一个本地工具中。默认脱敏和明确的退出码使它既适合个人使用，也适合接入 CI。

## 功能

- 内置 AWS、GitHub、GitLab、Slack、Stripe、Google、JWT、私钥、数据库 URL、`.env` 和通用密码规则
- Shannon 熵检测，自动排除常见 UUID 与散列值
- 默认隐藏匹配值；JSON、SARIF、日志和 baseline 均使用脱敏内容
- 支持 `.secretscannerignore`、路径/规则/指纹白名单和行内抑制
- 支持 YAML/TOML 配置、规则开关、严重级别覆盖和自定义正则规则
- 多线程文件扫描、实时进度条、文件数量与时间安全边界
- 可用作 CLI、pre-commit hook 和 GitHub Actions 检查
- 稳定退出码：`0` 无阻断发现，`1` 达到阈值，`2` 配置或运行错误

## 支持的敏感信息

| 类别 | 示例 | 默认级别 |
| --- | --- | --- |
| 云凭据 | AWS Access Key、AWS Secret Key、Google API Key | high / critical |
| 代码托管 | GitHub PAT/OAuth、GitLab Token | high / critical |
| 消息与支付 | Slack Token、Stripe live key | high / critical |
| 密钥材料 | PEM、RSA、OpenSSH、EC 私钥头 | critical |
| 应用凭据 | 数据库 URL、`.env` 敏感变量、通用密码赋值 | high / critical |
| Token | JWT | medium |
| 启发式 | 高熵随机字符串 | medium |

## 安装

需要 Python 3.11 或更高版本。

```bash
pipx install secretscanner
```

从源码安装开发版本：

```bash
git clone https://github.com/aidileide/SecretScanner.git
cd SecretScanner
python -m venv .venv
python -m pip install -e ".[dev]"
```

## 快速使用

```bash
# 递归扫描当前目录
secretscanner scan .

# 扫描单个文件并输出 JSON
secretscanner scan settings.py --format json --output result.json

# 扫描 Git 已跟踪文件，并包含未跟踪文件
secretscanner git . --include-untracked

# 只扫描暂存区新增行，适合提交前检查
secretscanner staged .

# 扫描最近 50 个提交的新增行
secretscanner history . --max-commits 50

# 生成 GitHub Code Scanning 可读的 SARIF
secretscanner scan . --format sarif --output secrets.sarif

# 查看规则和最终配置
secretscanner rules
secretscanner config .
```

大型目录可控制并发和扫描边界：

```bash
secretscanner scan . --workers 8 --max-files 50000 --timeout 300
```

如果达到文件数量或时间上限，报告会标记 `incomplete`，进程返回退出码 `2`，避免 CI 将部分扫描误判为安全。

安全演示值（**Example only — not a real credential**）：

```text
DEMO_API_KEY = "DEMO_NOT_REAL_123456789"
```

典型输出：

```text
SecretScanner
HIGH  GitHub Token  src/config.py:18:9
ghp_****************************9xyz
Recommendation: Revoke or rotate this credential and move it to a secret manager.

Scanned files: 842  High: 1  Total: 1  Elapsed: 1.28s
```

默认在 `high` 及以上发现时返回退出码 `1`。可调整阈值：

```bash
secretscanner scan . --fail-on medium
```

## 配置

SecretScanner 会从目标路径向上查找 `.secretscanner.yml`、`.secretscanner.yaml` 或 `.secretscanner.toml`。完整示例见 [`.secretscanner.example.yml`](.secretscanner.example.yml)。

```yaml
scan:
  max_file_size_mb: 5
  entropy: true
  follow_symlinks: false
  workers: 4
  max_files: 50000
  timeout_seconds: 300
  max_findings_per_rule_per_file: 20

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

额外忽略项可写入 `.secretscannerignore`，语法与 `.gitignore` 类似：

```gitignore
tests/fixtures/
docs/generated/
*.snapshot
```

对确认安全的单行示例，可使用精确抑制：

```python
example = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # secretscanner: allow

# secretscanner: allow-next-line
example_two = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Baseline

Baseline 只保存发现指纹，不保存明文或脱敏后的匹配内容：

```bash
secretscanner baseline create . --output .secretscanner-baseline.json
secretscanner scan . --baseline .secretscanner-baseline.json
```

建议只对已人工确认的历史发现建立 baseline，并在代码审查中检查 baseline 变化。

## JSON 与 SARIF

JSON 适合脚本处理，SARIF 2.1.0 可供 GitHub Code Scanning 使用。两种格式默认只包含脱敏匹配值，且不会附带完整源代码行：

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

hook 默认执行 `secretscanner staged .`，只检查准备提交的新增行。

## GitHub Actions

仓库自带 [敏感信息扫描工作流](.github/workflows/secrets.yml)，会生成 SARIF 并上传到 GitHub Code Scanning。私有仓库或未启用 Code Scanning 时，可删除上传步骤，CLI 检查仍然有效。

## 安全边界

- 规则和熵检测可能产生误报或漏报，不能替代密钥轮换、代码审查和专用秘密管理系统。
- 默认输出只保留首尾少量字符。`--show-secrets` 会把匹配值写到终端或报告中，仅在受控本地环境使用。
- 工具不会调用远程 API 验证凭据，不会执行扫描到的代码，也不会自动修改目标文件。
- 若真实密钥曾进入 Git 历史，仅删除文件不够；应立即吊销或轮换密钥，再清理历史。

## 隐私

扫描、过滤、生成指纹和报告均在本地完成。SecretScanner 不包含遥测、远程验证或上传逻辑。GitHub Actions 中的 SARIF 上传是仓库工作流显式执行的 GitHub 官方步骤；不需要 Code Scanning 时可删除该步骤。

发现安全问题请阅读 [SECURITY.md](SECURITY.md)。参与开发请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 开发

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
pytest
python -m build
twine check dist/*
```

## Roadmap

- **v0.1**：文件系统、Git 工作区、暂存区、历史、熵检测、baseline、allowlist、JSON、SARIF、pre-commit
- **v0.2**：更多规则、Git 历史性能优化、可共享规则包
- **v0.3**：IDE 集成、VS Code 扩展、可选 GitHub App
- **v0.4**：可选的本地 Web UI

## 许可证

[MIT](LICENSE)
