<div align="center">

# 🛡️ GuardX

**A keyless, defensive (blue-team) code-security auditor for the [Model Context Protocol](https://modelcontextprotocol.io).**
Let your AI assistant scan codebases for secrets, audit dependencies for known CVEs, and check passwords against breach data — all from natural language.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-8A2BE2)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![No API Keys](https://img.shields.io/badge/API%20keys-none%20required-success)]()
[![Use](https://img.shields.io/badge/use-defensive%20only-orange)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

---

> ⚠️ **Defensive use only.** Every tool is **read-only**, **privacy-preserving**, and needs **no API keys**. Use it only on code and credentials you own or are authorized to assess.

Unlike offensive recon tools that probe live websites, this server inspects **your own code and credentials** — making it the blue-team companion to your red-team tooling.

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Connect to an MCP Client](#connect-to-an-mcp-client)
- [Usage](#usage)
- [How the Privacy-Safe Password Check Works](#how-the-privacy-safe-password-check-works)
- [Tool Reference](#tool-reference)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🔑 **Secret scanning** — detect hardcoded AWS keys, GitHub/Slack tokens, private keys, JWTs, and generic credentials. Findings are **masked**, so reports are safe to share.
- 📦 **Dependency auditing** — check `requirements.txt` (PyPI) and `package.json` (npm) against the free [OSV.dev](https://osv.dev) vulnerability database.
- 🔐 **Breached-password check** — query [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using **k-anonymity**; the password never leaves your machine.
- 🚫 **No API keys, no accounts** — clone, install, run.
- 🤖 **Native MCP** — works with Claude Code, Claude Desktop, Gemini CLI, OpenAI Codex, Cursor, and any MCP client.

## Screenshots

### 🔑 Scan a project for hardcoded secrets
<p align="center">
  <img src="assets/scan_secrets.png" alt="scan_secrets output" width="800">
</p>

### 📦 Audit dependencies against the OSV vulnerability database
<p align="center">
  <img src="assets/audit_dependencies.png" alt="audit_dependencies output" width="800">
</p>

### 🔐 Check whether a password has been breached
<p align="center">
  <img src="assets/check_pwned_password.png" alt="check_pwned_password output" width="800">
</p>

## Installation

```bash
git clone https://github.com/harshzagade/guardx-mcp.git
cd guardx-mcp

# (recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

**Requirements:** Python 3.10+ and the `mcp` + `httpx` packages (installed via `requirements.txt`).

## Connect to an MCP Client

GuardX runs locally over **stdio**, so any MCP-capable client can launch it. In every example below, replace `/absolute/path/to/guardx-mcp/server.py` with the real path on your machine. If you used a virtual environment, point `command` at that env's Python (e.g. `.venv/bin/python` or `.venv\Scripts\python.exe`) instead of `python`.

> 💡 First, confirm the server starts on its own (it then waits for a client on stdin — press `Ctrl+C` to exit):
> ```bash
> python server.py
> ```

<details open>
<summary><b>Claude Code</b> (CLI)</summary>

Register the server with one command:

```bash
claude mcp add guardx -- python /absolute/path/to/guardx-mcp/server.py
```

- Add `--scope project` to write it to a shared `.mcp.json` in your repo.
- Verify with `claude mcp list`, then use `/mcp` inside Claude Code.

</details>

<details>
<summary><b>Claude Desktop</b> (app)</summary>

Edit your `claude_desktop_config.json`:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "guardx": {
      "command": "python",
      "args": ["/absolute/path/to/guardx-mcp/server.py"]
    }
  }
}
```

Restart Claude Desktop; GuardX appears under the 🔌 tools menu.

</details>

<details>
<summary><b>Gemini CLI</b> (& Gemini Code Assist)</summary>

Edit `~/.gemini/settings.json` (global) or `.gemini/settings.json` (per-project). The Gemini Code Assist IDE extension reads the same file:

```json
{
  "mcpServers": {
    "guardx": {
      "command": "python",
      "args": ["/absolute/path/to/guardx-mcp/server.py"]
    }
  }
}
```

Then run `gemini` and use `/mcp` to confirm the server is connected.

</details>

<details>
<summary><b>OpenAI Codex</b> (CLI & IDE extension)</summary>

Codex uses **TOML** and shares config between the CLI and the IDE extension. Either run:

```bash
codex mcp add guardx -- python /absolute/path/to/guardx-mcp/server.py
```

…or hand-edit `~/.codex/config.toml` ( note the **underscore** in `mcp_servers`):

```toml
[mcp_servers.guardx]
command = "python"
args = ["/absolute/path/to/guardx-mcp/server.py"]
```

> Codex only supports **local stdio** MCP servers — perfect for GuardX.

</details>

<details>
<summary><b>Cursor</b> / <b>VS Code</b></summary>

Create `.cursor/mcp.json` in your project (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "guardx": {
      "command": "python",
      "args": ["/absolute/path/to/guardx-mcp/server.py"]
    }
  }
}
```

VS Code (with MCP support) uses the same `mcpServers` shape in its settings.

</details>

> **Windows tip:** in JSON, write paths with forward slashes (`C:/Users/you/guardx-mcp/server.py`) or escaped backslashes (`C:\\Users\\you\\...`).

## Usage

Once connected, just ask your assistant in plain language:

| You say... | Tool used |
| --- | --- |
| *"Scan `./my-project` for hardcoded secrets"* | `scan_secrets` |
| *"Audit `requirements.txt` for known vulnerabilities"* | `audit_dependencies` |
| *"Has the password `password123` been pwned?"* | `check_pwned_password` |

## How the Privacy-Safe Password Check Works

`check_pwned_password` follows the [k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords) recommended by Have I Been Pwned:

1. The password is hashed locally with **SHA-1**.
2. Only the **first 5 hex characters** of the hash are sent to the HIBP range API.
3. The API returns all hash suffixes sharing that prefix; the match is found **locally**.

➡️ Your password and its full hash **never leave your machine**.

## Tool Reference

| Tool | Signature | Description |
| --- | --- | --- |
| **Secret scanner** | `scan_secrets(path, max_findings=200)` | Recursively scans a file or directory for hardcoded secrets. Skips binaries and common ignore dirs (`.git`, `node_modules`, …). Returns masked findings with file and line number. |
| **Dependency auditor** | `audit_dependencies(path)` | Parses a `requirements.txt` or `package.json` and checks each pinned dependency against OSV.dev. Returns CVE/GHSA ids and summaries. |
| **Pwned-password check** | `check_pwned_password(password)` | Checks a password against HIBP via k-anonymity. Reports breach count without transmitting the password. |

## Project Structure

```
guardx-mcp/
├── server.py          # MCP server + the three tools
├── requirements.txt   # runtime dependencies (mcp, httpx)
├── assets/            # README screenshots
├── README.md
├── LICENSE            # MIT
└── .gitignore
```

## Contributing

Contributions are welcome! Ideas: more secret patterns, additional ecosystems
(Go modules, Cargo, Maven), or an SBOM export. Please keep all contributions
**defensive** in nature. Open an issue or a pull request.

## License

Released under the [MIT License](LICENSE).

---

<div align="center">
<sub>Built as a defensive blue-team companion. Scan responsibly. 🛡️</sub>
</div>
