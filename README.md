# Code Security Auditor MCP Server

A small, **keyless** and **defensive** (blue-team) security toolkit exposed
over the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It
lets an AI assistant (Kiro CLI, Claude Desktop, Cursor, etc.) audit **local
codebases** through natural language.

Unlike recon/offensive tools that probe live websites, this one inspects
*your own code and credentials* — making it a defensive companion to
red-team tooling.

> ⚠️ **Defensive use only.** All tools are read-only and privacy-preserving,
> and require no API keys. Use only on code and credentials you own or are
> authorized to assess.

## Tools

| Tool | What it does |
| --- | --- |
| `scan_secrets(path)` | Recursively scans a file or directory for hardcoded secrets — AWS keys, GitHub/Slack tokens, private keys, JWTs, and generic credential assignments. Matches are **masked** in the report. |
| `audit_dependencies(path)` | Parses a `requirements.txt` (PyPI) or `package.json` (npm) and checks each pinned dependency against the free [OSV.dev](https://osv.dev) vulnerability database. |
| `check_pwned_password(password)` | Checks a password against [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using **k-anonymity** — only the first 5 characters of the SHA-1 hash are ever sent, so the password never leaves your machine. |

## Requirements

- Python 3.10+
- The `mcp` and `httpx` packages (see `requirements.txt`)

## Installation

```bash
git clone https://github.com/<your-username>/code-security-auditor-mcp.git
cd code-security-auditor-mcp

# (recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Running

The server speaks MCP over stdio, so it's normally launched by an MCP client.
To confirm it starts:

```bash
python server.py
```

(It will wait for an MCP client on stdin — press Ctrl+C to exit.)

## Connecting to an MCP client

Add this to your client's MCP config (e.g. `claude_desktop_config.json` or
your Kiro CLI MCP settings), adjusting the path:

```json
{
  "mcpServers": {
    "code-security-auditor": {
      "command": "python",
      "args": ["/absolute/path/to/code-security-auditor-mcp/server.py"]
    }
  }
}
```

Then ask your assistant things like:

- "Scan ./my-project for hardcoded secrets"
- "Audit requirements.txt for known vulnerabilities"
- "Has the password 'password123' been pwned?"

## Example output

```
Secret scan of ./my-project
Files scanned: 42
Findings: 1

  [!] AWS Access Key ID
      ./my-project/config.py:12
      match: AKIA...QF (len 20)
```

```
Dependency audit of requirements.txt
Ecosystem: PyPI
Dependencies checked: 8
Vulnerable packages: 1

  [!] requests==2.19.0  -> 1 known vuln(s)
      - GHSA-... (CVE-2018-18074): Requests before 2.20.0 leaks Authorization headers...
```

## How the privacy-safe password check works

`check_pwned_password` hashes the password with SHA-1 locally, sends only the
first **5 hex characters** of the hash to the HIBP range API, and matches the
remaining suffix against the response locally. The full password and full hash
never leave your machine. This is the same k-anonymity model HIBP recommends.

## Project structure

```
code-security-auditor-mcp/
├── server.py          # MCP server + the three tools
├── requirements.txt
├── README.md
├── LICENSE            # MIT
└── .gitignore
```

## License

MIT — see [LICENSE](LICENSE).
