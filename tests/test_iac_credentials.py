"""Unit tests for GuardX's `scan_secrets` IaC credential heuristic:
a hardcoded credential inside a sensitive infrastructure-as-code
resource block (Terraform, CloudFormation, ARM) is a HIGH "IaC
Credential" finding, while the same assignment outside a sensitive
block, or with a placeholder/reference value, stays clean.

`mcp` and `httpx` are not installed in this environment (and we do not
install packages to run tests), so this suite stubs both modules in
`sys.modules` before importing `server.py`. The stub `FastMCP.tool()`
returns the decorated function unchanged, exactly like FastMCP 1.x does,
so these tests exercise the real tool logic. Scans run against `tmp_path`
fixtures — no real target is ever touched.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Module stubs
# ---------------------------------------------------------------------------

_STUB_SENTINEL = "__guardx_test_stubs_installed__"


def _install_stubs() -> None:
    if getattr(sys, _STUB_SENTINEL, False):
        return
    httpx = types.ModuleType("httpx")

    class RequestError(Exception):
        pass

    class AsyncClient:  # pragma: no cover - replaced by monkeypatching
        def __init__(self, *args, **kwargs):
            raise AssertionError("test must patch httpx.AsyncClient")

    httpx.RequestError = RequestError
    httpx.AsyncClient = AsyncClient
    sys.modules["httpx"] = httpx

    mcp = types.ModuleType("mcp")
    server_pkg = types.ModuleType("mcp.server")
    fastmcp_mod = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, name: str):
            self.name = name

        def tool(self):
            def deco(fn):
                return fn  # FastMCP 1.x returns the function unchanged
            return deco

        def run(self):  # pragma: no cover
            raise AssertionError("tests must not start the server")

    fastmcp_mod.FastMCP = FastMCP
    server_pkg.fastmcp = fastmcp_mod
    mcp.server = server_pkg
    sys.modules["mcp"] = mcp
    sys.modules["mcp.server"] = server_pkg
    sys.modules["mcp.server.fastmcp"] = fastmcp_mod
    setattr(sys, _STUB_SENTINEL, True)


_install_stubs()

_SPEC = importlib.util.spec_from_file_location(
    "guardx_server_iac", str(Path(__file__).resolve().parent.parent / "server.py")
)
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


def _write(tmp_path, name, content):
    fp = tmp_path / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    return str(fp)


TF_DB = (
    'resource "aws_db_instance" "main" {\n'
    '  engine   = "postgres"\n'
    '  username = "admin"\n'
    '  password = "hunter2"\n'
    '}\n'
)


class TestTerraform:
    def test_db_instance_password_flagged_high(self, tmp_path):
        fp = _write(tmp_path, "main.tf", TF_DB)
        report = server.scan_secrets(fp)
        assert "[HIGH] IaC Credential" in report
        assert "HIGH: 1" in report
        assert "hunter2" not in report

    def test_non_sensitive_resource_stays_clean(self, tmp_path):
        # The same assignment in a bucket block is not an IaC finding;
        # the unquoted short value also misses the generic pattern.
        fp = _write(tmp_path, "main.tf",
                    'resource "aws_s3_bucket" "b" {\n'
                    '  bucket   = "mybucket"\n'
                    '  password = "hunter2"\n'
                    '}\n')
        report = server.scan_secrets(fp)
        assert "IaC Credential" not in report
        assert "No hardcoded secrets detected" in report

    def test_context_ends_when_block_closes(self, tmp_path):
        # A credential line after the db block's closing brace must
        # not inherit the block's sensitivity.
        fp = _write(tmp_path, "main.tf", TF_DB +
                    'output "x" {\n'
                    '  password = "hunter2"\n'
                    '}\n')
        report = server.scan_secrets(fp)
        assert report.count("IaC Credential") == 1

    def test_reference_and_placeholder_values_skipped(self, tmp_path):
        fp = _write(tmp_path, "main.tf",
                    'resource "aws_db_instance" "main" {\n'
                    '  password = var.db_password\n'
                    '  username = "admin"\n'
                    '}\n'
                    'resource "aws_rds_cluster" "c" {\n'
                    '  master_password = "example"\n'
                    '}\n'
                    'resource "azurerm_sql_server" "s" {\n'
                    '  administrator_login_password = var.sql_password\n'
                    '}\n')
        assert "No hardcoded secrets detected" in server.scan_secrets(fp)

    def test_azure_sql_camel_and_underscore_keys(self, tmp_path):
        fp = _write(tmp_path, "main.tf",
                    'resource "azurerm_sql_server" "s" {\n'
                    '  administrator_login_password = "hunter2"\n'
                    '}\n')
        assert "[HIGH] IaC Credential" in server.scan_secrets(fp)

    def test_non_credential_keys_stay_clean(self, tmp_path):
        fp = _write(tmp_path, "main.tf",
                    'resource "aws_db_instance" "main" {\n'
                    '  password_length = 16\n'
                    '  secret_santa = "alice"\n'
                    '}\n')
        assert "No hardcoded secrets detected" in server.scan_secrets(fp)

    def test_tfvars_credential_flagged_without_block(self, tmp_path):
        fp = _write(tmp_path, "terraform.tfvars",
                    'db_password = "hunter2"\n')
        assert "[HIGH] IaC Credential" in server.scan_secrets(fp)

    def test_code_file_same_block_not_flagged(self, tmp_path):
        # The IaC heuristic is IaC-files only: a .py file containing
        # the same text gets no IaC finding.
        fp = _write(tmp_path, "main.py", TF_DB)
        assert "IaC Credential" not in server.scan_secrets(fp)


class TestCloudFormationAndArm:
    def test_cfn_rds_master_password_flagged(self, tmp_path):
        fp = _write(tmp_path, "template.yaml",
                    "Resources:\n"
                    "  MyDB:\n"
                    "    Type: AWS::RDS::DBInstance\n"
                    "    Properties:\n"
                    "      MasterUsername: admin\n"
                    "      MasterUserPassword: hunter2\n")
        assert "[HIGH] IaC Credential" in server.scan_secrets(fp)

    def test_cfn_non_sensitive_type_stays_clean(self, tmp_path):
        fp = _write(tmp_path, "template.yaml",
                    "Resources:\n"
                    "  MyBucket:\n"
                    "    Type: AWS::S3::Bucket\n"
                    "    Properties:\n"
                    "      BucketName: mybucket\n"
                    "      password: hunter2\n")
        # A Type line for a non-sensitive resource replaces the
        # context, so no IaC finding; the unquoted value also misses
        # the generic pattern.
        assert "IaC Credential" not in server.scan_secrets(fp)

    def test_arm_sql_server_password_flagged(self, tmp_path):
        fp = _write(tmp_path, "azuredeploy.json",
                    '{\n'
                    '  "type": "Microsoft.Sql/servers",\n'
                    '  "administratorLoginPassword": "hunter2"\n'
                    '}\n')
        assert "[HIGH] IaC Credential" in server.scan_secrets(fp)

    def test_iac_finding_masked_in_json(self, tmp_path):
        import json
        fp = _write(tmp_path, "main.tf", TF_DB)
        data = json.loads(server.scan_secrets(fp, json_output=True))
        assert data["findings"][0]["type"] == "IaC Credential"
        assert data["findings"][0]["severity"] == "HIGH"
        assert "hunter2" not in json.dumps(data)
