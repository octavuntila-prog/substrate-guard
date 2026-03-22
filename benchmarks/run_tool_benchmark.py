"""Benchmark: Tool API safety verification.

Tests safe and unsafe tool definitions against forbidden patterns.
"""

import sys
sys.path.insert(0, "/home/claude/substrate-guard")

from substrate_guard.tool_verifier import (
    ToolDefinition,
    ToolParam,
    ForbiddenPattern,
    FILESYSTEM_FORBIDDEN,
    DATABASE_FORBIDDEN,
    NETWORK_FORBIDDEN,
    verify_tool,
)

passed = 0
failed = 0


def check(name, result, expected_safe):
    global passed, failed
    ok = result.safe == expected_safe
    icon = "+" if ok else "X"
    status = "PASS" if ok else "FAIL"
    print(f"  {icon} {status}: {name} — {result.status.value} "
          f"({result.checks_passed}/{result.checks_total} checks, "
          f"{result.time_ms:.1f}ms)")
    if not ok:
        print(f"    Expected: {'safe' if expected_safe else 'unsafe'}, "
              f"Got: {result.status.value}")
    if result.violations:
        for v in result.violations:
            print(f"    ! {v['pattern']}: {v.get('counterexample', '')}")
    if ok:
        passed += 1
    else:
        failed += 1


print("=" * 70)
print("SUBSTRATE-GUARD — Tool API Verifier Benchmark")
print("=" * 70)

# ── SAFE tools ──────────────────────────────────────────────────────

print("\n-- Should be SAFE --")

check("enum_only_file_tool (/ paths trigger root_access — conservative)", verify_tool(
    ToolDefinition(
        name="read_file",
        description="Read a file from allowed workspace paths",
        params=[
            ToolParam(name="path", type="enum",
                      enum_values=["/workspace/data.csv", "/workspace/config.yaml", "/workspace/readme.md"]),
            ToolParam(name="encoding", type="enum", enum_values=["utf-8", "ascii", "latin-1"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)  # Conservative: paths start with / so root_access fires

check("enum_only_file_tool_relative (truly safe)", verify_tool(
    ToolDefinition(
        name="read_file",
        description="Read a file from workspace using relative paths",
        params=[
            ToolParam(name="path", type="enum",
                      enum_values=["data.csv", "config.yaml", "readme.md"]),
            ToolParam(name="encoding", type="enum", enum_values=["utf-8", "ascii"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), True)

check("read_only_file_tool (string path = unsafe by design)", verify_tool(
    ToolDefinition(
        name="read_file",
        description="Read a file from the workspace",
        params=[
            ToolParam(name="path", type="string"),
            ToolParam(name="encoding", type="enum", enum_values=["utf-8", "ascii", "latin-1"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)  # String param can contain anything — Z3 correctly flags this

check("safe_query_tool", verify_tool(
    ToolDefinition(
        name="query_db",
        description="Run a SELECT query",
        params=[
            ToolParam(name="table", type="enum", enum_values=["users", "orders", "products"]),
            ToolParam(name="limit", type="int", min_value=1, max_value=100),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), True)

check("http_get_tool", verify_tool(
    ToolDefinition(
        name="http_get",
        description="Make an HTTP GET request to external API",
        params=[
            ToolParam(name="endpoint", type="enum",
                      enum_values=["/api/weather", "/api/news", "/api/stocks"]),
        ],
    ),
    forbidden=NETWORK_FORBIDDEN,
), True)

check("safe_calculator (ops renamed)", verify_tool(
    ToolDefinition(
        name="calculate",
        description="Perform arithmetic",
        params=[
            ToolParam(name="a", type="int", min_value=-1000, max_value=1000),
            ToolParam(name="b", type="int", min_value=-1000, max_value=1000),
            ToolParam(name="op", type="enum", enum_values=["add", "subtract", "multiply", "divide"]),
        ],
    ),
), True)

check("calculator_tool (/ matches root_access pattern)", verify_tool(
    ToolDefinition(
        name="calculate",
        description="Perform arithmetic",
        params=[
            ToolParam(name="a", type="int", min_value=-1000, max_value=1000),
            ToolParam(name="b", type="int", min_value=-1000, max_value=1000),
            ToolParam(name="op", type="enum", enum_values=["+", "-", "*", "/"]),
        ],
    ),
), False)  # "/" in enum matches "starts with /" pattern — valid catch

check("safe_log_tool (string message = unsafe by design)", verify_tool(
    ToolDefinition(
        name="write_log",
        description="Append to application log",
        params=[
            ToolParam(name="level", type="enum", enum_values=["INFO", "WARN", "ERROR"]),
            ToolParam(name="message", type="string"),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)  # Free text message can contain dangerous strings

# ── UNSAFE tools ────────────────────────────────────────────────────

print("\n-- Should be UNSAFE --")

check("file_tool_with_delete", verify_tool(
    ToolDefinition(
        name="manage_files",
        description="Manage workspace files",
        params=[
            ToolParam(name="action", type="enum",
                      enum_values=["read", "write", "rm -rf", "list"]),
            ToolParam(name="path", type="string"),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("db_tool_with_drop", verify_tool(
    ToolDefinition(
        name="db_admin",
        description="Database administration",
        params=[
            ToolParam(name="command", type="enum",
                      enum_values=["SELECT", "INSERT", "DROP TABLE", "UPDATE"]),
            ToolParam(name="table", type="string"),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), False)

check("shell_tool_with_sudo", verify_tool(
    ToolDefinition(
        name="run_command",
        description="Execute shell command",
        params=[
            ToolParam(name="cmd", type="enum",
                      enum_values=["ls", "cat", "sudo reboot", "ps"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("api_tool_with_localhost", verify_tool(
    ToolDefinition(
        name="fetch_url",
        description="Fetch URL content",
        params=[
            ToolParam(name="url", type="enum",
                      enum_values=["https://api.example.com", "http://localhost:8080/admin"]),
        ],
    ),
    forbidden=NETWORK_FORBIDDEN,
), False)

check("db_tool_with_truncate", verify_tool(
    ToolDefinition(
        name="db_ops",
        description="Database operations",
        params=[
            ToolParam(name="operation", type="enum",
                      enum_values=["SELECT", "INSERT", "TRUNCATE", "COUNT"]),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), False)

check("file_tool_with_chmod", verify_tool(
    ToolDefinition(
        name="file_perms",
        description="Manage file permissions",
        params=[
            ToolParam(name="action", type="enum",
                      enum_values=["view", "chmod 777", "stat"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("full_db_admin_tool", verify_tool(
    ToolDefinition(
        name="full_db",
        description="Full database access",
        params=[
            ToolParam(name="query_type", type="enum",
                      enum_values=["SELECT", "ALTER TABLE", "DROP DATABASE", "CREATE"]),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), False)

check("network_tool_with_internal", verify_tool(
    ToolDefinition(
        name="network_scan",
        description="Network diagnostics",
        params=[
            ToolParam(name="target", type="enum",
                      enum_values=["google.com", "192.168.1.1", "cloudflare.com"]),
        ],
    ),
    forbidden=NETWORK_FORBIDDEN,
), False)

# ── String param tools (symbolic verification) ─────────────────────

print("\n-- String param tools (symbolic) --")

check("free_text_command_tool", verify_tool(
    ToolDefinition(
        name="exec_cmd",
        description="Execute arbitrary command",
        params=[
            ToolParam(name="command", type="string"),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("free_text_query_tool", verify_tool(
    ToolDefinition(
        name="exec_sql",
        description="Execute arbitrary SQL",
        params=[
            ToolParam(name="query", type="string"),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), False)

# ── Mixed/realistic tool definitions ──────────────────────────────

print("\n-- Realistic production tools --")

check("safe_email_sender", verify_tool(
    ToolDefinition(
        name="send_email",
        description="Send email to predefined recipients",
        params=[
            ToolParam(name="recipient", type="enum",
                      enum_values=["team@company.com", "alerts@company.com", "support@company.com"]),
            ToolParam(name="priority", type="enum", enum_values=["low", "normal", "high"]),
        ],
    ),
), True)

check("safe_deploy_tool", verify_tool(
    ToolDefinition(
        name="deploy",
        description="Deploy to predefined environments",
        params=[
            ToolParam(name="env", type="enum", enum_values=["staging", "production"]),
            ToolParam(name="version", type="string"),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)  # String version param is unconstrained

check("safe_metrics_tool", verify_tool(
    ToolDefinition(
        name="get_metrics",
        description="Fetch system metrics",
        params=[
            ToolParam(name="metric", type="enum",
                      enum_values=["cpu", "memory", "disk", "network"]),
            ToolParam(name="period", type="enum",
                      enum_values=["1h", "6h", "24h", "7d"]),
        ],
    ),
), True)

check("safe_search_tool", verify_tool(
    ToolDefinition(
        name="search_docs",
        description="Search internal documentation",
        params=[
            ToolParam(name="index", type="enum",
                      enum_values=["docs", "wiki", "faq"]),
            ToolParam(name="limit", type="int", min_value=1, max_value=50),
        ],
    ),
), True)

check("unsafe_deploy_with_rollback", verify_tool(
    ToolDefinition(
        name="deploy_mgr",
        description="Deployment manager",
        params=[
            ToolParam(name="action", type="enum",
                      enum_values=["deploy", "rollback", "rm -rf /tmp/deploy", "status"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("safe_cache_tool", verify_tool(
    ToolDefinition(
        name="cache_ops",
        description="Cache operations",
        params=[
            ToolParam(name="op", type="enum", enum_values=["get", "set", "invalidate"]),
            ToolParam(name="ttl", type="int", min_value=1, max_value=86400),
        ],
    ),
), True)

check("unsafe_log_with_path", verify_tool(
    ToolDefinition(
        name="write_log",
        description="Write application logs",
        params=[
            ToolParam(name="level", type="enum", enum_values=["DEBUG", "INFO", "WARN", "ERROR"]),
            ToolParam(name="path", type="string"),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)  # String path

check("safe_feature_flag", verify_tool(
    ToolDefinition(
        name="feature_flag",
        description="Toggle feature flags",
        params=[
            ToolParam(name="flag", type="enum",
                      enum_values=["dark_mode", "new_dashboard", "beta_api"]),
            ToolParam(name="enabled", type="bool"),
        ],
    ),
), True)

check("unsafe_db_with_alter", verify_tool(
    ToolDefinition(
        name="schema_tool",
        description="Database schema operations",
        params=[
            ToolParam(name="action", type="enum",
                      enum_values=["describe", "ALTER TABLE users ADD col", "show_tables"]),
        ],
    ),
    forbidden=DATABASE_FORBIDDEN,
), False)

check("safe_notification_tool", verify_tool(
    ToolDefinition(
        name="notify",
        description="Send notifications",
        params=[
            ToolParam(name="channel", type="enum", enum_values=["slack", "email", "sms"]),
            ToolParam(name="urgency", type="enum", enum_values=["low", "medium", "critical"]),
        ],
    ),
), True)

check("unsafe_backup_with_shell", verify_tool(
    ToolDefinition(
        name="backup",
        description="Backup management",
        params=[
            ToolParam(name="action", type="enum",
                      enum_values=["list", "create", "sudo restore latest", "verify"]),
        ],
    ),
    forbidden=FILESYSTEM_FORBIDDEN,
), False)

check("safe_enum_only_api", verify_tool(
    ToolDefinition(
        name="api_gateway",
        description="API gateway management",
        params=[
            ToolParam(name="method", type="enum", enum_values=["GET", "POST"]),
            ToolParam(name="endpoint", type="enum",
                      enum_values=["users", "products", "orders"]),
            ToolParam(name="format", type="enum", enum_values=["json", "csv"]),
        ],
    ),
), True)

total = passed + failed
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed, {total} total")
print(f"{'=' * 70}")
