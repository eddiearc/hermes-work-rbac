# Hermes Work RBAC

Owner/guest RBAC for Hermes file and execution tools, with a small dashboard editor and optional guest conversation reporting.

## Install

```bash
hermes plugins install eddiearc/hermes-work-rbac --enable
hermes gateway restart
```

Then create a policy file:

```bash
cp ~/.hermes/plugins/work-rbac/examples/rbac_policy.yaml.example ~/.hermes/rbac_policy.yaml
```

Open the Hermes dashboard and visit **Work RBAC** to view or edit the YAML.

## Policy Model

The policy is intentionally allow-list based:

- `allowed_tools` controls which Hermes tools a role can call.
- `read_roots` limits `read_file` and `search_files`.
- `write_roots` limits `write_file` and `patch`, but only after those tools are explicitly allowed.
- Unknown tools are denied unless the role has `allowed_tools: ["*"]`.

Typical setup:

- `owner`: `allowed_tools: ["*"]`, read/write `/`.
- `guest`: only `read_file` and `search_files`, limited to a shared directory.

## Feishu IDs

For Feishu:

- `ou_...` is a user ID. Use this under `users` to assign a role.
- `oc_...` is a chat/channel ID. Use this under `reporting.send_to` for guest summaries.

The easiest workflow is to ask an agent to update the Work RBAC policy from logs and natural language, then use the dashboard page to review the final YAML.

Example request:

```text
帮我修改 Hermes 的 Work RBAC 插件配置，把张三设为 owner；李四这类访客只能读 /path/to/shared；访客只能使用 read_file 和 search_files；访客会话总结发到我的 Feishu DM。
```

## Dashboard

This plugin includes a dashboard tab at `/work-rbac`.

The dashboard plugin consists of:

- `dashboard/manifest.json`
- `dashboard/index.js`
- `dashboard/api.py`

The JS bundle calls `window.__HERMES_PLUGINS__.register("work-rbac", WorkRbacPage)`, which is the dashboard plugin registration protocol expected by Hermes.

## Environment Variables

Optional overrides:

- `HERMES_RBAC_POLICY`: policy path, defaults to `~/.hermes/rbac_policy.yaml`
- `HERMES_RBAC_AUDIT_LOG`: audit log path, defaults to `~/.hermes/rbac_audit.log`
- `HERMES_BIN`: command used for sending reports, defaults to `hermes` from `PATH`

## Development

```bash
python -m py_compile __init__.py dashboard/api.py
node --check dashboard/index.js
```

After editing the installed plugin:

```bash
hermes gateway restart
```
