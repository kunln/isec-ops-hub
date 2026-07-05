# Commercial Admin Split

Flocks ships two WebUI access surfaces:

- Frontstage user WebUI: development and preview default to port `8080`.
  Production should expose this surface through reverse proxy or container
  mapping on port `80`.
- Commercial admin WebUI: development, preview, and commercial delivery default
  to port `51174`.

The frontstage bundle registers only user routes. It does not register
`/admin/*` or `/security-admin/*`. The commercial admin bundle registers:

- `/admin` and `/admin/*` for vendor maintenance pages.
- `/security-admin/*` for the security business admin view.

The commercial Admin Console exposes local controls under:

- `/admin/branding`
- `/admin/connectivity`
- `/admin/notifications`
- `/admin/update`
- `/admin/license`
- `/admin/diagnostics`
- `/admin/audit`

All settings are stored through the existing `Storage` layer.

## Build and delivery

Use the split WebUI build targets:

```bash
cd webui
npm run build:frontstage
npm run build:commercial-admin
```

The output directories are:

- `webui/dist-frontstage`
- `webui/dist-commercial-admin`

`scripts/container-start.sh` serves both bundles and proxies `/api` and
`/event` to the backend. A typical production container mapping is:

```bash
docker run -p 8000:8000 -p 80:8080 -p 51174:51174 flocks
```

## Defaults

The commercial defaults are private and local-first:

- `outbound_enabled=false`
- `update_check_enabled=false`
- `update_apply_enabled=false`
- `legacy_flocks_update_sources_enabled=false`
- `benefit_notifications_enabled=false`
- `whats_new_notifications_enabled=false`
- `vendor_notifications_enabled=false`

## Enforcement

The frontend reads commercial policies before calling update or notification
APIs. This prevents disabled update checks and whats-new popups from being
triggered during normal WebUI startup.

The backend is the final enforcement layer:

- `/api/update/check` returns a local disabled result when checks, outbound
  access, or legacy Flocks sources are disabled.
- `/api/update/apply` returns `403` before any download when update application
  or outbound access is disabled.
- `flocks update` uses the same commercial update policy checks as the WebUI
  update route before release API calls or archive downloads.
- Remote MCP connections and MCP package preflight installs are denied before
  opening HTTP/SSE transports or running `npm`/`pip` installers.
- Skill downloads and skill dependency installers are denied before HTTP
  downloads or package-manager subprocesses run.
- Web search/fetch tools, declarative HTTP API tools, provider/API-service
  credential probes, device probes, channel gateway connections, and channel
  outbound delivery all consult `ConnectivityPolicy` server-side.
- First-run vendor onboarding is disabled unless both outbound connectivity
  and `vendor_notifications_enabled` are enabled. When disabled, the WebUI
  hides vendor model recommendations and the backend rejects ThreatBook
  onboarding validation/apply requests before running any vendor checks.
- `NotificationService.list_active()` filters built-in, benefit, whats-new,
  vendor, and announcement notifications by `NotificationPolicy`.
- `/api/notifications/{id}/ack` remains available, but disabled notifications
  are not returned by the active list.

## Commercial admin authentication

Commercial admin authentication uses dedicated backend endpoints:

- `/api/commercial-admin/auth/login`
- `/api/commercial-admin/auth/me`
- `/api/commercial-admin/auth/logout`

Successful login writes a separate HttpOnly cookie. The fixed commercial
admin credential is backend-only configuration and must not be copied into
frontend source or build output.

## Admin operations

The Admin Console writes the three primary policy groups through these APIs:

- `/api/commercial/connectivity` controls outbound connectivity, host
  allowlists, proxy, TLS verification, and service URLs.
- `/api/commercial/notification-policy` controls local, built-in, benefit,
  whats-new, vendor, and announcement notifications.
- `/api/commercial/update-policy` controls update checks, update application,
  legacy Flocks update sources, manual approval, offline package imports,
  signatures, and rollback.

The UI is localized through the existing WebUI i18n resources. User-facing
commercial Admin and Security pages must use translation namespaces rather
than hard-coded Chinese or English copy.

## Local delivery commands

For local commercial delivery validation, issue a temporary license without
contacting any remote license server:

```bash
flocks commercial issue-temp-license --days 30 --licensed-to "Local Commercial Evaluation"
```

The command writes to the active `Storage` location. When a dev or demo server
uses a custom root, run the command with the same environment, for example:

```bash
FLOCKS_ROOT=/path/to/flocks-root flocks commercial issue-temp-license --days 30
```

To permit a third-party model provider while keeping outbound access scoped,
add only the provider host to the allowlist:

```bash
flocks commercial allow-host api.minimax.chat
```

This sets `outbound_enabled=true` and preserves the host allowlist boundary.
Update checks, update application, telemetry, vendor onboarding, and built-in
notifications remain disabled unless their own policy switches are enabled.

Use this command to inspect the effective local state:

```bash
flocks commercial status
```

When `allowed_hosts` is non-empty, commercial updater network calls are limited
to matching hosts. Exact hosts and `*.example.com` wildcard suffix rules are
supported. Loopback URLs (`localhost`, `127.0.0.1`, `::1`) are treated as local
service traffic rather than external outbound traffic. Outbound actions without
a verifiable URL, such as package-manager installs or channel SDK connections,
are denied in host allowlist mode unless the call site can provide a target URL.

Denied outbound attempts are recorded in the commercial audit log as
`commercial.outbound.denied` when the `Storage` layer is initialized.

## Acceptance checklist

- A fresh default install does not call update release APIs, show benefit
  reminders, show vendor onboarding recommendations, or start external update
  downloads.
- Update checks run only after `outbound_enabled`,
  `update_check_enabled`, and `legacy_flocks_update_sources_enabled` are all
  enabled.
- Update application starts only after `outbound_enabled`,
  `update_apply_enabled`, and `legacy_flocks_update_sources_enabled` are all
  enabled.
- Benefit, whats-new, vendor, and built-in notifications are hidden unless the
  corresponding notification policy permits them.
- Admin and Security pages render correctly in `zh-CN` and `en-US`, without
  raw i18n keys or user-visible hard-coded copy.
- Rejected outbound attempts appear in commercial audit logs with the denied
  target and purpose.

## Suggested verification

- Backend: run the commercial, update-policy, and notifications route tests.
- Frontend: run the Layout and Admin Console tests, then build both WebUI
  bundles.
- Browser smoke: verify frontstage user routes on `8080`, verify commercial
  admin login and `/admin`, `/admin/connectivity`, `/admin/notifications`,
  `/admin/update`, `/admin/audit`, and `/security-admin/assets` on `51174` in
  Chinese and English.
