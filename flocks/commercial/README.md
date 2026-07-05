# Commercial Policy Module

This package stores local commercial-admin controls in `Storage`; it does not
introduce a separate database.

Key policy surfaces:

- `ConnectivityConfig`: controls outbound access, optional allowed hosts, proxy
  URL, TLS verification, and dedicated server URLs.
- `NotificationPolicy`: controls local, built-in, benefit, whats-new, vendor,
  and announcement notifications.
- `UpdatePolicy`: controls update checks, update application, legacy Flocks
  update sources, update channel, manual approval, and signatures.

Secure defaults:

- outbound access is disabled
- update checks are disabled
- update application is disabled
- legacy Flocks update sources are disabled
- benefit, whats-new, and vendor notifications are disabled

Policy checks that protect network operations live in `policy.py`. WebUI code may
hide disabled actions for usability, but backend update and notification routes
must remain the final enforcement point.
