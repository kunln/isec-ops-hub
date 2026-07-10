"""Backward-compatible test module for connector run history APIs.

The implementation lives in test_connector_sync_runs; this module keeps the
requested connector-runs test command available while the API remains at
/api/security/connector-runs.
"""

from tests.security.test_connector_sync_runs import *  # noqa: F401,F403
