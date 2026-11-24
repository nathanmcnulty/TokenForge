"""One fixed directory-audit validation with no public tenant-derived output."""

from datetime import datetime, timezone
from hashlib import sha256
import os

from collect import app_id_is_canonical, pinned_catalog_app_ids
from directory_provisioning import scan_window
from oidc_claim_check import WORKFLOW, run_scope
from workload_http import graph_reader

# Bind both existing environment identifiers without committing their values.
EXPECTED_WORKLOAD = 'd8d313beb1abc1947541401bdee343f8709d3bafb83d3773adb25ae18915da53'
SINCE = datetime.fromisoformat('2026-11-24T01:00:00Z')
UNTIL = datetime.fromisoformat('2026-11-24T02:00:00Z')
MAX_PAGES = 5
PASSED = 'Directory audit validation passed.'
INCOMPLETE = 'Directory audit validation incomplete.'


def validate(env):
    run_scope(env)
    if (env.get('GITHUB_WORKFLOW_REF'), env.get('TF_VALIDATION_MODE')) != (WORKFLOW, 'directory-validation'):
        raise ValueError('Unexpected workflow or dispatch mode')
    if any(key in ('GH_TOKEN', 'GITHUB_TOKEN') or key.startswith(('TF_HANDOFF_', 'TF_REVIEW_')) for key in env):
        raise ValueError('Unexpected issue or handoff configuration')
    identifiers = [env['TF_AUDIT_TENANT_ID'], env['TF_AUDIT_CLIENT_ID']]
    if (not all(app_id_is_canonical(value) for value in identifiers) or
            sha256(':'.join(identifiers).encode('ascii')).hexdigest() != EXPECTED_WORKLOAD):
        raise ValueError('Unexpected workload identity')
    if UNTIL > datetime.now(timezone.utc):
        raise ValueError('Validation window has not ended')

    known = pinned_catalog_app_ids()
    get = graph_reader(env, directory_only=True)
    _, observed = scan_window(get, SINCE, UNTIL, max_pages=MAX_PAGES)
    if not observed.intersection(known):
        raise ValueError('Expected a published AppId in a terminal directory window')


def main():
    try:
        validate(os.environ)
    except Exception:
        # This command runs in public CI. Parser and transport exceptions can contain provider input.
        raise SystemExit(INCOMPLETE) from None
    print(PASSED)


if __name__ == '__main__':
    main()
