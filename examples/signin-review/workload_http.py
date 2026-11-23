"""Fixed-endpoint, in-memory workload authentication and HTTP requests."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from candidate_metadata import is_principal_url
from collect import app_id_is_canonical, decode, valid_link
from oidc_claim_check import NoRedirect, check, get_assertion

MAX_PAGE_BYTES = 32 * 1024 * 1024


class HTTPFailure(ValueError):
    def __init__(self, status, retry_after=None):
        super().__init__('HTTP request failed')
        self.status = status
        self.retry_after = retry_after


def request_json(url, *, method='GET', headers=None, data=None, max_bytes=65536):
    request = Request(url, method=method, data=data, headers=headers or {})
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            if response.status != 200:
                raise HTTPFailure(response.status)
            raw = response.read(max_bytes + 1)
    except HTTPError as exc:
        try:
            raise HTTPFailure(exc.code, exc.headers.get('Retry-After')) from None
        finally:
            exc.close()
    except (OSError, URLError):
        raise ValueError('HTTP transport failed') from None
    if len(raw) > max_bytes:
        raise ValueError('HTTP response exceeds its bound')
    return decode(raw)


def delay_for(value, attempt):
    if value is None:
        return 30 * 2**attempt
    if re.fullmatch(r'[0-9]{1,6}', value):
        return int(value)
    try:
        date = parsedate_to_datetime(value)
        return max(0, (date - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Unreadable Graph retry delay') from None


def graph_reader(environment):
    tenant = environment['TF_AUDIT_TENANT_ID']
    client = environment['TF_AUDIT_CLIENT_ID']
    if not all(app_id_is_canonical(value) for value in (tenant, client)):
        raise ValueError('Unexpected workload identifiers')
    assertion, claims = get_assertion(environment)
    if not all(check(claims).values()):
        raise ValueError('Unverified workload subject')
    credentials = request_json(
        f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
        method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data=urlencode({
            'client_id': client, 'grant_type': 'client_credentials', 'scope': 'https://graph.microsoft.com/.default',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': assertion,
        }).encode('ascii'),
    )
    token = credentials.get('access_token') if isinstance(credentials, dict) else None
    if (not isinstance(credentials, dict) or credentials.get('token_type', '').lower() != 'bearer'
            or not isinstance(token, str) or not re.fullmatch(r'[!-~]{1,16384}', token)):
        raise ValueError('Invalid workload token response')
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}

    def get(url):
        if not valid_link(url) and not is_principal_url(url):
            raise ValueError('Unexpected Graph endpoint')
        for attempt in range(3):
            try:
                return request_json(url, headers=headers, max_bytes=MAX_PAGE_BYTES)
            except HTTPFailure as exc:
                if exc.status not in (429, 503) or attempt == 2:
                    raise
                delay = delay_for(exc.retry_after, attempt)
                if delay > 120:
                    raise
                time.sleep(delay)

    return get
