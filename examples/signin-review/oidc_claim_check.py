"""Check the expected GitHub OIDC claims in memory, before Azure login."""

import base64
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = "nathanmcnulty/TokenForge"
REPOSITORY_ID = "1402673320"
OWNER_ID = '6653432'
ENVIRONMENT = 'entra-audit'
ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'api://AzureADTokenExchange'
SUBJECT = f'repo:nathanmcnulty@{OWNER_ID}/TokenForge@{REPOSITORY_ID}:environment:{ENVIRONMENT}'
WORKFLOW = f'{REPOSITORY}/.github/workflows/signin-review-candidates.yml@refs/heads/main'


def run_scope(environment):
    if (environment.get('GITHUB_REPOSITORY'), environment.get('GITHUB_REPOSITORY_ID'),
            environment.get('GITHUB_REF'), environment.get('GITHUB_EVENT_NAME')) != (
            REPOSITORY, REPOSITORY_ID, 'refs/heads/main', 'workflow_dispatch'):
        raise ValueError('Unexpected repository, ref or event')
    if not re.fullmatch(r'[1-9][0-9]{0,19}', environment.get('GITHUB_RUN_ID', '')):
        raise ValueError('Unexpected run identity')
    if not re.fullmatch(r'[1-9][0-9]{0,9}', environment.get('GITHUB_RUN_ATTEMPT', '')):
        raise ValueError('Unexpected run attempt')


def check(claims):
    expected = {'iss': ISSUER, 'aud': AUDIENCE, 'sub': SUBJECT, 'repository': REPOSITORY,
                'repository_id': REPOSITORY_ID, 'repository_owner_id': OWNER_ID,
                'ref': 'refs/heads/main', 'environment': ENVIRONMENT, 'workflow_ref': WORKFLOW}
    return {name: claims.get(name) == match for name, match in expected.items()}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_claims(environment):
    url = urlsplit(environment['ACTIONS_ID_TOKEN_REQUEST_URL'])
    if (url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com')
            or url.username or url.password or url.port not in (None, 443) or url.fragment):
        raise ValueError('Unexpected GitHub token endpoint')
    args = parse_qsl(url.query, keep_blank_values=True)
    if any(name == 'audience' for name, _ in args):
        raise ValueError('Unexpected existing audience parameter')
    args.append(('audience', AUDIENCE))
    request = Request(urlunsplit(url._replace(query=urlencode(args))),
                      headers={'Authorization': 'Bearer ' + environment['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with build_opener(NoRedirect()).open(request, timeout=15) as response:
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError('Token response too large')
    value = json.loads(body)['value']
    if not isinstance(value, str):
        raise ValueError('Unexpected OIDC token shape')
    head, payload, signature = value.split('.')
    if not head or not payload or not signature:
        raise ValueError('Unexpected OIDC token shape')
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    if not isinstance(claims, dict):
        raise ValueError('Unexpected OIDC claim shape')
    return claims


if __name__ == '__main__':
    try:
        run_scope(os.environ)
        match = check(get_claims(os.environ))
        print(json.dumps(match, sort_keys=True))
        if not all(match.values()):
            sys.exit('GitHub OIDC claims did not match the reviewed trust.')
    except (KeyError, ValueError, OSError, TypeError):
        sys.exit('Could not verify expected GitHub OIDC claims.')
