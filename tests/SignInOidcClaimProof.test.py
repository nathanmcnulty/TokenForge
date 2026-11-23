from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
import oidc_claim_check as proof


class ClaimProofTests(unittest.TestCase):
    def test_exact_dispatch_context(self):
        env = {'GITHUB_REPOSITORY': 'nathanmcnulty/TokenForge', 'GITHUB_REPOSITORY_ID': '1402673320',
               'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_RUN_ID': '1234', 'GITHUB_RUN_ATTEMPT': '1'}
        proof.run_scope(env)
        for patch_value in ({'GITHUB_EVENT_NAME': 'schedule'}, {'GITHUB_REF': 'refs/tags/main'},
                            {'GITHUB_REPOSITORY_ID': '1'}, {'GITHUB_RUN_ATTEMPT': '0'}):
            with self.assertRaises(ValueError):
                proof.run_scope(env | patch_value)

    def test_claims_exact_and_results_boolean_only(self):
        claims = {'iss': 'https://token.actions.githubusercontent.com', 'aud': 'api://AzureADTokenExchange',
                  'sub': 'repo:nathanmcnulty@6653432/TokenForge@1402673320:environment:entra-audit',
                  'repository': 'nathanmcnulty/TokenForge', 'repository_id': '1402673320',
                  'repository_owner_id': '6653432', 'ref': 'refs/heads/main', 'environment': 'entra-audit',
                  'workflow_ref': 'nathanmcnulty/TokenForge/.github/workflows/signin-review-candidates.yml@refs/heads/main'}
        self.assertTrue(all(proof.check(claims | {'irrelevant': 'private-canary'}).values()))
        for key in claims:
            matches = proof.check(claims | {key: 'private-canary'})
            self.assertEqual(set(matches), set(claims))
            self.assertFalse(matches[key])
            self.assertTrue(all(type(value) is bool for value in matches.values()))

    def test_foreign_origin_and_wrong_audience_query_stop_before_request(self):
        candidates = ('https://actions.githubusercontent.com.example.invalid/',
                      'https://worker.actions.githubusercontent.com/path?audience=wrong',
                      'https://worker.actions.githubusercontent.com:8443/path',
                      'https://user@worker.actions.githubusercontent.com/path')
        with patch.object(proof, 'build_opener') as opener:
            for url in candidates:
                with self.assertRaises(ValueError):
                    proof.get_claims({'ACTIONS_ID_TOKEN_REQUEST_URL': url})
            opener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
