"""Read an exact TokenForge catalog commit without Git transport."""

import json
import os
import re
import subprocess
import uuid


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def app_id_is_canonical(value):
    if not isinstance(value, str):
        return False
    try:
        app = uuid.UUID(value)
    except ValueError:
        return False
    return app.int != 0 and str(app) == value


class OfflineCatalog:
    def __init__(self, repo, commit):
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('Use the full published catalog commit ID')
        self.commit = commit
        self.git = ['git', '--no-replace-objects', '-c', 'protocol.allow=never', '-C', str(repo)]
        self.environment = {**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': '', 'GIT_TERMINAL_PROMPT': '0'}
        if self._read('cat-file', '-t', commit).strip() != b'commit':
            raise ValueError('The pinned catalog object must be a Git commit')

    def _read(self, *command):
        try:
            return subprocess.check_output([*self.git, *command], env=self.environment,
                                           stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.CalledProcessError as exc:
            raise ValueError('Pinned catalog objects must be available locally') from exc

    def partition(self, verified):
        path = 'applications.json' if verified else 'applications.non-verified.json'
        expected_format = 'TokenForgeApplicationMetadata' if verified else 'TokenForgeNonVerifiedApplications'
        schema_version = 2 if verified else 1
        document = decode(self._read('cat-file', 'blob', self.commit + ':' + path))
        if document.get('Format') != expected_format or document.get('SchemaVersion') != schema_version:
            raise ValueError('Unsupported verified catalog format' if verified else 'Unsupported non-verified catalog format')
        return document

    @staticmethod
    def app_ids(verified, excluded):
        if not isinstance(verified, dict) or not isinstance(excluded, dict):
            raise ValueError('Invalid catalog partitions')
        if verified.keys() & excluded.keys():
            raise ValueError('Published catalog partitions overlap')
        ids = verified.keys() | excluded.keys()
        if not all(app_id_is_canonical(key) for key in ids):
            raise ValueError('Noncanonical ID in published catalog partitions')
        return ids
