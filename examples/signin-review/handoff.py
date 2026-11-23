"""Offline fixed-size age transport for candidate envelopes."""

import os
import re
import subprocess

from collect import EVENTS, WORKFLOW_REF
from report import validate_handoff

MAX_PAYLOAD = 65536
FRAME_BYTES = MAX_PAYLOAD + 4
AGE_HEADER = b'age-encryption.org/v1\n-> X25519 '
MAX_CIPHERTEXT = FRAME_BYTES + 1024
BECH32 = '023456789acdefghjklmnpqrstuvwxyz'


def age(arguments, data, max_output, pass_fds=()):
    try:
        result = subprocess.run(
            ['age', *arguments], input=data, capture_output=True, timeout=20,
            env={'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C'}, pass_fds=pass_fds,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError('Candidate encryption operation failed') from None
    if result.returncode or not result.stdout or len(result.stdout) > max_output:
        raise ValueError('Candidate encryption operation failed')
    return result.stdout


def seal(raw, environment, recipient, *, workflow_ref=WORKFLOW_REF, categories=EVENTS):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PAYLOAD:
        raise ValueError('Invalid candidate envelope size')
    validate_handoff(raw, environment, workflow_ref=workflow_ref, categories=categories)
    if not isinstance(recipient, str) or not re.fullmatch(f'age1[{BECH32}]{{58}}', recipient):
        raise ValueError('Expected one native age X25519 recipient')
    frame = len(raw).to_bytes(4, 'big') + raw.ljust(MAX_PAYLOAD, b'\x00')
    return age(['--encrypt', '--recipient', recipient], frame, MAX_CIPHERTEXT)


def open_envelope(ciphertext, environment, identity, *, workflow_ref=WORKFLOW_REF, categories=EVENTS):
    if (not isinstance(ciphertext, bytes) or not FRAME_BYTES < len(ciphertext) <= MAX_CIPHERTEXT
            or not ciphertext.startswith(AGE_HEADER)):
        raise ValueError('Invalid encrypted candidate envelope')
    if not isinstance(identity, str) or not re.fullmatch(f'AGE-SECRET-KEY-1[{BECH32.upper()}]{{58}}', identity):
        raise ValueError('Expected one native age X25519 identity')
    read_fd, write_fd = os.pipe()
    try:
        try:
            os.write(write_fd, (identity + '\n').encode('ascii'))
        finally:
            os.close(write_fd)
        frame = age(['--decrypt', '--identity', f'/proc/self/fd/{read_fd}'], ciphertext, FRAME_BYTES, (read_fd,))
    finally:
        os.close(read_fd)
    if len(frame) != FRAME_BYTES:
        raise ValueError('Invalid decrypted candidate frame')
    length = int.from_bytes(frame[:4], 'big')
    if not 0 < length <= MAX_PAYLOAD or any(frame[4 + length:]):
        raise ValueError('Invalid decrypted candidate frame')
    raw = frame[4:4 + length]
    validate_handoff(raw, environment, workflow_ref=workflow_ref, categories=categories)
    return raw
