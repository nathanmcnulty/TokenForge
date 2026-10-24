"""Synthetic characterization only: demonstrate unvalidated original-ZIP bytes.

No fixture contains credentials. These are known unsafe acceptances, not a privacy
acceptance gate. Keep artifacts in the test's private temporary directory.
"""
import io
from pathlib import Path
import struct
import sys
import zipfile

MARKER = b"SYNTHETIC_METADATA_MARKER"


def mutate(raw, case):
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("fixture bound")
    if case == "baseline-dotnet":
        return raw
    if case in ("archive-comment", "entry-comment", "local-and-central-extra"):
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, "w") as target:
            for i, entry in enumerate(source.infolist()):
                if i == 0 and case == "entry-comment":
                    entry.comment = MARKER
                if i == 0 and case == "local-and-central-extra":
                    entry.extra = struct.pack("<HH", 0xCAFE, len(MARKER)) + MARKER
                target.writestr(entry, source.read(entry))
            if case == "archive-comment":
                target.comment = MARKER
        return output.getvalue()
    end = raw.rfind(b"PK\x05\x06")
    if end < 0:
        raise ValueError("fixture EOCD")
    central = struct.unpack_from("<I", raw, end + 16)[0]
    if case == "appended-bytes":
        return raw + MARKER
    if case == "prepended-unadjusted":
        return MARKER + raw
    if case in ("prepended-adjusted", "gap-before-central-directory"):
        insertion = 0 if case == "prepended-adjusted" else central
        value = bytearray(raw[:insertion] + MARKER + raw[insertion:])
        new_end = end + len(MARKER)
        new_central = central + len(MARKER)
        struct.pack_into("<I", value, new_end + 16, new_central)
        if insertion == 0:
            pos = new_central
            while pos < new_end:
                if value[pos:pos + 4] != b"PK\x01\x02":
                    raise ValueError("fixture central entry")
                offset = struct.unpack_from("<I", value, pos + 42)[0]
                struct.pack_into("<I", value, pos + 42, offset + len(MARKER))
                lengths = struct.unpack_from("<HHH", value, pos + 28)
                pos += 46 + sum(lengths)
        return bytes(value)
    if case == "gap-before-end-record":
        return raw[:end] + MARKER + raw[end:]
    raise ValueError("fixture case")


if __name__ == "__main__":
    source, target, case = sys.argv[1:]
    value = mutate(Path(source).read_bytes(), case)
    with open(target, "xb") as output:
        output.write(value)
