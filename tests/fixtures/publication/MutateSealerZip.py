"""Synthetic hostile ZIP mutations for complete-original safety regressions.

No fixture contains credentials. Keep artifacts in the test's private temporary directory.
"""
import io
from pathlib import Path
import struct
import sys
import zipfile
import zlib
import warnings
warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)

MARKER = b"SYNTHETIC_METADATA_MARKER"


def canonical_from_directory(directory, official=False, order=None):
    """Independent reference encoder; does not call the production formatter."""
    names = ("coverage.json", "flows.json", "manifest.json", "recipe.json", "review.md", "scopes.json", "validation.json")
    if order is not None:
        if len(order) != 7 or set(order) != set(names):
            raise ValueError("seven-name permutation required")
        names = tuple(order)
    result = bytearray()
    records = []
    for name in names:
        payload = (Path(directory) / name).read_bytes()
        encoded = name.encode("ascii")
        crc = zlib.crc32(payload)
        offset = len(result)
        result += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 8 if official else 2048, 0, 0, 33,
                              0 if official else crc, 0 if official else len(payload),
                              0 if official else len(payload), len(encoded), 0)
        result += encoded + payload
        if official:
            result += struct.pack("<IIII", 0x08074B50, crc, len(payload), len(payload))
        records.append((encoded, crc, len(payload), offset))
    central = len(result)
    for name, crc, size, offset in records:
        result += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 813 if official else 788,
                              20, 8 if official else 2048, 0, 0, 33, crc, size, size,
                              len(name), 0, 0, 0, 0, 0x81800020 if official else 0, offset)
        result += name
    length = len(result) - central
    result += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 7, 7, length, central, 0)
    return bytes(result)


def mutate(raw, case):
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("fixture bound")
    if case in ("baseline-dotnet", "baseline-canonical"):
        return raw
    if case in ("archive-comment", "entry-comment", "local-and-central-extra", "deflate", "zip64-extra", "reordered", "duplicate-record"):
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, "w") as target:
            entries = source.infolist()
            if case == "reordered":
                entries.reverse()
            if case == "duplicate-record":
                entries[1] = entries[0]
            for i, entry in enumerate(entries):
                content = source.read(entry)
                if i == 0 and case == "entry-comment":
                    entry.comment = MARKER
                if i == 0 and case == "local-and-central-extra":
                    entry.extra = struct.pack("<HH", 0xCAFE, len(MARKER)) + MARKER
                if i == 0 and case == "zip64-extra":
                    entry.extra = struct.pack("<HHQQ", 1, 16, len(content), len(content))
                if case == "deflate":
                    entry.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(entry, content)
            if case == "archive-comment":
                target.comment = MARKER
        return output.getvalue()
    end = raw.rfind(b"PK\x05\x06")
    if end < 0:
        raise ValueError("fixture EOCD")
    central = struct.unpack_from("<I", raw, end + 16)[0]
    if case == "central-reordered":
        records = []
        pos = central
        while pos < end:
            if raw[pos:pos + 4] != b"PK\x01\x02":
                raise ValueError("fixture central directory")
            length = 46 + sum(struct.unpack_from("<HHH", raw, pos + 28))
            records.append(raw[pos:pos + length])
            pos += length
        return raw[:central] + b"".join(reversed(records)) + raw[end:]
    patches = {"local-crc": 14, "central-crc": central + 16,
               "local-size": 18, "central-size": central + 20,
               "local-name": 30, "central-name": central + 46,
               "offset": central + 42, "timestamp": 10,
               "attributes": central + 38}
    descriptor = 30 + struct.unpack_from("<H", raw, 26)[0] + struct.unpack_from("<H", raw, 28)[0] + struct.unpack_from("<I", raw, central + 24)[0]
    patches.update({"descriptor-signature": descriptor, "descriptor-crc": descriptor + 4,
                    "descriptor-size": descriptor + 8})
    if case in patches:
        value = bytearray(raw)
        value[patches[case]] ^= 1
        return bytes(value)
    if case in ("encryption", "descriptor", "unsupported-method"):
        value = bytearray(raw)
        if case == "unsupported-method":
            struct.pack_into("<H", value, 8, 99)
            struct.pack_into("<H", value, central + 10, 99)
        else:
            flag = 1 if case == "encryption" else 8
            struct.pack_into("<H", value, 6, struct.unpack_from("<H", value, 6)[0] | flag)
            struct.pack_into("<H", value, central + 8, struct.unpack_from("<H", value, central + 8)[0] | flag)
        return bytes(value)
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
    modes = ("canonical-from-directory", "official-from-directory", "official-reversed-from-directory")
    reverse = ["validation.json", "scopes.json", "review.md", "recipe.json", "manifest.json", "flows.json", "coverage.json"]
    value = canonical_from_directory(source, official=(case != "canonical-from-directory"), order=reverse if case == "official-reversed-from-directory" else None) if case in modes else mutate(Path(source).read_bytes(), case)
    with open(target, "xb") as output:
        output.write(value)
