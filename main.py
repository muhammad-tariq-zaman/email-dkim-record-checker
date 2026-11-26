"""Parse and check DKIM TXT records for weak keys.

Usage: python3 main.py records.txt
Each non-empty, non-comment line of records.txt is
"selector<TAB>record", e.g.
"s1._domainkey.example.com<TAB>v=DKIM1; k=rsa; p=MIGfMA0G...".
For each record this parses the tags and checks the public
key: the RSA modulus bit length is read from the DER-encoded
public key (not guessed from the base64 length), and Ed25519
keys are 256-bit by design. Verdicts:
- OK: a usable key of an accepted type (rsa or ed25519),
  RSA 1024 bits or more (2048+ recommended; a 1024-bit key is
  reported as OK with a note to consider 2048).
- WEAK: no public key, an unparseable key, an unsupported key
  type, or an RSA key under 1024 bits.
WEAK first, then OK; within a verdict by selector. Lines with
no record part, or with a record that has no tags at all, are
reported as skipped, not silently dropped.
"""
import argparse, base64, binascii, sys

RSA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
ED25519_OID = bytes([0x2B, 0x65, 0x70])
MIN_RSA_BITS = 1024
RECOMMENDED_RSA_BITS = 2048

def _read_tlv(data, pos):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    value = data[pos:pos + length]
    return tag, value, pos + length

def _key_bits(der):
    """Return (key_type, bits) for a DER SubjectPublicKeyInfo, or None."""
    try:
        _tag, outer, _ = _read_tlv(der, 0)
        _tag, alg_seq, rest = _read_tlv(outer, 0)
        _tag, oid, _ = _read_tlv(alg_seq, 0)
        _tag, bitstring, _ = _read_tlv(outer, rest)
        if not bitstring or bitstring[0] != 0:
            return None
        key_bytes = bitstring[1:]
        if oid == RSA_OID:
            _tag, inner, _ = _read_tlv(key_bytes, 0)
            _tag, modulus, _ = _read_tlv(inner, 0)
            stripped = modulus.lstrip(b"\x00")
            if not stripped:
                return None
            bits = (len(stripped) - 1) * 8 + stripped[0].bit_length()
            return ("rsa", bits)
        if oid == ED25519_OID:
            return ("ed25519", len(key_bytes) * 8)
        return None
    except (IndexError, ValueError):
        return None

def _parse_record(text):
    tags = {}
    for part in text.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags

def check(lines):
    out = []
    skipped = 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            selector, record = line.split("\t", 1)
            selector = selector.strip()
            record = record.strip()
        else:
            selector, record = "default", line
        tags = _parse_record(record)
        if not tags:
            skipped += 1
            continue
        key_type = tags.get("k", "rsa").lower()
        flags = tags.get("t", "")
        p = tags.get("p", "")
        if not p:
            out.append((selector, "WEAK", "no public key (p=) present"))
            continue
        try:
            der = base64.b64decode(p, validate=True)
        except (binascii.Error, ValueError):
            out.append((selector, "WEAK", "public key is not valid base64"))
            continue
        parsed = _key_bits(der)
        if parsed is None:
            out.append((selector, "WEAK", f"unsupported key type ({key_type}) or unparseable key"))
            continue
        actual_type, bits = parsed
        if actual_type == "rsa" and bits < MIN_RSA_BITS:
            detail = f"rsa {bits}-bit key - below {MIN_RSA_BITS}-bit minimum"
        elif actual_type == "rsa" and bits < RECOMMENDED_RSA_BITS:
            detail = f"rsa {bits}-bit key - ok, consider {RECOMMENDED_RSA_BITS}-bit"
        else:
            detail = f"{actual_type} {bits}-bit key"
        if flags:
            detail += f", flags t={flags}"
        verdict = "WEAK" if (actual_type == "rsa" and bits < MIN_RSA_BITS) else "OK"
        out.append((selector, verdict, detail))
    order = {"WEAK": 0, "OK": 1}
    out.sort(key=lambda r: (order[r[1]], r[0]))
    return out, skipped

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    args = parser.parse_args(argv)
    with open(args.path, encoding="utf-8") as f:
        results, skipped = check(f.readlines())
    for selector, verdict, detail in results:
        print(f"{selector}: {verdict} - {detail}")
    counts = {v: sum(1 for _, verdict, _ in results if verdict == v)
              for v in ("WEAK", "OK")}
    print(f"{counts['OK']} ok, {counts['WEAK']} weak out of "
          f"{len(results)} DKIM record(s).")
    if skipped:
        print(f"Skipped {skipped} invalid line(s).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
