import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
import base64
from main import check, _key_bits

RSA_2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzuOPqTOcpwg6ulSBZ0XAcMPugSeHljQE9F6WWPdr+hFdVEa5K0a8MA+HGM0m2ZFKDWAGWy/ZvKl5PtZLx5xzl+X+/wD5qIlV53b1/Xh1zfnrO9qL+x44bPns4LYqgnzvsAfxE/sWUlyzfAxEmvV9Vg2kA0GOYfIuTFJHifG+f1FgWrRrlBW8CMCP5XWk4+YGjPANwVsOO179CrhcRDc1rBRDfSnecSl9k/FWSHm6FBGfssme9MsBdNf1AVUTUDxJl2zTGMmFEc3ZS/aNT6HwrwwCOggazfrgnMF/wJ+ENTeFfpHFyUOupsk7EhwDg6bqT0zNJ2+WXvkawQyAE8bDZQIDAQAB"
RSA_512 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOSYPlX6KOocD2ryI2i+Yp+9bDYNS6cRECZLa9RFCo+W6c092Ouo19ehD5gsyk+G9fqc3UiyTaj68SZLxw3q2mkCAwEAAQ=="
ED = "MCowBQYDK2VwAyEAsjcCPjCeHTCDKbvOyoG/pyh2tlgVtwqOCeIFmkn/9Lk="

def _der_len(n):
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body

def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value

def _spki_rsa(modulus_bits):
    """Build a DER SubjectPublicKeyInfo with an RSA modulus of the
    requested bit length (test helper; the modulus is synthetic)."""
    modulus = (1 << (modulus_bits - 1)) | 1
    mod_bytes = modulus.to_bytes((modulus_bits + 7) // 8, "big")
    modulus_int = _tlv(0x02, b"\x00" + mod_bytes)
    exponent_int = _tlv(0x02, b"\x01\x00\x01")
    inner = _tlv(0x30, modulus_int + exponent_int)
    oid = _tlv(0x06, bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]))
    alg = _tlv(0x30, oid + _tlv(0x05, b""))
    bitstring = _tlv(0x03, b"\x00" + inner)
    return base64.b64encode(_tlv(0x30, alg + bitstring)).decode()

class TestDkimChecker(unittest.TestCase):
    def test_real_2048_bit_rsa_is_ok(self):
        r, _ = check([f"s1\tv=DKIM1; k=rsa; p={RSA_2048}"])
        self.assertEqual(r[0][1], "OK")
        self.assertIn("rsa 2048-bit key", r[0][2])

    def test_real_512_bit_rsa_is_weak(self):
        r, _ = check([f"s2\tv=DKIM1; k=rsa; p={RSA_512}"])
        self.assertEqual(r[0][1], "WEAK")
        self.assertIn("512-bit key - below 1024-bit minimum", r[0][2])

    def test_ed25519_is_ok(self):
        r, _ = check([f"s3\tv=DKIM1; k=ed25519; p={ED}"])
        self.assertEqual(r[0][1], "OK")
        self.assertIn("ed25519 256-bit key", r[0][2])

    def test_1024_bit_boundary_is_ok_with_note(self):
        p = _spki_rsa(1024)
        r, _ = check([f"s4\tv=DKIM1; k=rsa; p={p}"])
        self.assertEqual(r[0][1], "OK")
        self.assertIn("consider 2048-bit", r[0][2])

    def test_1023_bit_is_weak(self):
        p = _spki_rsa(1023)
        r, _ = check([f"s5\tv=DKIM1; k=rsa; p={p}"])
        self.assertEqual(r[0][1], "WEAK")

    def test_key_bits_parser(self):
        self.assertEqual(_key_bits(base64.b64decode(RSA_2048)), ("rsa", 2048))
        self.assertEqual(_key_bits(base64.b64decode(RSA_512)), ("rsa", 512))
        self.assertEqual(_key_bits(base64.b64decode(ED)), ("ed25519", 256))

    def test_missing_p_is_weak(self):
        r, _ = check(["s6\tv=DKIM1; k=rsa"])
        self.assertEqual(r[0][1], "WEAK")
        self.assertIn("no public key", r[0][2])

    def test_bad_base64_is_weak(self):
        r, _ = check(["s7\tv=DKIM1; k=rsa; p=!!!not-base64!!!"])
        self.assertEqual(r[0][1], "WEAK")

    def test_testing_flag_is_noted(self):
        r, _ = check([f"s8\tv=DKIM1; k=rsa; t=y; p={RSA_2048}"])
        self.assertEqual(r[0][1], "OK")
        self.assertIn("t=y", r[0][2])

    def test_weak_comes_first(self):
        r, _ = check([f"aaa\tv=DKIM1; k=rsa; p={RSA_2048}",
                      f"zzz\tv=DKIM1; k=rsa; p={RSA_512}"])
        self.assertEqual(r[0][0], "zzz")

    def test_empty_record_line_is_skipped(self):
        r, skipped = check(["s9\t", f"s1\tv=DKIM1; k=rsa; p={RSA_2048}"])
        self.assertEqual((len(r), skipped), (1, 1))

    def test_empty_input(self):
        self.assertEqual(check([]), ([], 0))
