# email-dkim-record-checker

Parse and check DKIM TXT records for weak keys: each line of records.txt is "selector<TAB>record" (e.g. "s1._domainkey.example.com<TAB>v=DKIM1; k=rsa; p=MIGfMA0G...") — for each record this parses the tags and checks the public key, reading the RSA modulus bit length from the DER-encoded public key (not guessed from the base64 length), with Ed25519 keys 256-bit by design — OK for a usable key of an accepted type (rsa or ed25519), RSA 1024 bits or more (2048+ recommended; a 1024-bit key is reported as OK with a note to consider 2048), WEAK for no public key, an unparseable key, an unsupported key type, or an RSA key under 1024 bits — WEAK first, then OK. Lines with no record part, or with a record that has no tags at all, are reported as skipped, not silently dropped. The sample records use real-format sample keys generated for testing (not live keys).

Sample input is included (sample.txt with five DKIM records, one with no public key).

## How to run

```sh
python3 main.py sample.txt
```

## Example output

```
bad._domainkey.example.com: WEAK - no public key (p=) present
s2._domainkey.example.com: WEAK - rsa 512-bit key - below 1024-bit minimum
s1._domainkey.example.com: OK - rsa 2048-bit key
s3._domainkey.example.com: OK - ed25519 256-bit key
s4._domainkey.example.com: OK - rsa 2048-bit key, flags t=y
3 ok, 2 weak out of 5 DKIM record(s).
```

Standard library only. Run the tests with `python3 -m unittest discover`.
