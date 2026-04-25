#!/usr/bin/env python3
"""
Usage: gen_identity.py <party_id>

Generates a P-256 keypair and writes:
  parties/<party_id>.key  — PEM PKCS8 private key (mode 600; KEEP SECRET)
  parties/<party_id>.pub  — raw 64-byte pubkey in SGX layout (X||Y, 32B LE each)

Requires: cryptography (pip install cryptography)
"""
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    party_id = sys.argv[1]
    if not party_id or len(party_id) > 63 or "/" in party_id:
        sys.exit(f"error: invalid party_id: {party_id!r}")

    parties = Path("parties")
    parties.mkdir(exist_ok=True)

    key_path = parties / f"{party_id}.key"
    pub_path = parties / f"{party_id}.pub"
    if key_path.exists():
        sys.exit(f"error: {key_path} already exists; refusing to overwrite")

    priv = ec.generate_private_key(ec.SECP256R1())

    key_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    nums = priv.public_key().public_numbers()
    # sgx_ec256_public_t stores gx and gy as 32-byte little-endian coordinates.
    pub_raw = nums.x.to_bytes(32, "little") + nums.y.to_bytes(32, "little")
    pub_path.write_bytes(pub_raw)

    print(f"wrote {key_path} (private, 0600)")
    print(f"wrote {pub_path} (public, 64B LE)")


if __name__ == "__main__":
    main()
