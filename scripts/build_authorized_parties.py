#!/usr/bin/env python3
"""
Builds authorized_parties.json from keypairs produced by gen_identity.py.

Usage:
  build_authorized_parties.py --quorum M \\
      --hospital H1 [--hospital H2 ...] \\
      [--researcher R --signed-by S1 [--signed-by S2 ...]]

Hospitals are founders (listed directly). The researcher (0 or 1 per
invocation) is approved by the --signed-by hospitals, which must also
appear in --hospital. Each signer produces an ECDSA-P256/SHA256 signature
over:

    "SAHC-approve-v1" || researcher_id || researcher_pubkey(64B LE)

Output is printed to stdout as pretty JSON.

Requires: cryptography (pip install cryptography)
"""
import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


APPROVAL_PREFIX = b"SAHC-approve-v1"


def load_pub(party_id: str) -> bytes:
    p = Path(f"parties/{party_id}.pub")
    if not p.exists():
        sys.exit(f"error: missing pubkey {p} (run gen_identity.py {party_id})")
    b = p.read_bytes()
    if len(b) != 64:
        sys.exit(f"error: {p} is not 64 bytes (got {len(b)})")
    return b


def load_priv(party_id: str):
    p = Path(f"parties/{party_id}.key")
    if not p.exists():
        sys.exit(f"error: missing private key {p}")
    return serialization.load_pem_private_key(p.read_bytes(), password=None)


def sign_approval(hospital_priv, researcher_id: str, researcher_pub: bytes) -> bytes:
    msg = APPROVAL_PREFIX + researcher_id.encode("utf-8") + researcher_pub
    der = hospital_priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    # sgx_ec256_signature_t: r and s as 32B little-endian each.
    return r.to_bytes(32, "little") + s.to_bytes(32, "little")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quorum", type=int, required=True)
    ap.add_argument("--hospital", action="append", default=[],
                    help="Founder hospital id. Repeat for multiple.")
    ap.add_argument("--researcher", action="append", default=[],
                    help="Researcher id (0 or 1 per invocation).")
    ap.add_argument("--signed-by", action="append", default=[],
                    help="Hospital id that signs the researcher's approval. "
                         "Repeat to collect multiple approvals.")
    args = ap.parse_args()

    if not args.hospital:
        sys.exit("error: at least one --hospital required")
    if len(args.researcher) > 1:
        sys.exit("error: at most one --researcher per invocation")
    if args.signed_by and not args.researcher:
        sys.exit("error: --signed-by requires --researcher")

    doc = {
        "version": 1,
        "quorum_m": args.quorum,
        "hospitals": [],
        "researchers": [],
    }

    for hid in args.hospital:
        doc["hospitals"].append({"id": hid, "pubkey": load_pub(hid).hex()})

    if args.researcher:
        rid = args.researcher[0]
        rpub = load_pub(rid)
        approvals = []
        for signer in args.signed_by:
            if signer not in args.hospital:
                sys.exit(f"error: --signed-by {signer} is not in --hospital list")
            priv = load_priv(signer)
            sig = sign_approval(priv, rid, rpub)
            approvals.append({"hospital_id": signer, "signature": sig.hex()})
        doc["researchers"].append({
            "id": rid,
            "pubkey": rpub.hex(),
            "approvals": approvals,
        })

    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
