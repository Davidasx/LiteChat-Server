from pgpy import PGPKey


def get_fingerprint(pub_key_str: str) -> str:
    """Return canonical fingerprint string from an ASCII-armored PGP public key."""
    key, _ = PGPKey.from_blob(pub_key_str)
    return str(key.fingerprint) 