from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

KEY_DIR = Path(__file__).resolve().parent.parent / "config" / "keys"


@pytest.mark.parametrize("name", ["jwt-rs256-public.pem", "service-es256-public.pem", "audit-ed25519-public.pem"])
def test_published_public_keys_parse(name):
    key = serialization.load_pem_public_key((KEY_DIR / name).read_bytes())
    assert key is not None
