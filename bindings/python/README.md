# Python bindings

Python bindings built with PyO3 and maturin.

## Build

```bash
cd bindings/python
python -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop
```

## Usage

```python
import json
from stateset_ucp import CheckoutService, Crypto

service = CheckoutService(
    ucp_version="2026-01-11",
    service_version="1.0.0",
    base_url="http://localhost:3000",
    session_ttl_seconds=3600,
    tax_bps=825,
)

checkout = service.create_checkout(json.dumps({
    "line_items": [{"item": {"id": "item_123"}, "quantity": 2}],
    "currency": "USD",
    "payment": {},
}))
print(json.loads(checkout))

signing_key, verifying_key = Crypto.generate_key_pair("ES256", "key-1")
jws = Crypto.sign_json('{"test": true}', signing_key)
Crypto.verify_json(jws, '{"test": true}', verifying_key)
```
