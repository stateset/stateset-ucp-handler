#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-http://127.0.0.1:8081}
API_KEY=${UCP_API_KEY:-}
REQUEST_ID=${REQUEST_ID:-}
IDEMPOTENCY_KEY=${IDEMPOTENCY_KEY:-}
UCP_AGENT=${UCP_AGENT:-}
REQUEST_SIGNATURE=${REQUEST_SIGNATURE:-}

header_args=("-H" "Content-Type: application/json")
if [[ -n "$API_KEY" ]]; then
  header_args+=("-H" "Authorization: Bearer ${API_KEY}")
fi
if [[ -n "$UCP_AGENT" ]]; then
  header_args+=("-H" "UCP-Agent: ${UCP_AGENT}")
fi
if [[ -n "$REQUEST_SIGNATURE" ]]; then
  header_args+=("-H" "Request-Signature: ${REQUEST_SIGNATURE}")
fi
if [[ -z "$REQUEST_ID" ]]; then
  REQUEST_ID=$(python - <<'PY'
import uuid
print(uuid.uuid4())
PY
)
fi
header_args+=("-H" "Request-Id: ${REQUEST_ID}")
if [[ -n "$IDEMPOTENCY_KEY" ]]; then
  header_args+=("-H" "Idempotency-Key: ${IDEMPOTENCY_KEY}")
fi

create_payload='{
  "line_items": [
    {"item": {"id": "item_123"}, "quantity": 2}
  ],
  "currency": "USD",
  "discounts": {
    "codes": ["SAVE10", "SHIPFREE"]
  },
  "fulfillment": {
    "methods": [
      {
        "type": "shipping",
        "destinations": [
          {
            "id": "dest_1",
            "street_address": "123 Main St",
            "address_locality": "San Francisco",
            "address_region": "CA",
            "address_country": "US",
            "postal_code": "94105"
          }
        ],
        "selected_destination_id": "dest_1"
      }
    ]
  },
  "payment": {
    "selected_instrument_id": "pi_demo",
    "instruments": [
      {
        "id": "pi_demo",
        "handler_id": "ucp_card",
        "type": "card",
        "brand": "visa",
        "last_digits": "4242"
      }
    ]
  },
  "buyer": {
    "email": "jane@example.com",
    "first_name": "Jane",
    "last_name": "Doe"
  }
}'

echo "Creating checkout session..."
create_resp=$(curl -sS -X POST "${BASE_URL}/api/checkout-sessions" "${header_args[@]}" -d "$create_payload")
checkout_id=$(python - <<PY
import json
print(json.loads('''$create_resp''')["id"])
PY
)

echo "Checkout ID: ${checkout_id}"

echo "Completing checkout..."
complete_payload='{
  "payment_data": {
    "id": "pi_demo",
    "handler_id": "ucp_card",
    "type": "card",
    "brand": "visa",
    "last_digits": "4242"
  }
}'

complete_resp=$(curl -sS -X POST "${BASE_URL}/api/checkout-sessions/${checkout_id}/complete" "${header_args[@]}" -d "$complete_payload")
order_id=$(python - <<PY
import json
print(json.loads('''$complete_resp''')["order"]["id"])
PY
)

echo "Order ID: ${order_id}"
