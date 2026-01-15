# StateSet UCP Handler (Rust)

[![CI](https://github.com/stateset/stateset-ucp-handler/actions/workflows/ci.yml/badge.svg)](https://github.com/stateset/stateset-ucp-handler/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/stateset-ucp-handler.svg)](https://crates.io/crates/stateset-ucp-handler)
[![License](https://img.shields.io/crates/l/stateset-ucp-handler.svg)](LICENSE)

A standalone Rust server that implements the Universal Commerce Protocol (UCP) checkout flow.

## Features

- UCP discovery endpoint at `/.well-known/ucp`
- Checkout session lifecycle (create, get, update, complete, cancel)
- Order webhook event emission on checkout completion
- Fulfillment + discount extensions (shipping options, promo codes)
- Discovery advertises checkout, fulfillment, discount, and order capabilities
- OAuth 2.0 identity linking capability (authorization code flow)
- AP2 mandate extension (optional embedded authorization)
- Tokenization handler endpoints (`/tokenize`, `/detokenize`)
- gRPC server (JSON payloads) with health + reflection
- **iCommerce execution backend** with SQLite persistence (optional)
- Dynamic tax calculation, promotions, and shipping rates via iCommerce
- In-memory storage with TTL (fallback when iCommerce disabled)
- Basic totals calculation (subtotal, tax, total)
- Optional API key authentication
- Optional idempotency handling

## Quick Start

```bash
cargo run
```

The server starts on `http://0.0.0.0:8081` by default.

Run the demo flow:

```bash
./demo_test.sh
```

### Request Headers

By default, the handler requires `UCP-Agent` on all requests and
`Request-Signature` on `POST`/`PUT`. You can relax this for local testing with
`UCP_REQUIRE_UCP_AGENT=false` and `UCP_REQUIRE_REQUEST_SIGNATURE=false`.

Additional headers when enabled:

- `Request-Id` on all calls when `UCP_REQUIRE_REQUEST_ID=true`.
- `Idempotency-Key` on POST/PUT when `UCP_REQUIRE_IDEMPOTENCY=true`.

### Example: Create Checkout

```bash
curl -X POST http://localhost:8081/api/checkout-sessions \
  -H "UCP-Agent: profile=\"https://platform.example/profile\"" \
  -H "Request-Signature: <detached-jws>" \
  -H "Request-Id: 00000000-0000-0000-0000-000000000001" \
  -H "Idempotency-Key: 00000000-0000-0000-0000-000000000002" \
  -H "Content-Type: application/json" \
  -d '{
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
    }
  }'
```

### Example: Complete Checkout

```bash
curl -X POST http://localhost:8081/api/checkout-sessions/{id}/complete \
  -H "UCP-Agent: profile=\"https://platform.example/profile\"" \
  -H "Request-Signature: <detached-jws>" \
  -H "Request-Id: 00000000-0000-0000-0000-000000000003" \
  -H "Idempotency-Key: 00000000-0000-0000-0000-000000000004" \
  -H "Content-Type: application/json" \
  -d '{
    "payment_data": {
      "id": "pi_demo",
      "handler_id": "ucp_card",
      "type": "card",
      "brand": "visa",
      "last_digits": "4242"
    }
  }'
```

## Order Webhooks

When a checkout is completed, the handler can emit an order event webhook
to a platform URL. Set `UCP_ORDER_WEBHOOK_URL` to enable delivery. If the
platform requires signature verification, provide a detached JWT in
`UCP_WEBHOOK_SIGNATURE` so it is sent in the `Request-Signature` header.
The event includes a full order payload with initial fulfillment expectations
and a processing event.

Orders are also stored locally and can be retrieved or updated via the
`/api/orders` endpoints after checkout completion.

## Fulfillment and Discounts

- If `fulfillment` is supplied without groups/options, the handler injects
  default shipping options (standard and express).
- If a shipping method has multiple destinations, you must set
  `selected_destination_id` or the checkout will return `requires_escalation`.
- Discount codes are normalized to uppercase. Supported codes:
  `SAVE10`, `SAVE5`, `SHIPFREE`.

## Commerce Backend (iCommerce)

The handler can use **StateSet iCommerce** as its execution backend, providing:

- **SQLite persistence** - Checkouts and orders survive server restarts
- **Real inventory tracking** - Stock management with reservation support
- **Dynamic promotions** - Full promotion engine (percentage, fixed, BOGO, etc.)
- **Multi-jurisdiction tax** - Address-based tax calculation
- **Dynamic shipping rates** - Real carrier rates when configured

### Enabling iCommerce

iCommerce is **enabled by default**. On startup, the handler initializes a SQLite
database at `./commerce.db`. To disable and use in-memory storage only:

```bash
COMMERCE_ENABLED=false cargo run
```

### Hybrid Architecture

All commerce integrations use a hybrid pattern:
1. Try iCommerce first for persistence and dynamic calculation
2. Fall back to in-memory/static behavior if iCommerce is unavailable

This ensures backward compatibility and graceful degradation.

### Feature Flags

You can selectively enable/disable iCommerce features:

```bash
# Use iCommerce for everything (default when COMMERCE_ENABLED=true)
COMMERCE_ENABLED=true

# Use iCommerce storage but static tax rates
USE_ICOMMERCE_TAX=false

# Use iCommerce storage but hardcoded promo codes
USE_ICOMMERCE_PROMOTIONS=false

# Use iCommerce storage but static shipping options
USE_ICOMMERCE_SHIPPING=false
```

## Tokenization

`/tokenize` and `/detokenize` implement the UCP tokenization handler. Tokens
are bound to `checkout_id` (and optional identity), expire after
`UCP_TOKEN_TTL_SECONDS`, and are single-use by default
(`UCP_TOKEN_SINGLE_USE=true`).

## Identity Linking (OAuth 2.0)

Enable OAuth endpoints by setting `UCP_OAUTH_ENABLED=true`. The handler exposes
`/.well-known/oauth-authorization-server` for metadata plus
`/oauth2/authorize`, `/oauth2/token`, and `/oauth2/revoke`. Token endpoint and
revocation require HTTP Basic auth with the configured client credentials.

## AP2 Mandate (Optional)

Enable AP2 by setting `UCP_AP2_ENABLED=true` and providing
`UCP_AP2_MERCHANT_AUTH` (detached JWS signature). When enabled, checkout
responses include `ap2.merchant_authorization`, and complete checkout requests
must include `ap2.checkout_mandate`.

If you load the signing key from `UCP_SIGNING_PRIVATE_KEY_JSON`, you can override
the JWK `kid` advertised in signatures with `UCP_AP2_SIGNING_KEY_ID`.

## Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/.well-known/ucp` | UCP discovery document |
| POST | `/api/checkout-sessions` | Create checkout |
| GET | `/api/checkout-sessions/:id` | Retrieve checkout |
| PUT | `/api/checkout-sessions/:id` | Update checkout |
| POST | `/api/checkout-sessions/:id/complete` | Complete checkout |
| POST | `/api/checkout-sessions/:id/cancel` | Cancel checkout |
| GET | `/api/orders/:id` | Retrieve order |
| POST | `/api/orders/:id/fulfillment-events` | Add fulfillment event |
| POST | `/api/orders/:id/adjustments` | Add order adjustment |
| POST | `/tokenize` | Tokenize credential |
| POST | `/detokenize` | Detokenize credential |
| GET | `/.well-known/oauth-authorization-server` | OAuth metadata (when enabled) |
| GET | `/oauth2/authorize` | OAuth authorize (when enabled) |
| POST | `/oauth2/token` | OAuth token exchange (when enabled) |
| POST | `/oauth2/revoke` | OAuth revoke (when enabled) |
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |

## gRPC

The gRPC server listens on `GRPC_HOST:GRPC_PORT` (default `0.0.0.0:50051`) and
exposes the `ucp_handler.v1.UcpHandler` service. Requests and responses use
`payload_json` bytes containing the same JSON objects as the HTTP API.
The proto definition lives at `proto/ucp_handler/v1/ucp_handler.proto`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8081` | Server port |
| `GRPC_HOST` | `0.0.0.0` | gRPC bind address |
| `GRPC_PORT` | `50051` | gRPC server port |
| `UCP_PUBLIC_BASE_URL` | `http://127.0.0.1:8081` | Public base URL used in discovery responses |
| `UCP_VERSION` | `2026-01-11` | UCP protocol version |
| `UCP_SERVICE_VERSION` | `2026-01-11` | Service version |
| `UCP_SESSION_TTL_SECONDS` | `21600` | Checkout TTL (seconds) |
| `UCP_TAX_BPS` | `875` | Tax rate in basis points |
| `UCP_API_KEYS` | _unset_ | Comma-separated API keys |
| `UCP_REQUIRE_AUTH` | `false` | Require auth headers |
| `UCP_REQUIRE_IDEMPOTENCY` | `false` | Require idempotency headers |
| `UCP_REQUIRE_REQUEST_ID` | `false` | Require Request-Id header |
| `UCP_REQUIRE_UCP_AGENT` | `true` | Require UCP-Agent header |
| `UCP_REQUIRE_REQUEST_SIGNATURE` | `true` | Require Request-Signature on POST/PUT |
| `UCP_PROFILE_CACHE_TTL_SECONDS` | `3600` | Cache TTL for platform profiles (seconds) |
| `UCP_PROFILE_FETCH_TIMEOUT_SECONDS` | `10` | Timeout for fetching platform profiles (seconds) |
| `UCP_ORDER_WEBHOOK_URL` | _unset_ | Platform webhook URL for order events |
| `UCP_ORDER_WEBHOOK_API_KEY` | _unset_ | API key sent to the platform webhook |
| `UCP_WEBHOOK_SIGNATURE` | _unset_ | Static `Request-Signature` header value for webhooks |
| `UCP_WEBHOOK_TIMEOUT_SECONDS` | `10` | Timeout for webhook delivery attempts (seconds) |
| `UCP_WEBHOOK_MAX_RETRIES` | `2` | Max retry attempts for webhook delivery |
| `UCP_WEBHOOK_RETRY_BASE_MS` | `250` | Base backoff delay for webhook retries (milliseconds) |
| `UCP_SIGNING_KEYS_JSON` | _unset_ | JSON array of JWKs advertised in discovery |
| `UCP_SIGNING_PRIVATE_KEY_JSON` | _unset_ | JWK private key for AP2 + response signing |
| `UCP_BUYER_CONSENT_ENABLED` | `false` | Advertise buyer consent extension support |
| `UCP_AP2_ENABLED` | `false` | Enable AP2 mandate extension |
| `UCP_AP2_MERCHANT_AUTH` | _unset_ | Detached JWS signature for AP2 merchant authorization |
| `UCP_AP2_SIGNING_KEY_ID` | _unset_ | Override `kid` for AP2 signing key |
| `UCP_OAUTH_ENABLED` | `false` | Enable OAuth identity linking endpoints |
| `UCP_OAUTH_ISSUER` | `http://127.0.0.1:8081` | Issuer URL for OAuth metadata |
| `UCP_OAUTH_CLIENT_ID` | `ucp-demo-client` | OAuth client identifier |
| `UCP_OAUTH_CLIENT_SECRET` | `ucp-demo-secret` | OAuth client secret |
| `UCP_OAUTH_REDIRECT_URIS` | _unset_ | Comma-separated OAuth redirect URIs (required when OAuth enabled) |
| `UCP_OAUTH_SCOPES` | `ucp:scopes:checkout_session` | Space- or comma-separated OAuth scopes |
| `UCP_OAUTH_TOKEN_TTL_SECONDS` | `3600` | OAuth access token TTL (seconds) |
| `UCP_OAUTH_CODE_TTL_SECONDS` | `300` | OAuth authorization code TTL (seconds) |
| `UCP_OAUTH_SERVICE_DOCUMENTATION` | _unset_ | Optional OAuth metadata documentation URL |
| `UCP_TOKEN_TTL_SECONDS` | `900` | Tokenization token TTL (seconds) |
| `UCP_TOKEN_SINGLE_USE` | `true` | Remove token after first detokenize |
| `COMMERCE_ENABLED` | `true` | Enable iCommerce execution backend |
| `COMMERCE_DB_PATH` | `./commerce.db` | SQLite database path for commerce data |
| `USE_ICOMMERCE_TAX` | `true` | Use iCommerce for tax calculation |
| `USE_ICOMMERCE_PROMOTIONS` | `true` | Use iCommerce for promotions/discounts |
| `USE_ICOMMERCE_SHIPPING` | `true` | Use iCommerce for shipping rates |

## Node.js Bindings

Native Node.js bindings are available in the `bindings/napi-node/` directory, providing direct access to the UCP handler from Node.js/TypeScript applications.

### Installation

```bash
cd bindings/napi-node
npm install
npm run build
```

### Usage

```javascript
import { CheckoutService, Crypto, SigningAlgorithm, McpHandler, A2AHandler } from '@stateset/ucp-handler-node';

// Checkout Service
const service = new CheckoutService({
  ucpVersion: '2026-01-11',
  serviceVersion: '1.0.0',
  baseUrl: 'http://localhost:3000',
  sessionTtlSeconds: 3600,
  taxBps: 825,
});

const checkout = await service.createCheckout(JSON.stringify({
  line_items: [{ item: { id: 'item_123' }, quantity: 2 }],
  currency: 'USD',
  payment: {},
}));
console.log(JSON.parse(checkout));

// Crypto (JWS signing/verification)
const { signingKey, verifyingKey } = Crypto.generateKeyPair(SigningAlgorithm.ES256, 'key-1');
const jws = Crypto.signJson('{"test": true}', signingKey);
Crypto.verifyJson(Crypto.jwsToCompact(jws), '{"test": true}', verifyingKey);

// MCP Handler (JSON-RPC 2.0)
const mcp = new McpHandler({ ucpVersion: '2026-01-11', ... });
const response = await mcp.handle(JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {}, id: 1 }));

// A2A Handler (Agent-to-Agent)
const a2a = new A2AHandler({ ucpVersion: '2026-01-11', ... });
const agentCard = await a2a.agentCard();
```

### Available Classes

- **CheckoutService** - Full checkout lifecycle management
- **Crypto** - JWS signing/verification with ES256/ES384
- **McpHandler** - Model Context Protocol (JSON-RPC 2.0) handler
- **A2AHandler** - Google A2A protocol handler
- **OrderService** - Post-checkout order management

## Python Bindings

Bindings live in `bindings/python/`. See `bindings/python/README.md` for build and usage.

## Go Bindings

Bindings live in `bindings/go/`. See `bindings/go/README.md` for build and usage.

## Ruby Bindings

Bindings live in `bindings/ruby/`. See `bindings/ruby/README.md` for build and usage.

## Notes

- By default, iCommerce provides SQLite persistence for checkouts, orders, and inventory.
- When iCommerce is disabled, the implementation uses an in-memory product catalog with demo items.
- Tax calculation uses iCommerce's multi-jurisdiction engine when enabled, or a fixed rate as fallback.
- The server advertises a sample payment handler (`dev.ucp.payments.card`).
- Discount codes supported by the fallback engine: `SAVE10`, `SAVE5`, `SHIPFREE`. iCommerce supports full promotion rules.
- OAuth identity linking is advertised when enabled; tokens are stored in-memory.
- Buyer consent data is preserved when `UCP_BUYER_CONSENT_ENABLED=true`.
- AP2 mandate support uses a configured merchant authorization and only checks presence of `ap2.checkout_mandate`.
- Tokenization tokens are scoped to checkout + identity and expire based on TTL.
- Webhook signatures are not generated automatically; provide a detached JWT via `UCP_WEBHOOK_SIGNATURE` if needed.

## License

Apache 2.0 or MIT
