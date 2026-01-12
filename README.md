# StateSet UCP Handler (Rust)

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
- In-memory storage with TTL
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

### Request Headers (when enabled)

If you enable header enforcement, include these on requests:

- `Request-Id` on all calls when `UCP_REQUIRE_REQUEST_ID=true`.
- `Idempotency-Key` on POST/PUT when `UCP_REQUIRE_IDEMPOTENCY=true`.

### Example: Create Checkout

```bash
curl -X POST http://localhost:8081/api/checkout-sessions \
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

## Fulfillment and Discounts

- If `fulfillment` is supplied without groups/options, the handler injects
  default shipping options (standard and express).
- If a shipping method has multiple destinations, you must set
  `selected_destination_id` or the checkout will return `requires_escalation`.
- Discount codes are normalized to uppercase. Supported codes:
  `SAVE10`, `SAVE5`, `SHIPFREE`.

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

## Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/.well-known/ucp` | UCP discovery document |
| POST | `/api/checkout-sessions` | Create checkout |
| GET | `/api/checkout-sessions/:id` | Retrieve checkout |
| PUT | `/api/checkout-sessions/:id` | Update checkout |
| POST | `/api/checkout-sessions/:id/complete` | Complete checkout |
| POST | `/api/checkout-sessions/:id/cancel` | Cancel checkout |
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
| `UCP_ORDER_WEBHOOK_URL` | _unset_ | Platform webhook URL for order events |
| `UCP_ORDER_WEBHOOK_API_KEY` | _unset_ | API key sent to the platform webhook |
| `UCP_WEBHOOK_SIGNATURE` | _unset_ | Static `Request-Signature` header value for webhooks |
| `UCP_SIGNING_KEYS_JSON` | _unset_ | JSON array of JWKs advertised in discovery |
| `UCP_BUYER_CONSENT_ENABLED` | `false` | Advertise buyer consent extension support |
| `UCP_AP2_ENABLED` | `false` | Enable AP2 mandate extension |
| `UCP_AP2_MERCHANT_AUTH` | _unset_ | Detached JWS signature for AP2 merchant authorization |
| `UCP_OAUTH_ENABLED` | `false` | Enable OAuth identity linking endpoints |
| `UCP_OAUTH_ISSUER` | `http://127.0.0.1:8081` | Issuer URL for OAuth metadata |
| `UCP_OAUTH_CLIENT_ID` | `ucp-demo-client` | OAuth client identifier |
| `UCP_OAUTH_CLIENT_SECRET` | `ucp-demo-secret` | OAuth client secret |
| `UCP_OAUTH_SCOPES` | `ucp:scopes:checkout_session` | Space- or comma-separated OAuth scopes |
| `UCP_OAUTH_TOKEN_TTL_SECONDS` | `3600` | OAuth access token TTL (seconds) |
| `UCP_OAUTH_CODE_TTL_SECONDS` | `300` | OAuth authorization code TTL (seconds) |
| `UCP_OAUTH_REDIRECT_URIS` | _unset_ | Comma-separated allowlist for OAuth redirects |
| `UCP_OAUTH_SERVICE_DOCUMENTATION` | _unset_ | Optional OAuth metadata documentation URL |
| `UCP_TOKEN_TTL_SECONDS` | `900` | Tokenization token TTL (seconds) |
| `UCP_TOKEN_SINGLE_USE` | `true` | Remove token after first detokenize |

## Node.js Bindings

Native Node.js bindings are available in the `napi-node/` directory, providing direct access to the UCP handler from Node.js/TypeScript applications.

### Installation

```bash
cd napi-node
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

## Notes

- This implementation uses an in-memory product catalog with demo items.
- Totals are computed using a fixed tax rate for illustration.
- The server advertises a sample payment handler (`dev.ucp.payments.card`).
- Discount codes supported by the demo engine: `SAVE10`, `SAVE5`, `SHIPFREE`.
- OAuth identity linking is advertised when enabled; tokens are stored in-memory.
- Buyer consent data is preserved when `UCP_BUYER_CONSENT_ENABLED=true`.
- AP2 mandate support uses a configured merchant authorization and only checks presence of `ap2.checkout_mandate`.
- Tokenization tokens are scoped to checkout + identity and expire based on TTL.
- Webhook signatures are not generated automatically; provide a detached JWT via `UCP_WEBHOOK_SIGNATURE` if needed.

## License

BUSL 1.1
