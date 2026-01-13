# Ruby bindings

Ruby bindings built with the magnus crate.

## Build

```bash
cd bindings/ruby
# Install the rb_sys gem if needed
# gem install rb_sys
ruby ext/stateset_ucp/extconf.rb
make -C ext/stateset_ucp
```

## Usage

```ruby
require "stateset_ucp"

service = StatesetUcp::CheckoutService.new({
  ucp_version: "2026-01-11",
  service_version: "1.0.0",
  base_url: "http://localhost:3000",
  session_ttl_seconds: 3600,
  tax_bps: 825,
})

checkout = service.create_checkout({
  line_items: [{ item: { id: "item_123" }, quantity: 2 }],
  currency: "USD",
  payment: {},
}.to_json)
puts checkout

signing_key, verifying_key = StatesetUcp::Crypto.generate_key_pair("ES256", "key-1")
jws = StatesetUcp::Crypto.sign_json('{"test": true}', signing_key)
StatesetUcp::Crypto.verify_json(jws, '{"test": true}', verifying_key)
```
