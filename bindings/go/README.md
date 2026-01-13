# Go bindings

Go bindings built on a small C ABI layer generated with cbindgen and consumed via cgo.

## Build

```bash
# Build the Rust C ABI and generate the header
cd bindings/go/native
cargo build --release

# Use the Go wrapper
cd ../
go test ./...
```

If you need a different output directory, update `CGO_LDFLAGS` or the `#cgo LDFLAGS` line in `ucp.go`.

## Usage

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/stateset/stateset-ucp-handler/bindings/go/ucp"
)

func main() {
    service, err := ucp.NewCheckoutService(ucp.CheckoutConfig{
        UCPVersion:         "2026-01-11",
        ServiceVersion:     "1.0.0",
        BaseURL:            "http://localhost:3000",
        SessionTTLSeconds:  3600,
        TaxBps:             825,
    })
    if err != nil {
        panic(err)
    }
    defer service.Close()

    payload, _ := json.Marshal(map[string]any{
        "line_items": []map[string]any{{"item": map[string]any{"id": "item_123"}, "quantity": 2}},
        "currency": "USD",
        "payment":  map[string]any{},
    })

    checkout, err := service.CreateCheckout(payload)
    if err != nil {
        panic(err)
    }

    fmt.Println(checkout)
}
```
