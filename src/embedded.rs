//! Embedded Protocol (EP) helpers.
//!
//! Provides query parsing and HTML template rendering for embedded checkout
//! handoff using the UCP Embedded Protocol (JSON-RPC 2.0 over postMessage).

use serde::Deserialize;
use std::collections::HashSet;

/// Embedded Protocol query parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EmbeddedParams {
    /// UCP version for this embedded session
    #[serde(rename = "ec_version")]
    pub version: Option<String>,
    /// Business-defined authentication token
    #[serde(rename = "ec_auth")]
    pub auth: Option<String>,
    /// Comma-delimited list of delegations requested by the host
    #[serde(rename = "ec_delegate")]
    pub delegate: Option<String>,
}

impl EmbeddedParams {
    pub fn requested_delegations(&self) -> Vec<String> {
        let Some(raw) = self.delegate.as_deref() else {
            return Vec::new();
        };

        let mut seen = HashSet::new();
        let mut delegations = Vec::new();

        for entry in raw.split(',').map(|value| value.trim()) {
            if entry.is_empty() || !valid_delegation(entry) {
                continue;
            }
            if seen.insert(entry.to_string()) {
                delegations.push(entry.to_string());
            }
        }

        delegations
    }
}

const SUPPORTED_DELEGATIONS: [&str; 3] = [
    "payment.instruments_change",
    "payment.credential",
    "fulfillment.address_change",
];

pub fn accepted_delegations(requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|entry| {
            SUPPORTED_DELEGATIONS
                .iter()
                .any(|supported| supported == &entry.as_str())
        })
        .cloned()
        .collect()
}

pub fn render_embedded_page(
    checkout_json: &str,
    ec_version: Option<&str>,
    accepted_delegations: &[String],
) -> String {
    let safe_checkout = escape_json_for_script(checkout_json);
    let version_json = serde_json::to_string(&ec_version).unwrap_or_else(|_| "null".to_string());
    let delegates_json = serde_json::to_string(accepted_delegations)
        .unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Embedded Checkout</title>
  <style>
    :root {{
      color-scheme: light;
    }}
    body {{
      font-family: "SF Pro Text", "Segoe UI", Arial, sans-serif;
      margin: 0;
      padding: 24px;
      background: #f7f7f3;
      color: #1f2933;
    }}
    main {{
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e5e7eb;
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 20px;
      letter-spacing: 0.2px;
    }}
    p {{
      margin: 0 0 16px 0;
      color: #475569;
      font-size: 14px;
    }}
    pre {{
      margin: 0;
      padding: 16px;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 10px;
      overflow: auto;
      font-size: 12px;
    }}
    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      background: #f1f5f9;
      color: #0f172a;
      margin-left: 8px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Embedded Checkout <span class="pill" id="ec-status">Idle</span></h1>
    <p id="ec-note">Loaded checkout session for embedded handoff.</p>
    <pre id="ec-checkout"></pre>
  </main>
  <script>
    (function() {{
      const checkout = {safe_checkout};
      const ecVersion = {version_json};
      const acceptedDelegations = {delegates_json};

      const statusEl = document.getElementById('ec-status');
      const noteEl = document.getElementById('ec-note');
      const checkoutEl = document.getElementById('ec-checkout');
      checkoutEl.textContent = JSON.stringify(checkout, null, 2);

      function setStatus(text) {{
        statusEl.textContent = text;
      }}

      function parseMessage(payload) {{
        if (!payload) return null;
        if (typeof payload === 'string') {{
          try {{
            return JSON.parse(payload);
          }} catch (err) {{
            return null;
          }}
        }}
        return payload;
      }}

      const pending = new Map();
      let messagePort = null;

      function handleMessage(payload) {{
        const msg = parseMessage(payload);
        if (!msg || !msg.id) {{
          return;
        }}
        const key = String(msg.id);
        const entry = pending.get(key);
        if (!entry) {{
          return;
        }}
        pending.delete(key);
        entry.resolve(msg);
      }}

      function sendMessage(message) {{
        if (messagePort) {{
          messagePort.postMessage(message);
          return;
        }}
        if (window.EmbeddedCheckoutProtocolConsumer && typeof window.EmbeddedCheckoutProtocolConsumer.postMessage === 'function') {{
          window.EmbeddedCheckoutProtocolConsumer.postMessage(JSON.stringify(message));
          return;
        }}
        if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.EmbeddedCheckoutProtocolConsumer) {{
          window.webkit.messageHandlers.EmbeddedCheckoutProtocolConsumer.postMessage(JSON.stringify(message));
          return;
        }}
        if (window.parent) {{
          window.parent.postMessage(message, '*');
        }}
      }}

      window.addEventListener('message', function(event) {{
        handleMessage(event.data);
      }});

      window.EmbeddedCheckoutProtocol = {{
        postMessage: function(message) {{
          handleMessage(message);
        }}
      }};

      function sendReady() {{
        const id = 'ready_' + Math.random().toString(36).slice(2);
        const request = {{
          jsonrpc: '2.0',
          id: id,
          method: 'ec.ready',
          params: {{
            delegate: acceptedDelegations
          }}
        }};
        const promise = new Promise(function(resolve) {{
          pending.set(String(id), {{ resolve: resolve }});
        }});
        sendMessage(request);
        return promise;
      }}

      async function handshake() {{
        let response = await sendReady();
        while (response && response.result && response.result.upgrade && response.result.upgrade.port) {{
          messagePort = response.result.upgrade.port;
          messagePort.onmessage = function(event) {{
            handleMessage(event.data);
          }};
          response = await sendReady();
        }}
        return response;
      }}

      function sendNotification(method, params) {{
        sendMessage({{ jsonrpc: '2.0', method: method, params: params }});
      }}

      const canHandshake = ecVersion && (
        (window.parent && window.parent !== window) ||
        (window.EmbeddedCheckoutProtocolConsumer && typeof window.EmbeddedCheckoutProtocolConsumer.postMessage === 'function') ||
        (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.EmbeddedCheckoutProtocolConsumer)
      );

      if (!ecVersion) {{
        noteEl.textContent = 'ECP parameters missing; running in non-embedded mode.';
        setStatus('Standalone');
        return;
      }}

      if (!canHandshake) {{
        noteEl.textContent = 'Embedded host channel not detected.';
        setStatus('No Host');
        return;
      }}

      setStatus('Handshake');
      handshake().then(function() {{
        setStatus('Ready');
        sendNotification('ec.start', {{ checkout: checkout }});
      }}).catch(function() {{
        setStatus('Failed');
      }});
    }})();
  </script>
</body>
</html>
"#,
        safe_checkout = safe_checkout,
        version_json = version_json,
        delegates_json = delegates_json,
    )
}

fn valid_delegation(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    for part in value.split('.') {
        if part.is_empty() {
            return false;
        }
        if !part
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch == '_')
        {
            return false;
        }
    }

    true
}

fn escape_json_for_script(value: &str) -> String {
    value.replace("</", "<\\/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requested_delegations() {
        let params = EmbeddedParams {
            delegate: Some("payment.credential, fulfillment.address_change,invalid-foo".to_string()),
            ..EmbeddedParams::default()
        };

        let delegations = params.requested_delegations();
        assert_eq!(
            delegations,
            vec!["payment.credential".to_string(), "fulfillment.address_change".to_string()]
        );
    }

    #[test]
    fn accepts_supported_delegations() {
        let requested = vec![
            "payment.credential".to_string(),
            "identity.link".to_string(),
        ];
        let accepted = accepted_delegations(&requested);
        assert_eq!(accepted, vec!["payment.credential".to_string()]);
    }
}
