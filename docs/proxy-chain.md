# Proxy Chain Implementation

## Architecture: v2rayN-Style dialerProxy Chaining

This project uses the **same proxy chaining approach as v2rayN** - Xray's native `dialerProxy` feature to chain multiple VLESS proxies in a **SINGLE Xray instance**.

### How It Works

```
User App → Single Xray Process (:22000)
              ↓
         VLESS Hop 1 (chain-0)
              ↓ dialerProxy="chain-1"
         VLESS Hop 2 (chain-1)
              ↓
           Internet
```

### ⚠️ CRITICAL: Transport Requirements

**Supported Transports (dialerProxy compatible):**
- ✅ VLESS + WebSocket (ws) + TLS
- ✅ VLESS + HTTPUpgrade + TLS
- ✅ VMess + WebSocket (ws) + TLS

**NOT Supported (dialerProxy INCOMPATIBLE):**
- ❌ VLESS + Reality (**does NOT work** with dialerProxy)
- ❌ VLESS + TCP (may have issues)

### Why Reality Doesn't Work

Xray's `dialerProxy` operates at the socket level and is incompatible with Reality's transport mechanism. This is a **known limitation** confirmed by testing:

> "If the exit node uses Reality protocol, it doesn't work. If the exit node uses WebSocket... it works."

Source: https://zelikk.blogspot.com/2023/11/xray-tcp-chain-proxy-sockopt-dialerproxy.html

### How to Use

1. **Get VLESS configs with WebSocket transport** (NOT Reality)
2. **Ensure TLS is enabled** (wss:// not ws://)
3. **Add to your proxy chain** - the code handles the rest

Example VLESS+WS+TLS URL:
```
vless://uuid@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fpath#remark
```

### Code Implementation

The chain is created in `source/utils/xray_tester.py:create_chain_config()`:

```python
config = tester.create_chain_config(
    proxy_urls=["vless://hop1...", "vless://hop2..."],
    socks_port=22000
)
```

This generates a single Xray config with:
- Multiple VLESS outbounds (one per hop)
- `dialerProxy` linking each hop to the next
- Single SOCKS5 inbound for user apps

### Benefits

- ✅ **Single process** - No relay needed, simpler architecture
- ✅ **Native Xray feature** - Maintained by Xray team
- ✅ **Same as v2rayN** - Battle-tested approach
- ✅ **End-to-end encrypted** - Each hop has independent VLESS encryption

### Limitations

- ⚠️ **Reality not supported** - Must use WebSocket/HTTPUpgrade
- ⚠️ **First hop sees your IP** - Proxy1 provider can see your real IP
- ❌ **No traffic correlation protection** - Not protected against global adversary

### Troubleshooting

**Chain exits via hop1 only (hop2 bypassed):**
- You're likely using Reality protocol - switch to WebSocket
- Check that all hops use compatible transports

**Connection fails immediately:**
- Verify WebSocket path and host settings
- Ensure TLS is enabled (wss:// not ws://)
- Check that all proxy URLs are valid and working individually

### References

- v2rayN source code: https://github.com/2dust/v2rayN
- Xray dialerProxy docs: https://xtls.github.io/en/config/outbound.html
- Reality + dialerProxy incompatibility: https://zelikk.blogspot.com/2023/11/xray-tcp-chain-proxy-sockopt-dialerproxy.html
