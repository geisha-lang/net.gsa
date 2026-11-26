# tls.gsa

Native TLS 1.2/1.3, HTTPS, WSS, and HMAC-SHA256 package for Geisha (backed by OpenSSL 3).

## Modules

- `tls.tls` — `TlsStream` (`Send`), SNI + system CA verification, `tlsConnect`, `tlsRead*`, `tlsWrite*`, `tlsClose`
- `tls.http` — HTTP/1.1 over TLS (`httpGet`, `httpPost`, `httpRequest`, custom headers, `Content-Length` & `Transfer-Encoding: chunked`, `urlEncode`)
- `tls.wss` — RFC 6455 WebSocket over TLS (`WssConn`, `wssConnect`, `wssRecv`, `wssSendText`, `wssSendPing/Pong/Close`)
- `tls.hmac` — Pure-Geisha RFC 2104 `hmacSha256Hex` (exchange API request signing)

## Test

```sh
geisha test
```
