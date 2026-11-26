# net.gsa

Unified networking stack for Geisha (`ByteStream`, TLS 1.2/1.3, HTTP/HTTPS, and WebSocket `ws://`/`wss://`).

## Modules

- `net.stream` — `concept ByteStream` implemented for `sys.net.TcpStream` and `net.tls.TlsStream`
- `net.tls` — OpenSSL 3 native TLS client (`TlsStream`, SNI + system CA verification)
- `net.ws` — Pure-Geisha RFC 6455 WebSocket server & client generic over `ByteStream` (zero OpenSSL dependency for plain `ws://`)
- `net.wss` — WebSocket over TLS (`wssConnect`, returning `WsConn TlsStream`)
- `net.http` — HTTP/1.1 & HTTPS client generic over `ByteStream` (`httpGet`, `httpsGet`, `httpsPost`, `httpsRequest`, chunked decoding, `urlEncode`)

## Test

```sh
geisha test
```
