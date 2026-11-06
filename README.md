# Hikari 光

Android port of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT) with a Material You UI.

A foreground service runs a local MTProto proxy on `127.0.0.1:1443`. Telegram connects to it
(`tg://proxy?...&secret=dd<hex>`); traffic is relayed to Telegram DCs over WebSocket
(`kws{dc}.web.telegram.org`), falling back to Cloudflare-proxied domains and then plain TCP.

## Download
Ready-made APKs are on the [Releases](../../releases) page; every push also uploads
`hikari-<commit>.apk` as an unzipped workflow artifact (Actions → Build). Allow installs from unknown sources to sideload.

## Ported
- obfuscated2 handshake, `dd` secret, DC / media detection, re-encryption (AES-CTR)
- MTProto packet splitter (one packet per WS frame)
- WebSocket pool per DC with SNI-fronting retry, CF proxy fallback with domain balancer
  (built-in list + hourly refresh from upstream), TCP fallback with exponential back-off

- Fake TLS (`ee` secret): ClientHello HMAC check, forged ServerHello profiled on the masking site,
  replay cache, non-matching traffic relayed to the real site
- CF Worker fallback (tried first, warm pool per DC)
- HTTP/2 media multiplexing: media packets are POSTed to `https://kws{dc}.{cf-domain}/api` over
  shared HTTP/2 connections, with the upstream replay/recovery logic (HTTP/2 framing via OkHttp)
- Telegram test DCs (`dc >= 10000` or forced), `/apiws_test`
- PROXY protocol v1, "no TLS" mode (port 80) for CF connections

All of these are configured in Settings. Deviations from upstream: HTTP/2 uses OkHttp instead of
`h2`/`httpx`, there is no per-request diagnostic tracing, and X25519 keys in the forged ServerHello are
random field elements (the client never derives keys from them, same as upstream's fallback).
None of it has been exercised against real Telegram servers or on a device yet.

## Build
```
./gradlew assembleDebug      # app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease    # app/build/outputs/apk/release/app-release.apk
./gradlew testDebugUnitTest  # crypto / splitter tests
```
Needs JDK 17–21, Android SDK 35. Gradle 9.5.x (AGP 8.13 is not compatible with Gradle 9.6).

## CI
`.github/workflows/build.yml` runs the unit tests and builds the release APK on every push and
pull request. Pushing a tag like `v1.0.0` also publishes a GitHub Release with the APK.

By default the release APK is signed with the debug key, which differs on every CI run, so
builds cannot update one another. To sign with a fixed key, add these repository secrets:
`KEYSTORE_BASE64` (`base64 -w0 your.jks`), `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.
