# ws-lean

`ws-lean` is a WebSocket protocol and networking library for Lean 4. It
implements RFC 6455 framing and opening handshakes, RFC 7692
`permessage-deflate`, and RFC 8441 WebSockets over HTTP/2.

The project is pre-release. Protocol behavior is implemented and tested, but
the high-level API may still change before the first stable release.

## Scope

The library provides:

- bounded, incremental HTTP/1.1 handshake, frame, message, and UTF-8 parsers;
- client masking with a fresh operating-system random key for every frame;
- fragmentation, interleaved control frames, automatic Pong replies, and the
  closing handshake;
- optional `permessage-deflate`, including context-takeover and window-size
  negotiation, raw DEFLATE framing, and decompression limits;
- plain TCP and TLS transports;
- HTTP/1.1 Upgrade and HTTP/2 Extended CONNECT adapters; and
- retained asynchronous ownership for readers, writers, cancellation, and
  transport retirement.

The pure framing and handshake modules can be used independently as a sans-I/O
protocol layer. The connection runtime owns an already-upgraded byte stream.
The client performs connection and opening-handshake setup; the server accepts
an already-connected plain or TLS byte stream, or supplies a composable HTTP/2
Extended CONNECT handler.

HTTP proxies, WebSocket multiplexing extensions, and HTTP/3 are not currently
part of the library.

## Client

`Client.connect` resolves the endpoint, opens TCP or TLS, performs the selected
HTTP mapping and WebSocket handshake, and returns a running `Connection`:

```lean
import Ws

open Std.Async
open Ws

def main : IO Unit := do
  let endpoint ← match Endpoint.parse "wss://example.com/chat" with
    | .ok endpoint => pure endpoint
    | .error error => throw (IO.userError error.message)
  let connected ← match ← Client.connect {
      endpoint
      compression? := some { clientMaxWindowBits := .any }
    } with
    | .ok connected => pure connected
    | .error error => throw (IO.userError error.message)
  match ← Async.block (Connection.sendText connected.connection "hello") with
  | .ok _ => pure ()
  | .error error => throw (IO.userError error.message)
  match ← Async.block (Connection.receive connected.connection) with
  | .ok (some (.message _)) => IO.println "received a message"
  | .ok (some _) => IO.println "received a control event"
  | .ok none => IO.println "the peer ended the connection"
  | .error error => throw (IO.userError error.message)
  match ← Async.block (Connection.close connected.connection) with
  | .ok _ => pure ()
  | .error error => throw (IO.userError error.message)
```

The default `.negotiate` version policy uses HTTP/1.1 or HTTP/2 according to
TLS ALPN and RFC 8441 capability. `.http1Only` and `.http2Only` are strict
alternatives. `connectAsyncWithCancellation` composes caller cancellation with
the finite opening timeout. Send cancellation applies before bounded queue
admission; once admitted, a write is connection-owned and the caller observes
its eventual result. Receive cancellation does not leave a hidden consumer
that could take a later event.

`wss` uses system trust and verifies both the certificate chain and endpoint
identity by default. A PEM trust-anchor string can be supplied with
`TrustPolicy.pem`. `TrustPolicy.insecureSkipVerification` is an explicit test
or diagnostic escape hatch and must not be used for production traffic.

Compression is disabled unless the client supplies a `ClientOffer` and the
server selects it. Once negotiated, messages at least `compressionThreshold`
bytes are compressed by default; `Connection.SendOptions.compress?` overrides
that choice per message.

## Server

Server policy is shared by the two HTTP mappings. `handleHttp1` owns one
already-accepted plain or TLS stream. `extendedConnectHandler` produces a
handler that can be installed in an HTTP/2 application table:

```lean
import Ws

open Std.Async
open Ws

def policy : Server.Policy := fun request => do
  if request.target == "/chat" then
    pure (.accept { compression := { enabled := true } })
  else
    pure (.reject { status := 404 })

def echo (session : Server.Session) : Async Unit := do
  let mut running := true
  while running do
    match ← Connection.receive session.connection with
    | .ok (some (.message message)) =>
        match ← Connection.send session.connection message with
        | .ok _ => pure ()
        | .error error => throw (IO.userError error.message)
    | .ok (some (.close _)) | .ok none => running := false
    | .ok (some _) => pure ()
    | .error error => throw (IO.userError error.message)

def serveHttp1 (stream : Transport.ByteStream) :
    Async (Except Server.Error Unit) :=
  Server.handleHttp1 stream policy echo

def websocketOverHttp2 :
    Except Server.Error Http2.ExtendedConnect.Handler :=
  Server.extendedConnectHandler policy echo
```

For an accepted TLS HTTP/1 stream, pass
`context := { scheme := "https" }`; TLS authentication and listener ownership
remain with the accepting server. Each handler owns the accepted session until
the application callback returns, then completes or aborts shutdown and
retires the transport. Opening policy has a finite timeout, and HTTP/1 response
writes have their own finite budget. A policy callback that ignores
cancellation may continue computing after an opening timeout, but the handler
exclusively commits the handshake result so that callback cannot send a late
response.

## Build and test

Bazel is authoritative:

```sh
bazel build //...
bazel test //...
```

The checked-in Bazel lock file and Lean toolchain pin make those commands
reproducible. The Lake package exists for editor integration only.

The interoperability runner is manual because it requires Docker:

```sh
Conformance/run-autobahn-server.sh
```

It uses a pinned Autobahn Testsuite image, omits only the explicitly
limits/performance-oriented category 9, covers compression categories 12 and
13, and rejects non-strict, unclean, wrong-code, or otherwise failing reports.
See [Conformance/README.md](Conformance/README.md) for focused runs and report
retention.

## Security defaults

Secure client connections load the system trust store, verify the certificate
chain and endpoint identity, send SNI for DNS names, and select the transport
from the negotiated ALPN protocol. When transport negotiation selects HTTP/2
but the peer's SETTINGS omit Extended CONNECT support, the default negotiation
policy retires that connection and retries once with a fresh HTTP/1.1-only TLS
connection; explicit HTTP/2-only mode does not downgrade. Plain `ws` remains
available when transport security is deliberately not required. Endpoint
parsing accepts ASCII URIs and already-IDNA-encoded DNS names; ambiguous numeric
names, percent-encoded hosts, IPvFuture literals, IPv6 zone identifiers, and
IRIs are rejected.

Peer-controlled handshake, frame, message, fragment, and inflated-payload sizes
are bounded before application delivery. HTTP field injection, invalid masking,
reserved opcodes and bits, non-minimal lengths, invalid close codes, malformed
UTF-8, and unnegotiated compression are rejected with typed failures and the
applicable WebSocket close status.

Application delivery uses a bounded queue without blocking the protocol reader.
Exhausting that queue terminates the connection with Close 1008, preserving
bounded memory and control-frame liveness. Each Ping is answered before its
observable event is offered to the application. Frames are processed in wire
order; a valid peer Close is replied to exactly once, retained in the termination
result, offered to the application when capacity remains, and ends message
processing without inspecting coalesced data after it.

The pinned networking runtime cannot cancel an operating-system DNS request,
connect, or write that is already in flight. Cooperative opening cancellation
requests transport shutdown and gives cleanup a bounded grace period. If a
native operation has not settled, its retained continuation later retires the
socket and releases the per-address attempt lease. Connection shutdown likewise
bounds Lean task ownership and may leave an in-flight native promise or
descriptor to settle under the operating system and runtime finalizer.

`permessage-deflate` can expose secrets through compression side channels when
an application places attacker-controlled and confidential values in the same
compression context. Applications should disable compression or disable
context takeover for such traffic.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the precise
trusted-computing boundary.

## Standards

- [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)
- [RFC 7692 — Compression Extensions for WebSocket](https://www.rfc-editor.org/rfc/rfc7692)
- [RFC 8441 — Bootstrapping WebSockets with HTTP/2](https://www.rfc-editor.org/rfc/rfc8441)

## License

Apache License 2.0. See [LICENSE](LICENSE).
