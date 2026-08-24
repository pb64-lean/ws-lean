import Ws.Endpoint
import Ws.Header

open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectError {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def main : IO Unit := do
  let plain ← take "plain endpoint" (Endpoint.parse "ws://Example.COM/chat?room=blue")
  expect (plain.scheme == .ws && plain.host == "Example.COM" && plain.port == 80)
    "plain endpoint authority differs"
  expect (!plain.explicitPort && plain.http1RequestTarget == "/chat?room=blue" &&
    plain.http2RequestTarget == "/chat?room=blue")
    "plain endpoint target differs"
  expect (plain.uri == "ws://Example.COM/chat?room=blue") "plain URI reconstruction differs"

  let secure ← take "secure endpoint" (Endpoint.parse "WSS://example.com:8443")
  expect (secure.scheme == .wss && secure.port == 8443 && secure.explicitPort)
    "secure endpoint differs"
  expect (secure.http1RequestTarget == "/" && secure.http2RequestTarget == "/" &&
    secure.authority == "example.com:8443")
    "secure endpoint normalization differs"

  let emptyQuery ← take "empty query endpoint" (Endpoint.parse "ws://example.com?")
  expect (emptyQuery.http1RequestTarget == "/" &&
    emptyQuery.http2RequestTarget == "/?")
    "an empty query did not use the transport-specific request target"
  expect (emptyQuery.uri == "ws://example.com/?")
    "URI reconstruction did not preserve the empty query component"
  let slashEmptyQuery ← take "slash empty query endpoint"
    (Endpoint.parse "ws://example.com/?")
  expect (slashEmptyQuery.http1RequestTarget == "/" &&
    slashEmptyQuery.http2RequestTarget == "/?" &&
    slashEmptyQuery.uri == "ws://example.com/?")
    "an explicit slash with an empty query was mapped incorrectly"

  let ipv6 ← take "IPv6 endpoint" (Endpoint.parse "ws://[2001:db8::1]:80/a%20b")
  expect (ipv6.host == "[2001:db8::1]" && ipv6.serverName == "2001:db8::1")
    "IPv6 host normalization differs"
  expect (ipv6.authority == "[2001:db8::1]:80") "explicit default port was lost"
  let ipv4 ← take "canonical IPv4 endpoint" (Endpoint.parse "ws://127.0.0.1/")
  expect (ipv4.serverName == "127.0.0.1") "canonical IPv4 host was changed"

  for (label, uri) in #[
    ("wrong scheme", "http://example.com/"),
    ("userinfo", "ws://user@example.com/"),
    ("fragment", "ws://example.com/#x"),
    ("empty host", "ws:///x"),
    ("empty port", "ws://example.com:/"),
    ("zero port", "ws://example.com:0/"),
    ("large port", "ws://example.com:65536/"),
    ("unbracketed IPv6", "ws://2001:db8::1/"),
    ("bad IPv6", "ws://[2001:db8::zz]/"),
    ("IPv6 zone", "ws://[fe80::1%25eth0]/"),
    ("IPvFuture", "ws://[v1.example]/"),
    ("percent-encoded host", "ws://exa%6dple.com/"),
    ("non-ASCII host with ASCII low byte", "ws://Ł.example/"),
    ("ambiguous numeric host", "ws://127.1/"),
    ("leading-zero IPv4 host", "ws://127.0.0.01/"),
    ("out-of-range IPv4 host", "ws://256.0.0.1/"),
    ("trailing-dot numeric host", "ws://127.0.0.1./"),
    ("hexadecimal IPv4 host", "ws://0x7f000001/"),
    ("mixed hexadecimal IPv4 host", "ws://0x7f.0.0.1/"),
    ("trailing-dot hexadecimal IPv4 host", "ws://0x7f000001./"),
    ("non-ASCII port digit with ASCII low byte", "ws://example.com:ı/"),
    ("bad percent", "ws://example.com/%2"),
    ("non-ASCII percent hex with ASCII low byte", "ws://example.com/%Ł1"),
    ("raw space", "ws://example.com/a b"),
    ("raw angle", "ws://example.com/<x>")
  ] do
    expectError label (Endpoint.parse uri)

  let header ← take "header" (Header.ofBytes "X-Binary"
    (ByteArray.mk #[0x20, 0x61, 0x80, 0x62, 0x09]))
  expect (header.name == "x-binary" && header.value == ByteArray.mk #[0x61, 0x80, 0x62])
    "header normalization or obs-text preservation differs"
  expectError "invalid header name" (Header.ofString "bad name" "x")
  expectError "DEL in field value" (Header.ofBytes "x" (ByteArray.mk #[0x7f]))
  expectError "NUL in field value" (Header.ofBytes "x" (ByteArray.mk #[0]))

  let mut headers : Headers := #[]
  headers ← take "first connection" (headers.insert "Connection" "keep-alive, Upgrade")
  headers ← take "second connection" (headers.insert "connection" "x-token")
  expect ((← take "connection token" (Headers.containsTokenCi headers "connection" "upgrade")))
    "case-insensitive connection token was not found"
  let tokens ← take "connection tokens" (Headers.tokenItems headers "connection")
  expect (tokens == #["keep-alive", "Upgrade", "x-token"])
    "repeated comma-list combination differs"

  let emptyList ← take "empty list setup"
    (Headers.empty.insert "connection" ", upgrade,,keep-alive, ")
  expect ((← take "empty comma-list members" (Headers.commaItems emptyList "connection")) ==
    #["upgrade".toUTF8, "keep-alive".toUTF8])
    "HTTP empty comma-list members were not ignored"
  let quotedAcross1 ← take "quoted line one"
    (Headers.empty.insert "x-list" "token; p=\"unterminated")
  let quotedAcross2 ← take "quoted line two"
    (quotedAcross1.insert "x-list" "continued\"")
  expectError "quoted string across field lines" (Headers.commaItems quotedAcross2 "x-list")

  let serialized ← take "serialize headers" (Headers.serialize #[header])
  expect (serialized == ByteArray.mk #[
    0x78, 0x2d, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x3a, 0x20,
    0x61, 0x80, 0x62, 0x0d, 0x0a
  ]) "header serialization changed obs-text"

  IO.println "endpoint and header tests passed"
