import Std.Async.TCP
import Ws.Client
import Ws.Server
import Ws.Transport.Plain

open Std
open Std.Async
open Std.Net
open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def loopback (port : UInt16) : SocketAddress :=
  .v4 { addr := IPv4Addr.ofParts 127 0 0 1, port }

def portOf (address : SocketAddress) : UInt16 :=
  match address with
  | .v4 address => address.port
  | .v6 address => address.port

def endpointAt (port : UInt16) : IO Endpoint :=
  match Endpoint.parse s!"ws://127.0.0.1:{port}/echo?mapping=integration" with
  | .ok endpoint => pure endpoint
  | .error error => throw (IO.userError error.message)

def secureEndpointAt (port : UInt16) : IO Endpoint :=
  match Endpoint.parse s!"wss://localhost:{port}/echo?mapping=integration" with
  | .ok endpoint => pure endpoint
  | .error error => throw (IO.userError error.message)

def testCertificateDerBase64 : String :=
  "MIIBWTCCAQugAwIBAgIUX7IBGCS/gSkjlT1Ec2omk0S8TCwwBQYDK2VwMBQxEjAQ" ++
  "BgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MTkxOTU3NDlaFw0zNjA3MTYxOTU3NDla" ++
  "MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAFngb4lCtT/37Uw438+r" ++
  "FjO/ya84CP0j+mM1L27fAiKWo28wbTAdBgNVHQ4EFgQUnRsarGS2CrWaueTK0WKb" ++
  "YUczOhYwHwYDVR0jBBgwFoAUnRsarGS2CrWaueTK0WKbYUczOhYwDwYDVR0TAQH/" ++
  "BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwBQYDK2VwA0EAUbom" ++
  "qwelv4vI3Nu7vG12whcKsFFb9qJ8xGFeXa02BZ6j/pkd3a0BzKMAlIUODaWYjzts" ++
  "5p5ZPTIrJkcgBo3ZAA=="

def testSigningKeyBase64 : String :=
  "Rxdhl02hKTiXfsobQMwOo9bpxSiXZIoWYWgeiP0x9L4="

def testCertificatePem : String :=
  "-----BEGIN CERTIFICATE-----\n" ++
  "MIIBWTCCAQugAwIBAgIUX7IBGCS/gSkjlT1Ec2omk0S8TCwwBQYDK2VwMBQxEjAQ\n" ++
  "BgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MTkxOTU3NDlaFw0zNjA3MTYxOTU3NDla\n" ++
  "MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAFngb4lCtT/37Uw438+r\n" ++
  "FjO/ya84CP0j+mM1L27fAiKWo28wbTAdBgNVHQ4EFgQUnRsarGS2CrWaueTK0WKb\n" ++
  "YUczOhYwHwYDVR0jBBgwFoAUnRsarGS2CrWaueTK0WKbYUczOhYwDwYDVR0TAQH/\n" ++
  "BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwBQYDK2VwA0EAUbom\n" ++
  "qwelv4vI3Nu7vG12whcKsFFb9qJ8xGFeXa02BZ6j/pkd3a0BzKMAlIUODaWYjzts\n" ++
  "5p5ZPTIrJkcgBo3ZAA==\n" ++
  "-----END CERTIFICATE-----\n"

def decodeFixture (label value : String) : IO ByteArray :=
  match Base64.decodeCanonical value with
  | .ok bytes => pure bytes
  | .error error => throw (IO.userError s!"invalid {label}: {error.message}")

def tlsServerConfig (protocols : List String) : IO Tls.Server.Config := do
  let entropy ← IO.getRandomBytes 64
  pure {
    serverRandom := entropy.extract 0 32
    x25519Private := entropy.extract 32 64
    certificateChain := #[← decodeFixture "test certificate" testCertificateDerBase64]
    signingKey := ← decodeFixture "test signing key" testSigningKeyBase64
    alpnProtocols := protocols
  }

partial def receiveMessage (connection : Connection.Connection) :
    Async Message.Message := do
  match ← Connection.receive connection with
  | .ok (some (.message message)) => pure message
  | .ok (some (.ping _)) | .ok (some (.pong _)) => receiveMessage connection
  | .ok (some (.close _)) => throw (IO.userError "peer closed before sending the echo")
  | .ok none => throw (IO.userError "peer ended before sending the echo")
  | .error error => throw (IO.userError error.message)

def echoApplication (session : Server.Session) : Async Unit := do
  let message ← receiveMessage session.connection
  match ← Connection.send session.connection message with
  | .error error => throw (IO.userError error.message)
  | .ok _ => pure ()
  let mut closing := false
  while !closing do
    match ← Connection.receive session.connection with
    | .ok (some (.close _)) | .ok none => closing := true
    | .ok (some _) => pure ()
    | .error error => throw (IO.userError error.message)

def selectedProtocol : IO Handshake.Subprotocol :=
  match Handshake.Subprotocol.parse "lean.echo.v1" with
  | .ok protocol => pure protocol
  | .error error => throw (IO.userError error.message)

def policy (protocol : Handshake.Subprotocol) : Server.Policy := fun request => do
  expect (request.target == "/echo?mapping=integration")
    "server observed the wrong request target"
  expect (request.subprotocols.contains protocol)
    "server did not observe the offered subprotocol"
  pure (.accept {
    subprotocol? := some protocol
    compression := {
      enabled := true
      serverNoContextTakeover := true
      clientNoContextTakeover := true
    }
  })

def exerciseClient (endpoint : Endpoint) (versionPolicy : Client.VersionPolicy)
    (expectedVersion : Transport.Version) (protocol : Handshake.Subprotocol)
    (security : Client.Security := {}) : IO Unit := do
  let connected ← match ← Client.connect {
      endpoint
      versionPolicy
      subprotocols := #[protocol]
      compression? := some {
        serverNoContextTakeover := true
        clientNoContextTakeover := true
        clientMaxWindowBits := .any
      }
      connection := { compressionThreshold := 0 }
      security
    } with
  | .ok connected => pure connected
  | .error error => throw (IO.userError s!"client opening failed: {error.message}")
  expect (connected.version == expectedVersion) "client selected the wrong HTTP mapping"
  expect (connected.subprotocol? == some protocol) "subprotocol negotiation did not round-trip"
  expect connected.compression?.isSome "permessage-deflate was not negotiated"
  let payload := "public API integration payload"
  match ← Async.block (Connection.sendText connected.connection payload) with
  | .error error => throw (IO.userError s!"client send failed: {error.message}")
  | .ok _ => pure ()
  let echoed ← Async.block (receiveMessage connected.connection)
  expect (echoed.kind == .text && echoed.data == payload.toUTF8 && !echoed.compressed)
    "public API echo changed the message"
  match ← Async.block (Connection.close connected.connection) with
  | .error error => throw (IO.userError s!"client close failed: {error.message}")
  | .ok termination => expect (termination.kind == .clean) "client close was not clean"

def http1Integration : IO Unit := do
  let protocol ← selectedProtocol
  let listener ← Std.Async.TCP.Socket.Server.mk
  listener.bind (loopback 0)
  listener.listen 8
  listener.noDelay
  let address ← listener.getSockName
  let serverTask ← Async.toIO do
    let socket ← listener.accept
    let stream ← Transport.Plain.ofSocket socket
    match ← Server.handleHttp1 stream (policy protocol) echoApplication with
    | .ok _ => pure ()
    | .error error => throw (IO.userError s!"HTTP/1 server failed: {error.message}")
  exerciseClient (← endpointAt (portOf address)) .http1Only .http1 protocol
  Async.block (Async.ofAsyncTask serverTask)

def http2Integration : IO Unit := do
  let protocol ← selectedProtocol
  let handler ← match Server.extendedConnectHandler (policy protocol) echoApplication with
  | .ok handler => pure handler
  | .error error => throw (IO.userError s!"HTTP/2 handler setup failed: {error.message}")
  let server ← Http2.Server.serveApplications {
    extendedConnect := some handler
  } { address := Http2.Server.loopback 0 }
  try
    exerciseClient (← endpointAt (portOf server.localAddress)) .http2Only .http2 protocol
  finally
    Http2.Server.shutdown server
    Http2.Server.wait server (some 3000)

def secureHttp1Integration : IO Unit := do
  let protocol ← selectedProtocol
  let listener ← Std.Async.TCP.Socket.Server.mk
  listener.bind (loopback 0)
  listener.listen 8
  listener.noDelay
  let address ← listener.getSockName
  let serverTask ← Async.toIO do
    let socket ← listener.accept
    let (session, initialInbound) ← Http2.Tls.ServerSession.establishWithLeftover socket
      (← tlsServerConfig ["http/1.1"])
    expect ((← session.alpnSelected) == some "http/1.1")
      "secure HTTP/1 server negotiated the wrong ALPN protocol"
    let stream ← Transport.Tls.ofServerSession session initialInbound
    match ← Server.handleHttp1 stream (policy protocol) echoApplication (context := {
        scheme := "https"
      }) with
    | .ok _ => pure ()
    | .error error => throw (IO.userError s!"secure HTTP/1 server failed: {error.message}")
  exerciseClient (← secureEndpointAt (portOf address)) .http1Only .http1 protocol {
    trust := .pem testCertificatePem
  }
  Async.block (Async.ofAsyncTask serverTask)

def secureHttp2Integration : IO Unit := do
  let protocol ← selectedProtocol
  let handler ← match Server.extendedConnectHandler (policy protocol) echoApplication with
  | .ok handler => pure handler
  | .error error => throw (IO.userError s!"secure HTTP/2 handler setup failed: {error.message}")
  let server ← Http2.Server.serveTlsApplications {
    extendedConnect := some handler
  } {
    certificateChain := #[← decodeFixture "test certificate" testCertificateDerBase64]
    signingKey := ← decodeFixture "test signing key" testSigningKeyBase64
  } { address := Http2.Server.loopback 0 }
  try
    exerciseClient (← secureEndpointAt (portOf server.localAddress))
      .http2Only .http2 protocol { trust := .pem testCertificatePem }
  finally
    Http2.Server.shutdown server
    Http2.Server.wait server (some 3000)

def main : IO Unit := do
  http1Integration
  http2Integration
  secureHttp1Integration
  secureHttp2Integration
  IO.println "public client/server integration tests passed"
