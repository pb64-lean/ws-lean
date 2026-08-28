module

public import Http2.Client
public import Http2.NameResolver
public import Http2.TrustAnchors
public import Ws.Connection
public import Ws.Http2.Handshake
public import Ws.Transport.Http1
public import Ws.Transport.Http2
public import Ws.Transport.Plain
public import Ws.Transport.Tls

public section

namespace Ws.Client

open Std
open Std.Async
open Std.Net

inductive VersionPolicy where
  | negotiate
  | http1Only
  | http2Only
  deriving Inhabited, Repr, BEq, DecidableEq

inductive TrustPolicy where
  | system
  | pem (anchors : String)
  | insecureSkipVerification
  deriving Inhabited, Repr, BEq, DecidableEq

structure Security where
  trust : TrustPolicy := .system
  deriving Inhabited, Repr, BEq, DecidableEq

structure Config where
  endpoint : Endpoint
  versionPolicy : VersionPolicy := .negotiate
  subprotocols : Array Handshake.Subprotocol := #[]
  compression? : Option PerMessageDeflate.ClientOffer := none
  origin? : Option String := none
  extraHeaders : Headers := #[]
  connection : Connection.Config := {}
  security : Security := {}
  openingTimeoutMs : Nat := 10000
  readSize : UInt64 := 16384

inductive ErrorKind where
  | invalidArgument
  | resolution
  | transport
  | tls
  | alpn
  | handshake
  | timeout
  | cancelled
  | runtime
  deriving Inhabited, Repr, BEq, DecidableEq

structure Error where
  kind : ErrorKind
  message : String
  deriving Inhabited, Repr, BEq, DecidableEq

structure Connected where
  connection : Connection.Connection
  subprotocol? : Option Handshake.Subprotocol
  compression? : Option PerMessageDeflate.Parameters
  version : Transport.Version

private structure AttemptCoordinator where
  active : Array String := #[]
  deriving Inhabited

private initialize attemptCoordinator : Std.Mutex AttemptCoordinator ← Std.Mutex.new {}

private def failure (kind : ErrorKind) (message : String) : Error := { kind, message }

private def releaseAttempt (key : String) : BaseIO Unit := do
  attemptCoordinator.atomically do
    modify fun state => { state with active := state.active.filter (· != key) }

private partial def acquireAttempt (key : String)
    (cancellation : Std.CancellationToken) : Async Unit := do
  if ← IO.checkCanceled then
    throw (IO.userError "connection-attempt lease was cancelled")
  if ← cancellation.isCancelled then
    throw (IO.userError "connection-attempt lease was cancelled")
  let acquired ← attemptCoordinator.atomically do
    let state ← get
    if state.active.contains key then
      pure false
    else
      set { state with active := state.active.push key }
      pure true
  unless acquired do
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    acquireAttempt key cancellation

private def withAttempt (key : String) (cancellation : Std.CancellationToken)
    (action : Async α) : Async α := do
  acquireAttempt key cancellation
  try
    let result ← action
    releaseAttempt key
    pure result
  catch error =>
    releaseAttempt key
    throw error

private def ofProtocol (error : Ws.Error) : Error :=
  failure (if error.kind == .invalidArgument then .invalidArgument else .handshake) error.message

private def extensions (compression? : Option PerMessageDeflate.ClientOffer) :
    Except Error (Array Handshake.Extension) := do
  match compression? with
  | none => pure #[]
  | some offer =>
      if let .atMost bits := offer.clientMaxWindowBits then
        if bits < 9 then
          throw (failure .invalidArgument
            "client_max_window_bits must be at least 9 for the production compressor")
      let value ← match offer.extensionValue with
        | .ok value => pure value
        | .error error => throw (ofProtocol error)
      match Handshake.parseExtensionItem value.toUTF8 with
      | .ok extension => pure #[extension]
      | .error error => throw (ofProtocol error)

private def compressionParameters (offer? : Option PerMessageDeflate.ClientOffer)
    (selected : Array Handshake.Extension) : Except Error (Option PerMessageDeflate.Parameters) :=
  match offer? with
  | none =>
      if selected.isEmpty then .ok none
      else .error (failure .handshake "server selected an unoffered WebSocket extension")
  | some offer =>
      match PerMessageDeflate.validateClientResponse offer selected with
      | .ok parameters => .ok parameters
      | .error error => .error (ofProtocol error)

private def resolveAddresses (endpoint : Endpoint) (cancellation : Std.CancellationToken) :
    Async (Except Error (Array Http2.NameResolver.Address)) := do
  let port := UInt16.ofNat endpoint.port
  match ← Http2.NameResolver.resolveHostAsync endpoint.serverName port (some cancellation) with
  | .error error => pure (.error (failure .resolution (toString error)))
  | .ok addresses =>
      if addresses.isEmpty then
        pure (.error (failure .resolution "name resolution returned no addresses"))
      else
        pure (.ok addresses)

private def http2Config (config : Config) (address : Http2.NameResolver.Address) :
    Http2.Client.Config := {
  address := address.socketAddress
  authority := config.endpoint.authority
  scheme := config.endpoint.scheme.httpName
  readSize := config.readSize
  maxHeaderListSize := some config.connection.limits.maxHandshakeBytes
  maxCompressedHeaderBlockSize := config.connection.limits.maxHandshakeBytes
}

private partial def awaitAsyncTaskWithin (task : AsyncTask α) (remainingMs : Nat) :
    Async Bool := do
  if ← IO.hasFinished task then
    pure true
  else if remainingMs == 0 then
    pure false
  else
    let slice := min remainingMs 10
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat slice)
    awaitAsyncTaskWithin task (remainingMs - slice)

private partial def openingTransportOperation (stream : Transport.ByteStream)
    (cancellation : Std.CancellationToken)
    (operation : Async (Except Transport.Failure α)) :
    Async (Except Transport.Failure α) := do
  if ← IO.checkCanceled then
    stream.abort
    return .error (Transport.Failure.cancelled "WebSocket opening was cancelled")
  if ← cancellation.isCancelled then
    stream.abort
    return .error (Transport.Failure.cancelled "WebSocket opening was cancelled")
  let task ← Async.toIO operation
  let rec wait : Async (Except Transport.Failure α) := do
    if ← IO.hasFinished task then
      Async.ofAsyncTask task
    else if (← IO.checkCanceled) || (← cancellation.isCancelled) then
      stream.abort
      -- The adapter retains its native continuation. Give it bounded time to
      -- observe abort without registering a losing task callback.
      if ← awaitAsyncTaskWithin task 200 then
        try discard <| Async.ofAsyncTask task catch _ => pure ()
      pure (.error (Transport.Failure.cancelled "WebSocket opening was cancelled"))
    else
      Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
      wait
  wait

private def withOpeningCancellation (stream : Transport.ByteStream)
    (cancellation : Std.CancellationToken) : Transport.ByteStream := {
  stream with
  recvImpl := fun _ => openingTransportOperation stream cancellation stream.recv?
  sendImpl := fun bytes => openingTransportOperation stream cancellation (stream.send bytes)
  finishSendImpl := fun _ => openingTransportOperation stream cancellation stream.finishSend
}

private inductive Timed (α : Type) where
  | completed (value : α)
  | expired
  | cancelled

private structure OpeningState where
  completed : Bool := false
  stopped : Bool := false

private def disposeConnected (result : Except Error Connected) : Async Unit := do
  if let .ok connected := result then
    Connection.requestAbort connected.connection
    try discard <| Connection.wait connected.connection catch _ => pure ()

private partial def awaitCommittedOpening
    (task : AsyncTask (Option (Except Error Connected))) :
    Async (Except Error Connected) := do
  if ← IO.hasFinished task then
    match ← Async.ofAsyncTask task with
    | some value => pure value
    | none => pure (.error (failure .runtime "WebSocket opening result was dropped"))
  else
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    awaitCommittedOpening task

private partial def awaitOpening (task : AsyncTask (Option (Except Error Connected)))
    (state : Std.Mutex OpeningState) (combined : Std.CancellationToken)
    (caller? : Option Std.CancellationToken) (remainingMs : Nat) :
    Async (Timed (Except Error Connected)) := do
  if ← IO.hasFinished task then
    match ← Async.ofAsyncTask task with
    | some value => return .completed value
    | none => return .expired
  let callerCancelled ← match caller? with
    | none => pure false
    | some caller => caller.isCancelled
  let forcedCancelled ← IO.checkCanceled
  if forcedCancelled || callerCancelled || remainingMs == 0 then
    let won ← state.atomically do
      let current ← get
      if current.completed then pure false
      else
        set { current with stopped := true }
        pure true
    if !won then
      pure (.completed (← awaitCommittedOpening task))
    else
      discard <| Http2.CancellationToken.cancel combined
      -- Native DNS/connect promises may still be in flight. Their retained
      -- action owns eventual socket and lease cleanup; caller latency remains
      -- bounded without force-cancelling that cleanup continuation.
      if ← awaitAsyncTaskWithin task 200 then
        try discard <| Async.ofAsyncTask task catch _ => pure ()
      pure (if forcedCancelled || callerCancelled then .cancelled else .expired)
  else
    let slice := min remainingMs 10
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat slice)
    awaitOpening task state combined caller? (remainingMs - slice)

private def withOpeningTimeout (milliseconds : Nat)
    (caller? : Option Std.CancellationToken)
    (action : Std.CancellationToken → Async (Except Error Connected)) :
    Async (Timed (Except Error Connected)) := do
  if let some caller := caller? then
    if ← caller.isCancelled then return .cancelled
  let cancellation ← Std.CancellationToken.new
  let state ← Std.Mutex.new {}
  let actionTask ← Async.toIO do
    let value ← action cancellation
    let won ← state.atomically do
      let current ← get
      if current.stopped then pure false
      else
        set { current with completed := true }
        pure true
    if won then pure (some value)
    else
      disposeConnected value
      pure none
  awaitOpening actionTask state cancellation caller? milliseconds

private def retireStream (stream : Transport.ByteStream) : Async Unit := do
  stream.abort
  let task ← Async.toIO stream.retire
  if ← awaitAsyncTaskWithin task 200 then
    try Async.ofAsyncTask task catch _ => pure ()
  else
    IO.cancel task

private def startRuntime (stream : Transport.ByteStream) (config : Config)
    (subprotocol? : Option Handshake.Subprotocol)
    (compression? : Option PerMessageDeflate.Parameters)
    (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  if ← cancellation.isCancelled then
    retireStream stream
    return .error (failure .timeout "WebSocket opening was cancelled")
  match ← Connection.start .client stream config.connection compression? with
  | .error error =>
      retireStream stream
      pure (.error (failure .runtime error.message))
  | .ok connection =>
      if ← cancellation.isCancelled then
        Connection.requestAbort connection
        try discard <| Connection.wait connection catch _ => pure ()
        pure (.error (failure .timeout "WebSocket opening was cancelled"))
      else pure (.ok {
        connection, subprotocol?, compression?, version := stream.version })

private def openHttp1 (stream : Transport.ByteStream) (config : Config)
    (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  let offeredExtensions ← match extensions config.compression? with
    | .ok values => pure values
    | .error error =>
        retireStream stream
        return .error error
  let nonce ← IO.getRandomBytes 16
  let offer ← match Handshake.Http1.ClientOffer.create config.endpoint nonce
      config.subprotocols offeredExtensions config.origin? config.extraHeaders with
    | .ok offer => pure offer
    | .error error =>
        retireStream stream
        return .error (ofProtocol error)
  match ← Transport.Http1.clientUpgrade stream offer config.connection.limits with
  | .error error =>
      retireStream stream
      pure (.error (failure (if error.kind == .transport then .transport else .handshake)
        error.message))
  | .ok (accepted, stream) =>
      let parameters ← match compressionParameters config.compression? accepted.extensions with
        | .ok parameters => pure parameters
        | .error error =>
            retireStream stream
            return .error error
      startRuntime stream config accepted.subprotocol? parameters cancellation

private def ownHttp2Connection (stream : Transport.ByteStream)
    (parent : Http2.Client.Connection) : Transport.ByteStream := {
  stream with
  retireImpl := fun _ => do
    try Http2.Client.close parent catch _ => pure ()
    try stream.retire catch _ => pure ()
}

private structure Http2OpenError where
  error : Error
  extendedConnectUnsupported : Bool := false

private def openHttp2 (parent : Http2.Client.Connection) (config : Config)
    (cancellation : Std.CancellationToken) :
    Async (Except Http2OpenError Connected) := do
  let offeredExtensions ← match extensions config.compression? with
    | .ok values => pure values
    | .error error =>
        Http2.Client.close parent
        return .error { error }
  let offer ← match Http2.Handshake.ClientOffer.create config.endpoint
      config.subprotocols offeredExtensions config.origin? config.extraHeaders with
    | .ok offer => pure offer
    | .error error =>
        Http2.Client.close parent
        return .error { error := ofProtocol error }
  let request ← match Http2.Handshake.buildClientRequest offer with
    | .ok request => pure request
    | .error error =>
        Http2.Client.close parent
        return .error { error := ofProtocol error }
  match ← parent.peerExtendedConnectEnabled (some cancellation) with
  | .error status =>
      Http2.Client.close parent
      return .error { error := failure .transport status.message }
  | .ok false =>
      Http2.Client.close parent
      return .error {
        error := failure .handshake "peer did not enable RFC 8441 Extended CONNECT",
        extendedConnectUnsupported := true
      }
  | .ok true => pure ()
  match ← parent.openExtendedConnect request (some cancellation) with
  | .error status =>
      Http2.Client.close parent
      pure (.error { error := failure .transport status.message })
  | .ok (.rejected response) =>
      Http2.Client.close parent
      let error := failure .handshake
        s!"WebSocket extended CONNECT was rejected with status {response.status}"
      pure (.error { error })
  | .ok (.accepted response tunnel) =>
      let accepted ← match Http2.Handshake.validateServerResponse offer response
          config.connection.limits with
        | .ok accepted => pure accepted
        | .error error =>
            try tunnel.cancel catch _ => pure ()
            Http2.Client.close parent
            return .error { error := ofProtocol error }
      let parameters ← match compressionParameters config.compression? accepted.extensions with
        | .ok parameters => pure parameters
        | .error error =>
            try tunnel.cancel catch _ => pure ()
            Http2.Client.close parent
            return .error { error }
      let stream := ownHttp2Connection (← Transport.Http2.ofTunnel tunnel) parent
      match ← startRuntime stream config accepted.subprotocol? parameters cancellation with
      | .ok connected => pure (.ok connected)
      | .error error => pure (.error { error })

private def plaintext (address : Http2.NameResolver.Address) (config : Config)
    (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  if config.versionPolicy == .http2Only then
    try
      let parent ← Http2.Client.connectAsync (http2Config config address) (some cancellation)
      match ← openHttp2 parent config cancellation with
      | .ok connected => pure (.ok connected)
      | .error error => pure (.error error.error)
    catch error =>
      pure (.error (failure .transport (toString error)))
  else
    let socket ← TCP.Socket.Client.mk
    try
      socket.connect address.socketAddress
      if ← cancellation.isCancelled then
        try socket.shutdown catch _ => pure ()
        return .error (failure .timeout "WebSocket TCP opening was cancelled")
      socket.noDelay
      let stream := withOpeningCancellation
        (← Transport.Plain.ofSocket socket { readSize := config.readSize }) cancellation
      openHttp1 stream config cancellation
    catch error =>
      try socket.shutdown catch _ => pure ()
      pure (.error (failure .transport (toString error)))

private def trustAnchors (security : Security) : IO (Except Error (Option String)) := do
  match security.trust with
  | .insecureSkipVerification => pure (.ok none)
  | .pem anchors =>
      if anchors.isEmpty then
        pure (.error (failure .invalidArgument "TLS trust-anchor PEM must not be empty"))
      else pure (.ok (some anchors))
  | .system =>
      match ← Http2.TrustAnchors.load with
      | .ok bundle => pure (.ok (some bundle.pem))
      | .error error => pure (.error (failure .tls (toString error)))

private def tlsConfig (config : Config) (anchors? : Option String)
    (protocols : Array String) : Http2.Client.TlsConfig :=
  let numericIdentity := (Std.Net.IPv4Addr.ofString config.endpoint.serverName).isSome ||
    (Std.Net.IPv6Addr.ofString config.endpoint.serverName).isSome
  {
    serverName := if numericIdentity then none else some config.endpoint.serverName
    verificationName := some config.endpoint.serverName
    alpnProtocols := protocols
    trustAnchorsPEM := anchors?
    verifyHostname := config.security.trust != .insecureSkipVerification
    insecureSkipVerification := config.security.trust == .insecureSkipVerification
  }

private def openTlsHttp1 (bootstrap : Http2.Client.TlsBootstrap) (config : Config)
    (cancellation : Std.CancellationToken) : Async (Except Error Connected) := do
  let stream := withOpeningCancellation
    (← Transport.Tls.ofClientSession bootstrap.session
      bootstrap.initialInbound { readSize := config.readSize }) cancellation
  openHttp1 stream config cancellation

private def retrySecureHttp1 (address : Http2.NameResolver.Address) (config : Config)
    (anchors? : Option String) (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  let bootstrap ← try
      Http2.Client.bootstrapTlsAsync (http2Config config address)
        (tlsConfig config anchors? #["http/1.1"]) (some cancellation)
    catch error => return .error (failure .tls (toString error))
  match ← bootstrap.session.alpnSelected with
  | some "http/1.1" | none => openTlsHttp1 bootstrap config cancellation
  | some protocol =>
      bootstrap.close
      pure (.error (failure .alpn
        s!"HTTP/1 fallback selected unsupported ALPN protocol {protocol}"))

private def secure (address : Http2.NameResolver.Address) (config : Config)
    (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  let anchors? ← match ← trustAnchors config.security with
    | .ok anchors => pure anchors
    | .error error => return .error error
  let protocols := match config.versionPolicy with
    | .negotiate => #["h2", "http/1.1"]
    | .http1Only => #["http/1.1"]
    | .http2Only => #["h2"]
  let bootstrap ← try
      Http2.Client.bootstrapTlsAsync (http2Config config address)
        (tlsConfig config anchors? protocols) (some cancellation)
    catch error => return .error (failure .tls (toString error))
  let selected ← bootstrap.session.alpnSelected
  match selected with
  | some "h2" =>
      if config.versionPolicy == .http1Only then
        bootstrap.close
        pure (.error (failure .alpn "server selected h2 for an HTTP/1-only connection"))
      else
        let adopted ← IO.mkRef (none : Option Http2.Client.Connection)
        let result : Except Http2OpenError Connected ← try
            let parent ← Http2.Client.Connection.adoptTlsH2Async
              (http2Config config address) bootstrap (some cancellation)
            adopted.set (some parent)
            openHttp2 parent config cancellation
          catch error =>
            match ← adopted.get with
            | some parent => Http2.Client.close parent
            | none => bootstrap.close
            pure (.error { error := failure .transport (toString error) })
        match result with
        | .ok connected => pure (.ok connected)
        | .error error =>
            if config.versionPolicy == .negotiate && error.extendedConnectUnsupported then
              -- RFC 8441 capability is learned only after the HTTP/2 peer
              -- SETTINGS arrive. HTTP/1.1 requires a fresh TLS connection and
              -- an HTTP/1-only ALPN offer; the same outer token and IP lease
              -- continue to own this retry.
              retrySecureHttp1 address config anchors? cancellation
            else pure (.error error.error)
  | some "http/1.1" =>
      if config.versionPolicy == .http2Only then
        bootstrap.close
        pure (.error (failure .alpn "server selected HTTP/1.1 for an HTTP/2-only connection"))
      else
        openTlsHttp1 bootstrap config cancellation
  | some protocol =>
      bootstrap.close
      pure (.error (failure .alpn s!"server selected unsupported ALPN protocol {protocol}"))
  | none =>
      if config.versionPolicy == .http2Only then
        bootstrap.close
        pure (.error (failure .alpn "server did not negotiate h2"))
      else
        openTlsHttp1 bootstrap config cancellation

private def preflight (config : Config) : Except Error Unit := do
  if config.openingTimeoutMs == 0 then
    throw (failure .invalidArgument "openingTimeoutMs must be positive")
  if config.readSize == 0 then
    throw (failure .invalidArgument "readSize must be positive")
  if config.connection.limits.maxHandshakeBytes == 0 ||
      config.connection.limits.maxStartLineBytes == 0 ||
      config.connection.limits.maxHeaderCount == 0 ||
      config.connection.limits.maxHeaderNameBytes == 0 ||
      config.connection.limits.maxHeaderValueBytes == 0 then
    throw (failure .invalidArgument "opening-handshake limits must be positive")
  if config.connection.limits.maxFramePayloadBytes == 0 ||
      config.connection.limits.maxMessagePayloadBytes == 0 ||
      config.connection.limits.maxFragmentsPerMessage == 0 then
    throw (failure .invalidArgument "runtime payload and fragment limits must be positive")
  if config.connection.fragmentSize == 0 ||
      config.connection.fragmentSize > config.connection.limits.maxFramePayloadBytes then
    throw (failure .invalidArgument
      "fragmentSize must be between 1 and maxFramePayloadBytes")
  if config.connection.closeTimeoutMs == 0 || config.connection.retireTimeoutMs == 0 then
    throw (failure .invalidArgument "close and retire timeouts must be positive")
  if config.connection.incomingCapacity == 0 then
    throw (failure .invalidArgument "incomingCapacity must be positive")
  if let .pem anchors := config.security.trust then
    if anchors.isEmpty then
      throw (failure .invalidArgument "TLS trust-anchor PEM must not be empty")
  let offered ← extensions config.compression?
  let nonce := ByteArray.mk (Array.replicate 16 (0 : UInt8))
  let h1 ← match Handshake.Http1.ClientOffer.create config.endpoint nonce
      config.subprotocols offered config.origin? config.extraHeaders with
    | .ok offer => pure offer
    | .error error => throw (ofProtocol error)
  match Handshake.Http1.buildClientRequest h1 with
  | .ok _ => pure ()
  | .error error => throw (ofProtocol error)
  unless config.versionPolicy == .http1Only do
    let h2 ← match Http2.Handshake.ClientOffer.create config.endpoint
        config.subprotocols offered config.origin? config.extraHeaders with
      | .ok offer => pure offer
      | .error error => throw (ofProtocol error)
    match Http2.Handshake.buildClientRequest h2 with
    | .ok _ => pure ()
    | .error error => throw (ofProtocol error)

private def connectOpeningCore (config : Config) (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  let addresses ← match ← resolveAddresses config.endpoint cancellation with
    | .ok addresses => pure addresses
    | .error error => return .error error
  let mut lastError := failure .transport "all resolved WebSocket addresses failed"
  for address in addresses do
    if ← cancellation.isCancelled then
      return .error (failure .timeout "WebSocket connection establishment was cancelled")
    let result ← withAttempt address.numericHost cancellation <|
      if config.endpoint.scheme.secure then secure address config cancellation
      else plaintext address config cancellation
    match result with
    | .ok connected => return .ok connected
    | .error error => lastError := error
  pure (.error lastError)

private def connectOpening (config : Config) (cancellation : Std.CancellationToken) :
    Async (Except Error Connected) := do
  try connectOpeningCore config cancellation catch error =>
    pure (.error (failure .transport (toString error)))

private def connectAsyncWithCaller (config : Config)
    (caller? : Option Std.CancellationToken) : Async (Except Error Connected) := do
  match preflight config with
  | .error error => pure (.error error)
  | .ok _ =>
      match ← withOpeningTimeout config.openingTimeoutMs caller? (connectOpening config) with
      | Timed.completed result => pure result
      | Timed.expired => pure (.error
          (failure .timeout "WebSocket connection establishment timed out"))
      | Timed.cancelled => pure (.error
          (failure .cancelled "WebSocket connection establishment was cancelled"))

/-- Asynchronously resolve, connect, negotiate the HTTP mapping, validate the
opening handshake, and start a protocol-owned WebSocket connection. The single
deadline token owns cooperative cleanup. A pinned native DNS/connect operation
may outlive the bounded caller wait; its retained continuation eventually
retires the socket and releases the per-address attempt lease. -/
def connectAsync (config : Config) : Async (Except Error Connected) :=
  connectAsyncWithCaller config none

/-- Connect with caller cancellation composed with the same opening deadline.
A token already cancelled before this call prevents DNS and socket work. -/
def connectAsyncWithCancellation (config : Config)
    (cancellation : Std.CancellationToken) : Async (Except Error Connected) :=
  connectAsyncWithCaller config (some cancellation)

/-- Synchronous wrapper for `connectAsync`. `wss` verifies the certificate
chain and endpoint hostname against system trust by default. -/
def connect (config : Config) : IO (Except Error Connected) :=
  Async.block (connectAsync config)

end Ws.Client
