module

public import Http2.Server
public import Ws.Connection
public import Ws.Http2.Handshake
public import Ws.Transport.Http1
public import Ws.Transport.Http2

public section

namespace Ws.Server

open Std.Async

inductive ErrorKind where
  | invalidArgument
  | handshake
  | policy
  | transport
  | timeout
  | runtime
  | application
  deriving Inhabited, Repr, BEq, DecidableEq

structure Error where
  kind : ErrorKind
  message : String
  deriving Inhabited, Repr, BEq, DecidableEq

/-- Transport-independent opening metadata presented to server policy. -/
structure Request where
  mapping : Transport.Version
  scheme : String
  authority : String
  target : String
  origin? : Option String
  subprotocols : Array Handshake.Subprotocol
  extensions : Array Handshake.Extension
  headers : Headers

/-- A policy-controlled successful opening. Compression is selected only when
the peer offered a compatible permessage-deflate alternative. -/
structure Acceptance where
  subprotocol? : Option Handshake.Subprotocol := none
  compression : PerMessageDeflate.ServerConfig := {}
  extraHeaders : Headers := #[]

/-- A final HTTP rejection. Statuses are restricted to 400--599. -/
structure Rejection where
  status : Nat := 403
  reason : String := ""
  advertiseVersion : Bool := false
  extraHeaders : Headers := #[]

inductive Decision where
  | accept (acceptance : Acceptance)
  | reject (rejection : Rejection)

abbrev Policy := Request → Async Decision

structure Session where
  connection : Connection.Connection
  request : Request
  subprotocol? : Option Handshake.Subprotocol
  compression? : Option PerMessageDeflate.Parameters

/-- The application owns the session for the duration of this callback. When
it returns, the handler completes or aborts the close handshake and retires the
transport before returning to its caller. -/
abbrev Application := Session → Async Unit

structure Config where
  connection : Connection.Config := {}
  openingTimeoutMs : Nat := 10000
  openingWriteTimeoutMs : Nat := 5000
  retirementTimeoutMs : Nat := 200
  onError : Error → IO Unit := fun _ => pure ()

structure Http1Context where
  /-- `http` for a plain accepted socket and `https` for an accepted TLS
  stream. The value is exposed to policy; the HTTP/1 request does not carry it. -/
  scheme : String := "http"

private def failure (kind : ErrorKind) (message : String) : Error := { kind, message }

private def ofWsError (error : Ws.Error) : Error :=
  failure (if error.kind == .invalidArgument then .invalidArgument else .handshake) error.message

private def ofUpgradeFailure (error : Transport.Http1.UpgradeFailure) : Error :=
  failure (if error.kind == .transport || error.kind == .unexpectedEof then .transport else .handshake)
    error.message

private def validateConfig (config : Config) : Except Error Unit := do
  if config.openingTimeoutMs == 0 || config.openingWriteTimeoutMs == 0 ||
      config.retirementTimeoutMs == 0 then
    throw (failure .invalidArgument "server opening and retirement timeouts must be positive")
  let runtime := config.connection
  if runtime.limits.maxHandshakeBytes == 0 || runtime.limits.maxStartLineBytes == 0 ||
      runtime.limits.maxHeaderCount == 0 || runtime.limits.maxHeaderNameBytes == 0 ||
      runtime.limits.maxHeaderValueBytes == 0 || runtime.limits.maxFramePayloadBytes == 0 ||
      runtime.limits.maxMessagePayloadBytes == 0 ||
      runtime.limits.maxFragmentsPerMessage == 0 then
    throw (failure .invalidArgument "server protocol limits must be positive")
  if runtime.fragmentSize == 0 || runtime.fragmentSize > runtime.limits.maxFramePayloadBytes then
    throw (failure .invalidArgument
      "server fragmentSize must be between 1 and maxFramePayloadBytes")
  if runtime.closeTimeoutMs == 0 || runtime.retireTimeoutMs == 0 then
    throw (failure .invalidArgument "server close and runtime-retirement timeouts must be positive")
  if runtime.incomingCapacity == 0 then
    throw (failure .invalidArgument "server incomingCapacity must be positive")

private inductive Timed (α : Type) where
  | completed (value : α)
  | expired

private structure DeadlineGate where
  expiresAtMs : Nat
  expired : Bool := false

private def newDeadlineGate (milliseconds : Nat) : BaseIO (Std.Mutex DeadlineGate) := do
  Std.Mutex.new { expiresAtMs := (← IO.monoMsNow) + milliseconds }

private def deadlineExpired (gate : Std.Mutex DeadlineGate) : BaseIO Bool := do
  let now ← IO.monoMsNow
  gate.atomically do
    let state ← get
    if state.expired || state.expiresAtMs <= now then
      unless state.expired do set { state with expired := true }
      pure true
    else
      pure false

private def effectiveDeadline (gate : Std.Mutex DeadlineGate)
    (milliseconds : Nat) : BaseIO Nat := do
  let localDeadline := (← IO.monoMsNow) + milliseconds
  gate.atomically do pure (min (← get).expiresAtMs localDeadline)

private def expireDeadline (gate : Std.Mutex DeadlineGate) : BaseIO Unit :=
  gate.atomically do modify fun state => { state with expired := true }

private def deadlineWasExpired (gate : Std.Mutex DeadlineGate) : BaseIO Bool :=
  gate.atomically do pure (← get).expired

private partial def awaitTimedTask (gate : Std.Mutex DeadlineGate)
    (task : AsyncTask (Nat × α)) (expiresAtMs : Nat) : Async (Timed α) := do
  if ← IO.hasFinished task then
    let (completedAtMs, value) ← Async.ofAsyncTask task
    if completedAtMs <= expiresAtMs && !(← deadlineWasExpired gate) then
      pure (.completed value)
    else
      expireDeadline gate
      pure .expired
  else
    let now ← IO.monoMsNow
    if expiresAtMs <= now || (← deadlineExpired gate) then
      expireDeadline gate
      -- A non-interruptible callback may settle later. Callers arrange for the
      -- retained continuation to perform no further protocol-visible action.
      IO.cancel task
      pure .expired
    else
      -- Polling with a short retained sleep avoids the losing full-duration
      -- timer task that `IO.cancel` cannot interrupt in the pinned runtime.
      let slice := min (expiresAtMs - now) 10
      Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat slice)
      awaitTimedTask gate task expiresAtMs

private def boundedActionWithGate (gate : Std.Mutex DeadlineGate)
    (milliseconds : Nat) (action : Async α) : Async (Timed α) := do
  let expiresAtMs ← effectiveDeadline gate milliseconds
  if ← deadlineExpired gate then return .expired
  let actionTask ← Async.toIO do
    let value ← action
    pure ((← IO.monoMsNow), value)
  if ← deadlineExpired gate then
    -- A non-interruptible callback may settle later. The shared gate prevents
    -- its retained continuation from committing an HTTP opening side effect.
    IO.cancel actionTask
    pure .expired
  else
    awaitTimedTask gate actionTask expiresAtMs

private def boundedWithGate (stream : Transport.ByteStream)
    (gate : Std.Mutex DeadlineGate) (milliseconds : Nat)
    (action : Async α) : Async (Timed α) := do
  try
    match ← boundedActionWithGate gate milliseconds action with
    | .completed value => pure (.completed value)
    | .expired =>
        stream.abort
        pure .expired
  catch error =>
    stream.abort
    throw error

private def bounded (stream : Transport.ByteStream) (milliseconds : Nat)
    (action : Async α) : Async (Timed α) := do
  let gate ← newDeadlineGate milliseconds
  boundedWithGate stream gate milliseconds action

private def retireStream (stream : Transport.ByteStream) (config : Config) : Async Unit := do
  stream.abort
  try discard <| bounded stream config.retirementTimeoutMs stream.retire catch _ => pure ()

private structure Negotiated where
  parameters? : Option PerMessageDeflate.Parameters := none
  responseExtensions : Array Handshake.Extension := #[]

private def negotiate (request : Request) (acceptance : Acceptance) : Except Error Negotiated := do
  let selection? ← match PerMessageDeflate.selectServer acceptance.compression request.extensions with
    | .ok value => pure value
    | .error error => throw (ofWsError error)
  match selection? with
  | none => pure {}
  | some selection =>
      let extension ← match Handshake.parseExtensionItem selection.responseValue.toUTF8 with
        | .ok extension => pure extension
        | .error error => throw (ofWsError error)
      pure { parameters? := some selection.parameters, responseExtensions := #[extension] }

private def managedRejectionHeader (name : String) : Bool :=
  name == "connection" || name == "content-length" || name == "transfer-encoding" ||
    name == "upgrade" || name == "sec-websocket-version"

private def validateRejection (rejection : Rejection) : Except Error Unit := do
  unless 400 <= rejection.status && rejection.status <= 599 do
    throw (failure .invalidArgument "WebSocket rejection status must be between 400 and 599")
  for header in rejection.extraHeaders do
    let checked ← match Header.ofBytes header.name header.value with
      | .ok checked => pure checked
      | .error error => throw (ofWsError error)
    if managedRejectionHeader checked.name then
      throw (failure .invalidArgument s!"rejection field {checked.name} is managed by the server")

private def reasonPhrase (status : Nat) : String :=
  match status with
  | 400 => "Bad Request"
  | 403 => "Forbidden"
  | 404 => "Not Found"
  | 426 => "Upgrade Required"
  | 429 => "Too Many Requests"
  | 500 => "Internal Server Error"
  | 503 => "Service Unavailable"
  | _ => "WebSocket Rejected"

private def buildHttp1Rejection (rejection : Rejection) : Except Error ByteArray := do
  validateRejection rejection
  let reasonBytes := rejection.reason.toUTF8
  unless reasonBytes.toList.all fun byte => byte == 0x09 || (0x20 <= byte && byte <= 0x7e) do
    throw (failure .invalidArgument "HTTP/1 rejection reason must contain ASCII field-value bytes")
  let reason := if rejection.reason.isEmpty then reasonPhrase rejection.status else rejection.reason
  let mut headers : Headers := #[]
  headers ← match headers.insert "Connection" "close" with
    | .ok nextHeaders => pure nextHeaders
    | .error error => throw (ofWsError error)
  headers ← match headers.insert "Content-Length" "0" with
    | .ok nextHeaders => pure nextHeaders
    | .error error => throw (ofWsError error)
  if rejection.status == 426 then
    headers ← match headers.insert "Upgrade" "websocket" with
      | .ok nextHeaders => pure nextHeaders
      | .error error => throw (ofWsError error)
  if rejection.advertiseVersion then
    headers ← match headers.insert "Sec-WebSocket-Version" "13" with
      | .ok nextHeaders => pure nextHeaders
      | .error error => throw (ofWsError error)
  headers := headers.append rejection.extraHeaders
  let fields ← match Headers.serialize headers with
    | .ok fields => pure fields
    | .error error => throw (ofWsError error)
  pure <| s!"HTTP/1.1 {rejection.status} {reason}\r\n".toUTF8.append fields |>.append "\r\n".toUTF8

private def openingTimeoutError : Error :=
  failure .timeout "timed out opening the HTTP/1 WebSocket connection"

private def rejectHttp1 (stream : Transport.ByteStream) (config : Config)
    (gate : Std.Mutex DeadlineGate) (rejection : Rejection) : Async (Except Error Unit) := do
  let wire ← match buildHttp1Rejection rejection with
    | .ok wire => pure wire
    | .error error =>
        retireStream stream config
        return .error error
  let sent ← try
      boundedWithGate stream gate config.openingWriteTimeoutMs (stream.send wire)
    catch error =>
      retireStream stream config
      return .error (failure .transport (toString error))
  match sent with
  | .expired =>
      retireStream stream config
      pure (.error openingTimeoutError)
  | .completed (.error error) =>
      retireStream stream config
      pure (.error (failure .transport error.message))
  | .completed (.ok _) =>
      match ← boundedWithGate stream gate config.openingWriteTimeoutMs stream.finishSend with
      | .expired =>
          retireStream stream config
          pure (.error openingTimeoutError)
      | .completed _ =>
          retireStream stream config
          pure (.ok ())

private def validVersionToken (value : String) : Bool :=
  let bytes := value.toUTF8
  if bytes.isEmpty || bytes.size > 3 then false
  else if !bytes.toList.all fun byte => 0x30 <= byte && byte <= 0x39 then false
  else if bytes.size > 1 && bytes[0]! == 0x30 then false
  else bytes.size < 3 || bytes[0]! == 0x31 || bytes[0]! == 0x32

private def unsupportedVersionToken (value : String) : Bool :=
  validVersionToken value && value != "13"

private def requestHasUnsupportedVersion (headers : Headers) : Bool :=
  match Headers.getUnique? headers "sec-websocket-version" with
  | .ok (some value) =>
      match Header.asciiString? value with
      | some value => unsupportedVersionToken value
      | none => false
  | _ => false

private def closeSession (session : Session) : Async (Except Error Unit) := do
  match ← Connection.close session.connection with
  | .ok _ => pure (.ok ())
  | .error error =>
      Connection.requestAbort session.connection
      try discard <| Connection.wait session.connection catch _ => pure ()
      pure (.error (failure .runtime error.message))

private def runApplication (stream : Transport.ByteStream) (config : Config)
    (request : Request) (acceptance : Acceptance) (negotiated : Negotiated)
    (application : Application) : Async (Except Error Unit) := do
  let started ← Connection.start .server stream config.connection negotiated.parameters?
  let connection ← match started with
    | .ok connection => pure connection
    | .error error =>
        retireStream stream config
        return .error (failure .runtime error.message)
  let session : Session := {
    connection, request, subprotocol? := acceptance.subprotocol?,
    compression? := negotiated.parameters?
  }
  try
    application session
    closeSession session
  catch error =>
    Connection.requestAbort connection
    try discard <| Connection.wait connection catch _ => pure ()
    pure (.error (failure .application (toString error)))

private structure Http1Opening where
  stream : Transport.ByteStream
  request : Request
  acceptance : Acceptance
  negotiated : Negotiated

private inductive Http1RejectOutcome where
  | rejected
  | failed (error : Error)

private inductive Http1Plan where
  | reject (rejection : Rejection) (outcome : Http1RejectOutcome)
  | retire (error : Error)
  | accept (response : ByteArray) (opening : Http1Opening)

private def prepareHttp1 (stream : Transport.ByteStream) (policy : Policy)
    (config : Config) (context : Http1Context) : Async Http1Plan := do
  let (raw, stream) ← match ← Transport.Http1.receiveRequestHead stream config.connection.limits with
    | .ok value => pure value
    | .error error =>
        if error.kind == .handshake then
          return .reject { status := 400 } (.failed (ofUpgradeFailure error))
        else
          return .retire (ofUpgradeFailure error)
  let accepted ← match Handshake.Http1.validateClientRequest raw with
    | .ok request => pure request
    | .error error =>
        let advertiseVersion := requestHasUnsupportedVersion raw.headers
        return .reject { status := 400, advertiseVersion } (.failed (ofWsError error))
  let request : Request := {
    mapping := .http1, scheme := context.scheme, authority := accepted.authority,
    target := accepted.target, origin? := accepted.origin?,
    subprotocols := accepted.subprotocols, extensions := accepted.extensions,
    headers := accepted.headers
  }
  let decision ← try policy request catch error =>
    return .reject { status := 500 } (.failed (failure .policy (toString error)))
  match decision with
  | .reject rejection =>
      match buildHttp1Rejection rejection with
      | .error error =>
          -- A policy cannot prevent a bounded final response by returning an
          -- invalid status, reason, or managed field.
          pure (.reject { status := 500 } (.failed error))
      | .ok _ =>
          pure (.reject rejection .rejected)
  | .accept acceptance =>
      let negotiated ← match negotiate request acceptance with
        | .ok negotiated => pure negotiated
        | .error error =>
            return .reject {
              status := if error.kind == .invalidArgument then 500 else 400 } (.failed error)
      let response ← match Handshake.Http1.buildServerResponse accepted {
          subprotocol? := acceptance.subprotocol?,
          extensions := negotiated.responseExtensions,
          extraHeaders := acceptance.extraHeaders } with
        | .ok response => pure response
        | .error error =>
            let mapped := ofWsError error
            return .reject {
              status := if mapped.kind == .invalidArgument then 500 else 400 } (.failed mapped)
      pure (.accept response { stream, request, acceptance, negotiated })

private def commitHttp1Plan (stream : Transport.ByteStream) (application : Application)
    (config : Config) (gate : Std.Mutex DeadlineGate) (plan : Http1Plan) :
    Async (Except Error Unit) := do
  if ← deadlineExpired gate then
    retireStream stream config
    return .error openingTimeoutError
  match plan with
  | .retire error =>
      retireStream stream config
      pure (.error error)
  | .reject rejection outcome =>
      let sent ← rejectHttp1 stream config gate rejection
      match outcome with
      | .rejected =>
          match sent with
          | .ok _ => pure (.ok ())
          | .error error => pure (.error error)
      | .failed original =>
          match sent with
          | .error error =>
              if error.kind == .timeout then pure (.error error) else pure (.error original)
          | .ok _ => pure (.error original)
  | .accept response opening =>
      match ← boundedWithGate stream gate config.openingWriteTimeoutMs
          (stream.send response) with
      | .expired =>
          retireStream stream config
          pure (.error openingTimeoutError)
      | .completed (.error error) =>
          retireStream stream config
          pure (.error (failure .transport error.message))
      | .completed (.ok _) =>
          runApplication opening.stream config opening.request opening.acceptance
            opening.negotiated application

private def handleHttp1Owned (stream : Transport.ByteStream) (policy : Policy)
    (application : Application) (config : Config) (context : Http1Context) :
    Async (Except Error Unit) := do
  match validateConfig config with
  | .error error =>
      retireStream stream config
      return .error error
  | .ok _ => pure ()
  unless context.scheme == "http" || context.scheme == "https" do
    retireStream stream config
    return .error (failure .invalidArgument "HTTP/1 server scheme must be http or https")
  let gate ← newDeadlineGate config.openingTimeoutMs
  match ← boundedWithGate stream gate config.openingTimeoutMs
      (prepareHttp1 stream policy config context) with
  | .expired =>
      retireStream stream config
      pure (.error openingTimeoutError)
  | .completed plan => commitHttp1Plan stream application config gate plan

private def reportError (config : Config) (error : Error) : Async Unit :=
  try config.onError error catch _ => pure ()

/-- Handle one already-accepted plain or TLS HTTP/1 byte stream. The callback
is lifetime-scoped: this action owns handshake, connection, and retirement. -/
def handleHttp1 (stream : Transport.ByteStream) (policy : Policy)
    (application : Application) (config : Config := {}) (context : Http1Context := {}) :
    Async (Except Error Unit) := do
  let result ← try handleHttp1Owned stream policy application config context catch error =>
    stream.abort
    retireStream stream config
    pure (.error (failure .runtime (toString error)))
  if let .error error := result then reportError config error
  pure result

private def rejectionMetadata (rejection : Rejection) : Except Error Http2.Headers := do
  validateRejection rejection
  let mut metadata := Http2.Headers.empty
  if rejection.status == 426 then
    throw (failure .invalidArgument "HTTP/2 WebSocket rejection must not use status 426")
  if rejection.advertiseVersion then metadata := metadata.insert "sec-websocket-version" "13"
  for header in rejection.extraHeaders do
    let checked ← match Header.ofBytes header.name header.value with
      | .ok checked => pure checked
      | .error error => throw (ofWsError error)
    let (value, valueOctets?) := Http2.Header.decodeWireString checked.value
    metadata := metadata.push { name := checked.name, value, valueOctets? }
  pure metadata

private def h2Rejection (rejection : Rejection) : Http2.ExtendedConnect.Decision :=
  match rejectionMetadata rejection with
  | .ok headers => .reject { status := rejection.status, headers }
  | .error _ => .reject { status := 500 }

private def h2InvalidVersion (request : Http2.ExtendedConnect.Request) : Bool :=
  let values := request.headers.getAll "sec-websocket-version"
  values.size == 1 && unsupportedVersionToken values[0]!

private structure Http2Plan where
  decision : Http2.ExtendedConnect.Decision
  report? : Option Error := none

/-- Construct an RFC 8441 handler for composition into an HTTP/2 server's
application table. Each accepted tunnel is lifetime-scoped to `application`;
no connection task is detached. -/
def extendedConnectHandler (policy : Policy) (application : Application)
    (config : Config := {}) : Except Error Http2.ExtendedConnect.Handler := do
  validateConfig config
  pure fun raw => do
    let accepted ← match Http2.Handshake.validateServerRequest raw
        config.connection.limits with
      | .ok request => pure request
      | .error _ =>
          return h2Rejection { status := 400, advertiseVersion := h2InvalidVersion raw }
    let request : Request := {
      mapping := .http2, scheme := accepted.scheme, authority := accepted.authority,
      target := accepted.target, origin? := accepted.origin?,
      subprotocols := accepted.subprotocols, extensions := accepted.extensions,
      headers := accepted.headers
    }
    let gate ← newDeadlineGate config.openingTimeoutMs
    -- This worker may outlive a non-cooperative policy after the deadline. It
    -- only computes a plan: the handler task exclusively commits the returned
    -- HTTP decision and error callback after winning the deadline race.
    let opening : Async Http2Plan := do
      let decision ← try policy request catch error =>
        return {
          decision := h2Rejection { status := 500 },
          report? := some (failure .policy (toString error))
        }
      match decision with
      | .reject rejection => pure { decision := h2Rejection rejection }
      | .accept acceptance =>
          let negotiated ← match negotiate request acceptance with
            | .ok negotiated => pure negotiated
            | .error error =>
                return {
                  decision := h2Rejection {
                    status := if error.kind == .invalidArgument then 500 else 400 },
                  report? := some error
                }
          let response ← match Http2.Handshake.buildServerResponse accepted {
              subprotocol? := acceptance.subprotocol?,
              extensions := negotiated.responseExtensions,
              extraHeaders := acceptance.extraHeaders } with
            | .ok response => pure response
            | .error error =>
                let mapped := ofWsError error
                return {
                  decision := h2Rejection {
                    status := if error.kind == .invalidArgument then 500 else 400 },
                  report? := some mapped
                }
          pure { decision := .accept {
              status := response.status,
              headers := response.headers,
              run := fun tunnel => do
                let stream ← Transport.Http2.ofTunnel tunnel
                match ← runApplication stream config request acceptance negotiated application with
                | .ok _ => pure ()
                | .error error => reportError config error
            } }
    let timed ← try boundedActionWithGate gate config.openingTimeoutMs opening catch error =>
      reportError config (failure .runtime (toString error))
      return h2Rejection { status := 500 }
    match timed with
    | .completed plan =>
        if let some error := plan.report? then reportError config error
        pure plan.decision
    | .expired =>
        reportError config (failure .timeout "timed out deciding the HTTP/2 WebSocket opening")
        pure (h2Rejection { status := 503 })

end Ws.Server
