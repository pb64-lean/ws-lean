import Ws.Server

open Std.Async
open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

partial def awaitFinished (task : Task α) (remainingMs : Nat) : Async Bool := do
  if ← IO.hasFinished task then
    pure true
  else if remainingMs == 0 then
    pure false
  else
    let slice := min remainingMs 5
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat slice)
    awaitFinished task (remainingMs - slice)

def takeHandler (result : Except Server.Error Grpc.Http2.ExtendedConnect.Handler) :
    IO Grpc.Http2.ExtendedConnect.Handler :=
  match result with
  | .ok handler => pure handler
  | .error error => throw (IO.userError error.message)

structure MemoryStream where
  stream : Transport.ByteStream
  writes : IO.Ref (Array ByteArray)
  aborts : IO.Ref Nat
  retirements : IO.Ref Nat

def memoryStream (input? : Option ByteArray) : IO MemoryStream := do
  let input ← IO.mkRef input?
  let writes ← IO.mkRef #[]
  let aborts ← IO.mkRef 0
  let retirements ← IO.mkRef 0
  let stream : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => do
      let value ← input.modifyGet fun value => (value, none)
      pure (.ok value)
    sendImpl := fun bytes => do
      writes.modify (fun values => values.push bytes)
      pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := aborts.modify (fun count => count + 1)
    retireImpl := fun _ => retirements.modify (fun count => count + 1)
  }
  pure { stream, writes, aborts, retirements }

def stalledStream : IO MemoryStream := do
  let never : IO.Promise Unit ← IO.Promise.new
  let writes ← IO.mkRef #[]
  let aborts ← IO.mkRef 0
  let retirements ← IO.mkRef 0
  let stream : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => do
      discard <| Async.ofTask never.result?
      pure (.ok none)
    sendImpl := fun bytes => do
      writes.modify (fun values => values.push bytes)
      pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := aborts.modify (fun count => count + 1)
    retireImpl := fun _ => retirements.modify (fun count => count + 1)
  }
  pure { stream, writes, aborts, retirements }

def requestWire (versionFields : String) : ByteArray :=
  ("GET /chat HTTP/1.1\r\n" ++
   "Host: example.test\r\n" ++
   "Upgrade: websocket\r\n" ++
   "Connection: Upgrade\r\n" ++
   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
   versionFields ++ "\r\n").toUTF8

def rejectionText (stream : MemoryStream) : IO String := do
  let writes ← stream.writes.get
  expect (writes.size == 1) "server did not emit exactly one HTTP/1 rejection"
  let some text := Header.asciiString? writes[0]!
    | throw (IO.userError "HTTP/1 rejection was not ASCII")
  pure text

def hasVersionAdvertisement (text : String) : Bool :=
  (text.splitOn "\r\n").contains "sec-websocket-version: 13"

def runHttp1VersionCase (label versionFields : String) (advertise : Bool) : IO Unit := do
  let transport ← memoryStream (some (requestWire versionFields))
  let policyCalled ← IO.mkRef false
  let policy : Server.Policy := fun _ => do
    policyCalled.set true
    pure (.reject {})
  let result ← Async.block <| Server.handleHttp1 transport.stream policy (fun _ => pure ()) {
    openingTimeoutMs := 200, openingWriteTimeoutMs := 100, retirementTimeoutMs := 20
  }
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: malformed version request was accepted")
  expect (!(← policyCalled.get)) s!"{label}: invalid request reached policy"
  let text ← rejectionText transport
  expect (text.startsWith "HTTP/1.1 400 ") s!"{label}: rejection was not status 400"
  expect (hasVersionAdvertisement text == advertise)
    s!"{label}: Sec-WebSocket-Version advertisement mismatch"

def http1VersionTests : IO Unit := do
  runHttp1VersionCase "unsupported decimal"
    "Sec-WebSocket-Version: 12\r\n" true
  runHttp1VersionCase "zero version"
    "Sec-WebSocket-Version: 0\r\n" true
  runHttp1VersionCase "missing version" "" false
  runHttp1VersionCase "empty version"
    "Sec-WebSocket-Version:\r\n" false
  runHttp1VersionCase "malformed version"
    "Sec-WebSocket-Version: twelve\r\n" false
  runHttp1VersionCase "comma version list"
    "Sec-WebSocket-Version: 12, 13\r\n" false
  runHttp1VersionCase "leading-zero version"
    "Sec-WebSocket-Version: 012\r\n" false
  runHttp1VersionCase "out-of-grammar version"
    "Sec-WebSocket-Version: 300\r\n" false
  runHttp1VersionCase "duplicate version"
    ("Sec-WebSocket-Version: 12\r\n" ++
     "Sec-WebSocket-Version: 13\r\n") false

def h2Request (headers : Grpc.Metadata) : Grpc.Http2.ExtendedConnect.Request := {
  protocol := "websocket"
  scheme := "http"
  authority := "example.test"
  path := "/chat"
  headers
}

def runHttp2VersionCase (label : String) (headers : Grpc.Metadata)
    (advertise : Bool) : IO Unit := do
  let policyCalled ← IO.mkRef false
  let handler ← takeHandler <| Server.extendedConnectHandler
    (fun _ => do policyCalled.set true; pure (.reject {})) (fun _ => pure ())
  match ← Async.block (handler (h2Request headers)) with
  | .accept _ => throw (IO.userError s!"{label}: malformed HTTP/2 version was accepted")
  | .reject rejection =>
      expect (rejection.status == 400) s!"{label}: HTTP/2 rejection was not 400"
      let advertised := rejection.headers.getAll "sec-websocket-version"
      expect ((advertised == #["13"]) == advertise)
        s!"{label}: HTTP/2 version advertisement mismatch"
  expect (!(← policyCalled.get)) s!"{label}: invalid HTTP/2 request reached policy"

def http2VersionTests : IO Unit := do
  runHttp2VersionCase "H2 unsupported decimal"
    (Grpc.Metadata.singleton "sec-websocket-version" "12") true
  runHttp2VersionCase "H2 missing" Grpc.Metadata.empty false
  runHttp2VersionCase "H2 empty"
    (Grpc.Metadata.singleton "sec-websocket-version" "") false
  runHttp2VersionCase "H2 malformed"
    (Grpc.Metadata.singleton "sec-websocket-version" "twelve") false
  runHttp2VersionCase "H2 comma list"
    (Grpc.Metadata.singleton "sec-websocket-version" "12, 13") false
  runHttp2VersionCase "H2 leading zero"
    (Grpc.Metadata.singleton "sec-websocket-version" "012") false
  runHttp2VersionCase "H2 out of grammar"
    (Grpc.Metadata.singleton "sec-websocket-version" "300") false
  runHttp2VersionCase "H2 duplicate" #[
    { name := "sec-websocket-version", value := "12" },
    { name := "sec-websocket-version", value := "13" }
  ] false

def openingDeadlineTests : IO Unit := do
  let slowloris ← stalledStream
  let startedAt ← IO.monoMsNow
  let result ← Async.block <| Server.handleHttp1 slowloris.stream
    (fun _ => pure (.reject {})) (fun _ => pure ()) {
      openingTimeoutMs := 25, openingWriteTimeoutMs := 25, retirementTimeoutMs := 20
    }
  let elapsed := (← IO.monoMsNow) - startedAt
  match result with
  | .error error => expect (error.kind == .timeout) "slow request head returned the wrong error"
  | .ok _ => throw (IO.userError "slow request head escaped its opening deadline")
  expect (elapsed < 500) "slow request head teardown exceeded its bounded deadline"
  expect ((← slowloris.aborts.get) > 0) "slow request head did not abort its transport"

  let stalledPolicy : IO.Promise Unit ← IO.Promise.new
  let stalledPolicyFinished : IO.Promise Unit ← IO.Promise.new
  let h1Observed ← IO.mkRef (#[] : Array Server.ErrorKind)
  let transport ← memoryStream (some (requestWire "Sec-WebSocket-Version: 13\r\n"))
  let startedAt ← IO.monoMsNow
  let result ← Async.block <| Server.handleHttp1 transport.stream
    (fun _ => do
      discard <| Async.ofTask stalledPolicy.result?
      discard <| stalledPolicyFinished.resolve ()
      pure (.accept {}))
    (fun _ => pure ()) {
      openingTimeoutMs := 25, openingWriteTimeoutMs := 25, retirementTimeoutMs := 20,
      onError := fun error => h1Observed.modify (fun kinds => kinds.push error.kind)
    }
  let elapsed := (← IO.monoMsNow) - startedAt
  match result with
  | .error error => expect (error.kind == .timeout) "stalled H1 policy returned the wrong error"
  | .ok _ => throw (IO.userError "stalled H1 policy escaped its opening deadline")
  expect (elapsed < 500) "stalled H1 policy teardown exceeded its bounded deadline"
  expect ((← transport.aborts.get) > 0) "stalled H1 policy did not abort its transport"
  expect ((← transport.writes.get).isEmpty)
    "stalled H1 policy wrote an HTTP response before late resolution"
  expect ((← h1Observed.get) == #[.timeout])
    "stalled H1 policy did not report exactly its opening timeout"
  discard <| stalledPolicy.resolve ()
  expect (← Async.block (awaitFinished stalledPolicyFinished.result? 100))
    "stalled H1 policy continuation did not settle after late resolution"
  Async.block <| Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 20)
  expect ((← transport.writes.get).isEmpty)
    "late H1 policy resolution wrote an HTTP response after handler return"
  expect ((← h1Observed.get) == #[.timeout])
    "late H1 policy resolution triggered another error callback"

  let stalledH2Policy : IO.Promise Unit ← IO.Promise.new
  let stalledH2PolicyFinished : IO.Promise Unit ← IO.Promise.new
  let observed ← IO.mkRef (#[] : Array Server.ErrorKind)
  let handler ← takeHandler <| Server.extendedConnectHandler
    (fun _ => do
      discard <| Async.ofTask stalledH2Policy.result?
      discard <| stalledH2PolicyFinished.resolve ()
      throw (IO.userError "late H2 policy failure"))
    (fun _ => pure ()) {
      openingTimeoutMs := 25,
      onError := fun error => observed.modify (fun kinds => kinds.push error.kind)
    }
  let startedAt ← IO.monoMsNow
  match ← Async.block (handler (h2Request
      (Grpc.Metadata.singleton "sec-websocket-version" "13"))) with
  | .accept _ => throw (IO.userError "stalled H2 policy was accepted")
  | .reject rejection =>
      expect (rejection.status == 503) "stalled H2 policy did not return status 503"
  let elapsed := (← IO.monoMsNow) - startedAt
  expect (elapsed < 500) "stalled H2 policy exceeded its bounded deadline"
  expect ((← observed.get) == #[.timeout])
    "stalled H2 policy did not report exactly its opening timeout"
  discard <| stalledH2Policy.resolve ()
  expect (← Async.block (awaitFinished stalledH2PolicyFinished.result? 100))
    "stalled H2 policy continuation did not settle after late resolution"
  Async.block <| Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 20)
  expect ((← observed.get) == #[.timeout])
    "late H2 policy resolution triggered another error callback"

def invalidPolicyRejectionTest : IO Unit := do
  let transport ← memoryStream (some (requestWire "Sec-WebSocket-Version: 13\r\n"))
  let result ← Async.block <| Server.handleHttp1 transport.stream
    (fun _ => pure (.reject { status := 200 })) (fun _ => pure ()) {
      openingTimeoutMs := 200, openingWriteTimeoutMs := 100, retirementTimeoutMs := 20
    }
  match result with
  | .error error =>
      expect (error.kind == .invalidArgument) "invalid policy rejection returned the wrong error"
  | .ok _ => throw (IO.userError "invalid policy rejection succeeded")
  let text ← rejectionText transport
  expect (text.startsWith "HTTP/1.1 500 ")
    "invalid policy rejection did not fall back to status 500"

def main : IO Unit := do
  http1VersionTests
  http2VersionTests
  openingDeadlineTests
  invalidPolicyRejectionTest
  IO.println "server opening tests passed"
