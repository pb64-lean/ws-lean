import Ws.Connection

open Std.Async
open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def takeStart (label : String) : Except Connection.SendError Connection.Connection →
    IO Connection.Connection
  | .ok connection => pure connection
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def takeSend (label : String) : Except Connection.SendError Unit → IO Unit
  | .ok _ => pure ()
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def takeReceive (label : String) :
    Except Connection.ReceiveError (Option Message.Event) → IO (Option Message.Event)
  | .ok event => pure event
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def closeChannel (channel : Std.CloseableChannel α) : BaseIO Unit := do
  discard <| channel.close.toBaseIO

partial def awaitTaskFinished (task : Task α) (remainingMs : Nat) : Async Bool := do
  if ← IO.hasFinished task then
    pure true
  else if remainingMs == 0 then
    pure false
  else
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    awaitTaskFinished task (remainingMs - 1)

partial def awaitWriteCount (capture : IO.Ref (Array ByteArray)) (count remainingMs : Nat) :
    Async Bool := do
  if (← capture.get).size >= count then
    pure true
  else if remainingMs == 0 then
    pure false
  else
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    awaitWriteCount capture count (remainingMs - 1)

structure Link where
  client : Transport.ByteStream
  server : Transport.ByteStream
  clientWire : IO.Ref (Array ByteArray)
  serverWire : IO.Ref (Array ByteArray)

def stream (incoming outgoing : Std.CloseableChannel ByteArray)
    (capture : IO.Ref (Array ByteArray)) : Transport.ByteStream := {
  version := .http1
  recvImpl := fun _ => do
    pure (.ok (← await (← incoming.recv)))
  sendImpl := fun bytes => do
    capture.modify (·.push bytes)
    match ← await (← outgoing.send bytes) with
    | .ok _ => pure (.ok ())
    | .error _ => pure (.error (Transport.Failure.closed "test link is closed"))
  finishSendImpl := fun _ => do
    closeChannel outgoing
    pure (.ok ())
  abortImpl := do
    closeChannel incoming
    closeChannel outgoing
  retireImpl := fun _ => pure ()
}

def link : IO Link := do
  let clientToServer ← Std.CloseableChannel.new (some 1)
  let serverToClient ← Std.CloseableChannel.new (some 1)
  let clientWire ← IO.mkRef #[]
  let serverWire ← IO.mkRef #[]
  pure {
    client := stream serverToClient clientToServer clientWire
    server := stream clientToServer serverToClient serverWire
    clientWire, serverWire
  }

def maskKey (frame : ByteArray) : Option ByteArray := do
  if frame.size < 6 || (frame[1]! &&& 0x80) == 0 then none else pure ()
  let lengthCode := (frame[1]! &&& 0x7f).toNat
  let offset := if lengthCode < 126 then 2 else if lengthCode == 126 then 4 else 10
  if offset + 4 <= frame.size then some (frame.extract offset (offset + 4)) else none

def cleanPairTest : IO Unit := Async.block do
  let transport ← link
  let client ← takeStart "client start" (← Connection.start .client transport.client)
  let server ← takeStart "server start" (← Connection.start .server transport.server)

  for label in #["first text", "second text"] do
    takeSend label (← Connection.sendText client "same payload")
    match ← takeReceive "server text" (← Connection.receive server) with
    | some (.message message) =>
        expect (message.kind == .text && message.data == "same payload".toUTF8 &&
          !message.compressed)
          "received text differs"
    | _ => throw (IO.userError "server did not receive a text message")
  let clientWire ← transport.clientWire.get
  expect (clientWire.size >= 2) "client wire did not capture two frames"
  let firstKey := maskKey clientWire[0]!
  let secondKey := maskKey clientWire[1]!
  expect (firstKey.isSome && secondKey.isSome)
    "client frames were not masked in the required direction"

  takeSend "ping" (← Connection.ping client "probe".toUTF8)
  match ← takeReceive "server ping" (← Connection.receive server) with
  | some (.ping payload) => expect (payload == "probe".toUTF8) "Ping payload differs"
  | _ => throw (IO.userError "server did not deliver Ping")
  match ← takeReceive "client pong" (← Connection.receive client) with
  | some (.pong payload) => expect (payload == "probe".toUTF8) "Pong payload differs"
  | _ => throw (IO.userError "client did not receive automatic Pong")

  takeSend "unsolicited pong" (← Connection.pong client "notice".toUTF8)
  match ← takeReceive "server unsolicited pong" (← Connection.receive server) with
  | some (.pong payload) => expect (payload == "notice".toUTF8) "unsolicited Pong differs"
  | _ => throw (IO.userError "server did not receive unsolicited Pong")

  let closeResult ← Connection.close client
  let clientTermination ← match closeResult with
    | .ok termination => pure termination
    | .error error => throw (IO.userError s!"client close: {error.message}")
  let serverTermination ← Connection.wait server
  expect (clientTermination.kind == .clean && serverTermination.kind == .clean)
    "close handshake was not clean"
  match ← Connection.sendText client "late" with
  | .error error => expect (error.kind == .closed) "send-after-close returned wrong error"
  | .ok _ => throw (IO.userError "send-after-close succeeded")

def timeoutTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 0)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let connection ← takeStart "timeout start" (← Connection.start .client
    (stream inbound outbound capture) { closeTimeoutMs := 20, retireTimeoutMs := 20 })
  let result ← Connection.close connection
  let termination ← match result with
    | .ok termination => pure termination
    | .error error => throw (IO.userError s!"timeout close send: {error.message}")
  expect (termination.kind == .timeout) "silent peer did not trigger close timeout"

def compressionTest : IO Unit := Async.block do
  let transport ← link
  let parameters : PerMessageDeflate.Parameters := {}
  let config : Connection.Config := { compressionThreshold := 0 }
  let client ← takeStart "compressed client"
    (← Connection.start .client transport.client config (some parameters))
  let server ← takeStart "compressed server"
    (← Connection.start .server transport.server config (some parameters))
  let payload := String.join (List.replicate 1024 "compressible payload ")
  takeSend "compressed send" (← Connection.sendText client payload)
  match ← takeReceive "compressed receive" (← Connection.receive server) with
  | some (.message message) =>
      expect (message.kind == .text && message.data == payload.toUTF8 && !message.compressed)
        "compressed message did not roundtrip"
  | _ => throw (IO.userError "compressed message was not delivered")
  let wire ← transport.clientWire.get
  expect (!wire.isEmpty && (wire[0]![0]! &&& 0x40) != 0)
    "compressed message did not set RSV1"
  discard <| Connection.close client
  discard <| Connection.wait server

def invalidOutboundTest : IO Unit := Async.block do
  let transport ← link
  let client ← takeStart "invalid outbound client"
    (← Connection.start .client transport.client)
  match ← Connection.send client { kind := .text, data := ByteArray.mk #[0xff] } with
  | .error error => expect (error.kind == .invalidArgument) "invalid UTF-8 returned wrong error"
  | .ok _ => throw (IO.userError "invalid outbound UTF-8 was accepted")
  Connection.requestAbort client
  discard <| Connection.wait client

def closeStopsSameChunkTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 2)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let closeWire ← match Frame.encode .server none {
      opcode := .close, payload := ByteArray.mk #[0x03, 0xe8] } with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode peer Close: {error.message}")
  let lateData ← match Frame.encode .server none {
      opcode := .text, payload := "late".toUTF8 } with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode late data: {error.message}")
  match ← await (← inbound.send (closeWire.append lateData)) with
  | .ok _ => pure ()
  | .error _ => throw (IO.userError "could not stage coalesced Close input")
  let client ← takeStart "terminal chunk client"
    (← Connection.start .client (stream inbound outbound capture))
  let termination ← Connection.wait client
  expect (termination.kind == .clean)
    "data following Close in one chunk preempted the clean handshake"
  let writes ← capture.get
  expect (writes.size == 1) "peer Close did not produce exactly one reply"
  let (_, frames) ← match (Frame.Decoder.new .server).feed writes[0]! with
    | .ok decoded => pure decoded
    | .error error => throw (IO.userError s!"decode Close reply: {error.message}")
  expect (frames.size == 1 && frames[0]!.opcode == .close &&
      frames[0]!.payload == ByteArray.mk #[0x03, 0xe8])
    "Close reply did not echo the peer status exactly"

def expectFailureClose (capture : IO.Ref (Array ByteArray)) (code : Nat)
    (label : String) : IO Unit := do
  let writes ← capture.get
  expect (!writes.isEmpty) s!"{label}: no Close frame was written"
  let mut decoder := Frame.Decoder.new .server
  let mut frames : Array Frame.Frame := #[]
  for wire in writes do
    let (next, decoded) ← match decoder.feed wire with
      | .ok result => pure result
      | .error error => throw (IO.userError s!"{label}: decode Close: {error.message}")
    decoder := next
    frames := frames.append decoded
  let expected := ByteArray.mk #[UInt8.ofNat (code / 256), UInt8.ofNat code]
  expect (frames.size == 1 && frames[0]!.opcode == .close &&
      frames[0]!.payload == expected)
    s!"{label}: wrong failure Close"

def validPrefixBeforeProtocolFailureTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 2)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let valid ← match Frame.encode .server none {
      opcode := .text, payload := "before failure".toUTF8 } with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode valid prefix: {error.message}")
  let wire := valid.append (ByteArray.mk #[0x83, 0])
  match ← await (← inbound.send wire) with
  | .ok _ => pure ()
  | .error _ => throw (IO.userError "could not stage valid-prefix input")
  let client ← takeStart "valid-prefix client"
    (← Connection.start .client (stream inbound outbound capture))
  match ← takeReceive "valid-prefix receive" (← Connection.receive client) with
  | some (.message message) =>
      expect (message.kind == .text && message.data == "before failure".toUTF8)
        "the event preceding a malformed frame changed"
  | _ => throw (IO.userError "the event preceding a malformed frame was discarded")
  let termination ← Connection.wait client
  expect (termination.kind == .protocolError)
    "a malformed suffix did not terminate as a protocol failure"
  expectFailureClose capture 1002 "valid-prefix failure"

def incrementalUtf8FailureTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 2)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let invalid : Frame.Frame := {
    opcode := .text
    payload := ByteArray.mk #[0x61, 0xf0, 0x28, 0x8c, 0xbc, 0x62]
  }
  let wire ← match Frame.encode .server none invalid with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode incremental UTF-8: {error.message}")
  -- The declared frame is deliberately incomplete, but the bytes already
  -- present prove that its text payload is invalid.
  match ← await (← inbound.send (wire.extract 0 5)) with
  | .ok _ => pure ()
  | .error _ => throw (IO.userError "could not stage incremental UTF-8 input")
  let client ← takeStart "incremental UTF-8 client"
    (← Connection.start .client (stream inbound outbound capture))
  let waiting ← Async.toIO (Connection.wait client)
  unless ← awaitTaskFinished waiting 500 do
    Connection.requestAbort client
    try discard <| Async.ofAsyncTask waiting catch _ => pure ()
    throw (IO.userError "invalid UTF-8 was not rejected before frame completion")
  let termination ← Async.ofAsyncTask waiting
  expect (termination.kind == .protocolError)
    "incremental invalid UTF-8 did not terminate as a protocol failure"
  expectFailureClose capture 1007 "incremental UTF-8 failure"

def incomingBackpressureTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 2)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let first ← match Frame.encode .server none {
      opcode := .binary, payload := ByteArray.mk #[1] } with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode first data: {error.message}")
  let second ← match Frame.encode .server none {
      opcode := .binary, payload := ByteArray.mk #[2] } with
    | .ok bytes => pure bytes
    | .error error => throw (IO.userError s!"encode second data: {error.message}")
  match ← await (← inbound.send (first.append second)) with
  | .ok _ => pure ()
  | .error _ => throw (IO.userError "could not stage backpressure input")
  let client ← takeStart "backpressure client" (← Connection.start .client
    (stream inbound outbound capture) { incomingCapacity := 1 })
  let termination ← Connection.wait client
  expect (termination.kind == .protocolError)
    "incoming capacity exhaustion did not terminate as a policy failure"
  let writes ← capture.get
  expect (writes.size == 1) "incoming capacity exhaustion did not write one Close"
  let (_, frames) ← match (Frame.Decoder.new .server).feed writes[0]! with
    | .ok decoded => pure decoded
    | .error error => throw (IO.userError s!"decode policy Close: {error.message}")
  expect (frames.size == 1 && frames[0]!.opcode == .close &&
      frames[0]!.payload == ByteArray.mk #[0x03, 0xf0])
    "incoming capacity exhaustion did not send Close 1008"

def cancelledReceiveDoesNotConsumeTest : IO Unit := Async.block do
  let transport ← link
  let client ← takeStart "receive cancellation client"
    (← Connection.start .client transport.client)
  let server ← takeStart "receive cancellation server"
    (← Connection.start .server transport.server)
  let cancellation ← Std.CancellationToken.new
  let waiting ← Async.toIO (Connection.receiveWithCancellation server cancellation)
  Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 5)
  cancellation.cancel
  match ← Async.ofAsyncTask waiting with
  | .error error =>
      expect (error.kind == .cancelled) "cancelled receive returned the wrong error"
  | .ok _ => throw (IO.userError "blocked receive ignored cancellation")
  takeSend "post-cancellation send" (← Connection.sendText client "still visible")
  match ← takeReceive "post-cancellation receive" (← Connection.receive server) with
  | some (.message message) =>
      expect (message.data == "still visible".toUTF8)
        "cancelled receive consumed the next event"
  | _ => throw (IO.userError "next receive did not observe the post-cancellation event")

  for index in [0:12] do
    let forced ← Async.toIO (Connection.receive server)
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 2)
    IO.cancel forced
    expect (← awaitTaskFinished forced 250)
      s!"force-cancelled receive worker {index} did not retire"
    match ← Async.ofAsyncTask forced with
    | .error error =>
        expect (error.kind == .cancelled)
          s!"force-cancelled receive worker {index} returned the wrong error"
    | .ok _ => throw (IO.userError s!"force-cancelled receive worker {index} succeeded")
    let payload := s!"also visible {index}"
    takeSend "post-forced-cancellation send" (← Connection.sendText client payload)
    match ← takeReceive "post-forced-cancellation receive" (← Connection.receive server) with
    | some (.message message) =>
        expect (message.data == payload.toUTF8)
          s!"force-cancelled receive worker {index} consumed the next event"
    | _ => throw (IO.userError
        s!"receive after forced cancellation {index} lost its next event")
  discard <| Connection.close client
  discard <| Connection.wait server

def fragmentedCloseRaceTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 2)
  let capture ← IO.mkRef #[]
  let firstWrite ← IO.Promise.new
  let releaseFirst ← IO.Promise.new
  let closeWritten ← IO.Promise.new
  let writeIndex ← IO.mkRef 0
  let stream : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => do
      let value ← await (← inbound.recv)
      pure (.ok value)
    sendImpl := fun bytes => do
      capture.modify (fun writes => writes.push bytes)
      let index ← writeIndex.modifyGet fun index => (index, index + 1)
      if index == 0 then
        discard <| firstWrite.resolve ()
        discard <| Async.ofTask releaseFirst.result?
      if !bytes.isEmpty && (bytes[0]! &&& 0x0f) == 0x08 then
        discard <| closeWritten.resolve ()
      pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := closeChannel inbound
    retireImpl := fun _ => pure ()
  }
  let client ← takeStart "fragmented close client" (← Connection.start .client stream {
    fragmentSize := 1, closeTimeoutMs := 100, retireTimeoutMs := 20
  })
  let dataTask ← Async.toIO (Connection.sendText client "fragmented")
  discard <| Async.ofTask firstWrite.result?
  let pingTask ← Async.toIO (Connection.ping client "must-not-follow-close".toUTF8)
  Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 5)
  let releaseTask ← Async.toIO do
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 5)
    discard <| releaseFirst.resolve ()
  let peerTask ← Async.toIO do
    discard <| Async.ofTask closeWritten.result?
    let wire := (Frame.encode .server none {
      opcode := .close, payload := ByteArray.mk #[0x03, 0xe8] }).toOption.get!
    discard <| await (← inbound.send wire)
  let startedAt ← IO.monoMsNow
  let result ← Connection.close client
  let elapsed := (← IO.monoMsNow) - startedAt
  match result with
  | .ok termination =>
      expect (termination.kind == .clean) "fragment-interrupt Close was not clean"
  | .error error => throw (IO.userError s!"fragment-interrupt Close: {error.message}")
  expect (elapsed < 500) "peer Close waited past the written local Close"
  try discard <| Async.ofAsyncTask dataTask catch _ => pure ()
  match ← Async.ofAsyncTask pingTask with
  | .error error =>
      expect (error.kind == .closed) "control queued before Close returned the wrong error"
  | .ok _ => throw (IO.userError "control queued before Close was written after Close")
  try discard <| Async.ofAsyncTask releaseTask catch _ => pure ()
  try discard <| Async.ofAsyncTask peerTask catch _ => pure ()
  let writes ← capture.get
  let closeCount := writes.foldl (fun count bytes =>
    if !bytes.isEmpty && (bytes[0]! &&& 0x0f) == 0x08 then count + 1 else count) 0
  let pingCount := writes.foldl (fun count bytes =>
    if !bytes.isEmpty && (bytes[0]! &&& 0x0f) == 0x09 then count + 1 else count) 0
  expect (closeCount == 1) "fragment interruption wrote more than one local Close"
  expect (pingCount == 0) "writer emitted a control frame after Close ownership"

def pongAfterLocalCloseTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 4)
  let outbound ← Std.CloseableChannel.new (some 8)
  let capture ← IO.mkRef #[]
  let client ← takeStart "post-Close Ping client" (← Connection.start .client
    (stream inbound outbound capture) { closeTimeoutMs := 500, retireTimeoutMs := 20 })
  let closing ← Async.toIO (Connection.close client)
  unless ← awaitWriteCount capture 1 250 do
    Connection.requestAbort client
    try discard <| Async.ofAsyncTask closing catch _ => pure ()
    throw (IO.userError "local Close was not written")
  let pingPayload := "after-close".toUTF8
  let pingWire := (Frame.encode .server none {
    opcode := .ping, payload := pingPayload
  }).toOption.get!
  discard <| await (← inbound.send pingWire)
  unless ← awaitWriteCount capture 2 250 do
    Connection.requestAbort client
    try discard <| Async.ofAsyncTask closing catch _ => pure ()
    throw (IO.userError "Ping after local Close did not produce a Pong")
  let closeWire := (Frame.encode .server none {
    opcode := .close, payload := ByteArray.mk #[0x03, 0xe8]
  }).toOption.get!
  discard <| await (← inbound.send closeWire)
  match ← Async.ofAsyncTask closing with
  | .error error => throw (IO.userError s!"post-Close Ping handshake: {error.message}")
  | .ok termination =>
      expect (termination.kind == .clean)
        "Ping after local Close changed clean termination"
  let writes ← capture.get
  let mut decoder := Frame.Decoder.new .server
  let mut frames : Array Frame.Frame := #[]
  for wire in writes do
    let (next, decoded) ← match decoder.feed wire with
      | .ok result => pure result
      | .error error => throw (IO.userError s!"decode post-Close control: {error.message}")
    decoder := next
    frames := frames.append decoded
  expect (frames.size == 2 && frames[0]!.opcode == .close &&
      frames[1]!.opcode == .pong && frames[1]!.payload == pingPayload)
    "post-Close Ping was not answered exactly once after the local Close"

def forcedAdmissionCancellationTest : IO Unit := Async.block do
  let inbound ← Std.CloseableChannel.new (some 1)
  let capture ← IO.mkRef #[]
  let firstWrite ← IO.Promise.new
  let releaseFirst ← IO.Promise.new
  let writeIndex ← IO.mkRef 0
  let stream : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => do
      let value ← await (← inbound.recv)
      pure (.ok value)
    sendImpl := fun bytes => do
      capture.modify (fun writes => writes.push bytes)
      let index ← writeIndex.modifyGet fun index => (index, index + 1)
      if index == 0 then
        discard <| firstWrite.resolve ()
        discard <| Async.ofTask releaseFirst.result?
      pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := closeChannel inbound
    retireImpl := fun _ => pure ()
  }
  let client ← takeStart "admission cancellation client"
    (← Connection.start .client stream { retireTimeoutMs := 20 })
  let first ← Async.toIO (Connection.sendText client "first")
  discard <| Async.ofTask firstWrite.result?
  -- The transport proves this request was admitted and transferred to the
  -- writer. Cancelling its observer must retire that worker without retracting
  -- the connection-owned write or releasing its permit a second time.
  IO.cancel first
  expect (← awaitTaskFinished first 250)
    "force-cancelled admitted-send observer did not retire"
  match ← Async.ofAsyncTask first with
  | .error error =>
      expect (error.kind == .cancelled)
        "force-cancelled admitted-send observer returned the wrong error"
  | .ok _ => throw (IO.userError "force-cancelled admitted-send observer succeeded")
  let second ← Async.toIO (Connection.sendText client "second")
  Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 10)
  for index in [0:12] do
    let ghost ← Async.toIO (Connection.sendText client s!"ghost {index}")
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 2)
    IO.cancel ghost
    expect (← awaitTaskFinished ghost 250)
      s!"force-cancelled admission worker {index} did not retire"
    match ← Async.ofAsyncTask ghost with
    | .error error =>
        expect (error.kind == .cancelled)
          s!"force-cancelled admission worker {index} returned the wrong error"
    | .ok _ => throw (IO.userError
        s!"force-cancelled admission worker {index} acquired admission")
  discard <| releaseFirst.resolve ()
  expect (← awaitTaskFinished second 250) "second admitted send did not finish"
  takeSend "second admitted send" (← Async.ofAsyncTask second)
  let probe ← Async.toIO (Connection.sendText client "probe")
  expect (← awaitTaskFinished probe 250)
    "admission was not released after force-cancelled waiters"
  takeSend "post-cancellation admission probe" (← Async.ofAsyncTask probe)
  let writes ← capture.get
  expect (writes.size == 3) "force-cancelled admission waiter later emitted a frame"
  Connection.requestAbort client
  discard <| Connection.wait client

def main : IO Unit := do
  cleanPairTest
  timeoutTest
  compressionTest
  invalidOutboundTest
  closeStopsSameChunkTest
  validPrefixBeforeProtocolFailureTest
  incrementalUtf8FailureTest
  incomingBackpressureTest
  cancelledReceiveDoesNotConsumeTest
  fragmentedCloseRaceTest
  pongAfterLocalCloseTest
  forcedAdmissionCancellationTest
  IO.println "connection lifecycle tests passed"
