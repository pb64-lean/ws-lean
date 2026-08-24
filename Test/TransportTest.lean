import Std.Async.TCP
import Ws.Transport.Http1
import Ws.Transport.Http2
import Ws.Transport.Plain

open Std
open Std.Async
open Std.Net
open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def takeTransport (label : String) (result : Except Transport.Failure α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def waitTaskWithin (task : AsyncTask α) (timeoutMs : Nat) : Async Bool := do
  let mut finished ← IO.hasFinished task
  for _ in [0:timeoutMs] do
    if finished then break
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    finished ← IO.hasFinished task
  pure finished

def byteStreamNormalizationTest : IO Unit := Async.block do
  let sends ← IO.mkRef (0 : Nat)
  let receives ← IO.mkRef (#[ByteArray.empty, "payload".toUTF8] : Array ByteArray)
  let stream : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => do
      let chunks ← receives.get
      match chunks[0]? with
      | none => pure (.ok none)
      | some bytes =>
          receives.set (chunks.extract 1 chunks.size)
          pure (.ok (some bytes))
    sendImpl := fun _ => do sends.modify (· + 1); pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := pure ()
    retireImpl := fun _ => pure ()
  }
  takeTransport "empty send" (← stream.send ByteArray.empty)
  expect ((← sends.get) == 0) "empty ByteStream.send reached the transport"
  let bytes? ← takeTransport "normalized receive" (← stream.recv?)
  expect (bytes? == some "payload".toUTF8) "ByteStream.recv? exposed an empty chunk"

def initialInboundLifecycleTest : IO Unit := Async.block do
  let aborted ← IO.mkRef false
  let retired ← IO.mkRef false
  let underlying : Transport.ByteStream := {
    version := .http1
    recvImpl := fun _ => pure (.ok (some "underlying".toUTF8))
    sendImpl := fun _ => pure (.ok ())
    finishSendImpl := fun _ => pure (.ok ())
    abortImpl := aborted.set true
    retireImpl := fun _ => retired.set true
  }
  let wrapped ← Transport.Http1.withInitialInbound underlying "initial".toUTF8
  let first ← takeTransport "initial receive" (← wrapped.recv?)
  let second ← takeTransport "underlying receive" (← wrapped.recv?)
  expect (first == some "initial".toUTF8 && second == some "underlying".toUTF8)
    "HTTP/1 upgraded stream did not preserve exact coalesced-byte order"

  let cancelled ← Transport.Http1.withInitialInbound underlying "discard me".toUTF8
  cancelled.abort
  let afterAbort ← takeTransport "receive after wrapper abort" (← cancelled.recv?)
  expect (afterAbort == some "underlying".toUTF8)
    "HTTP/1 wrapper retained coalesced bytes after abort"
  cancelled.retire
  expect (← aborted.get) "HTTP/1 wrapper did not forward abort"
  expect (← retired.get) "HTTP/1 wrapper did not forward retirement"

def tunnelFrom (waitImpl cancelImpl : Async Unit) : Grpc.Http2.ExtendedConnect.Tunnel := {
  sendBytesImpl := fun _ => pure (.ok ())
  recvBytesImpl := pure (.ok none)
  closeSendImpl := pure (.ok ())
  cancelImpl
  waitImpl := do waitImpl; pure (.ok ())
}

def cleanHttp2LifecycleTest : IO Unit := Async.block do
  let ended ← IO.Promise.new
  let cancelCount ← IO.mkRef (0 : Nat)
  let tunnel := tunnelFrom
    (do discard <| Async.ofTask ended.result?)
    (cancelCount.modify (· + 1))
  let stream ← Transport.Http2.ofTunnel tunnel
  ended.resolve ()
  stream.retire
  expect ((← cancelCount.get) == 0) "clean HTTP/2 retirement sent RST_STREAM"

def faultyHttp2LifecycleTest : IO Unit := Async.block do
  let neverWait : IO.Promise Unit ← IO.Promise.new
  let neverCancel : IO.Promise Unit ← IO.Promise.new
  let cancelCount ← IO.mkRef (0 : Nat)
  let tunnel := tunnelFrom
    (do discard <| Async.ofTask neverWait.result?)
    (do
      cancelCount.modify (· + 1)
      discard <| Async.ofTask neverCancel.result?)
  let stream ← Transport.Http2.ofTunnel tunnel
  stream.abort
  stream.abort
  let retirement ← Async.toIO stream.retire
  expect (← waitTaskWithin retirement 400)
    "faulty HTTP/2 cancel/wait made ByteStream.retire unbounded"
  try Async.ofAsyncTask retirement catch _ => pure ()
  expect ((← cancelCount.get) == 1) "sticky HTTP/2 abort invoked tunnel cancellation more than once"

def loopback : IO (TCP.Socket.Client × TCP.Socket.Client) := do
  let listener ← TCP.Socket.Server.mk
  listener.bind (.v4 { addr := IPv4Addr.ofParts 127 0 0 1, port := 0 })
  listener.listen 8
  let address ← listener.getSockName
  let accepted ← Async.toIO listener.accept
  let client ← TCP.Socket.Client.mk
  Async.block (client.connect address)
  let server ← Async.block (Async.ofAsyncTask accepted)
  pure (client, server)

def plainTransportTest : IO Unit := do
  let (client, peer) ← loopback
  let stream ← Transport.Plain.ofSocket client { readSize := 0 }
  Async.block do
    let peerRead ← Async.toIO (peer.recv? 16)
    takeTransport "plain send" (← stream.send "plain".toUTF8)
    let received ← Async.ofAsyncTask peerRead
    expect (received == some "plain".toUTF8)
      "plaintext adapter acknowledged bytes before the socket writer completed"

    let receive ← Async.toIO stream.recv?
    stream.abort
    expect (← waitTaskWithin receive 100) "plaintext abort did not wake a pending receive"
    match ← Async.ofAsyncTask receive with
    | .error error => expect (error.kind == .cancelled) "plaintext abort returned wrong failure"
    | .ok _ => throw (IO.userError "plaintext receive succeeded after abort")
    stream.retire
    stream.retire
    try peer.shutdown catch _ => pure ()

def plainFinishIdempotencyTest : IO Unit := do
  let (client, peer) ← loopback
  let stream ← Transport.Plain.ofSocket client
  Async.block do
    let first ← Async.toIO stream.finishSend
    let second ← Async.toIO stream.finishSend
    takeTransport "first plain finish" (← Async.ofAsyncTask first)
    takeTransport "concurrent idempotent plain finish" (← Async.ofAsyncTask second)
    stream.retire
    try peer.shutdown catch _ => pure ()

def retirePlainConnection (listener : TCP.Socket.Server) (address : SocketAddress) : IO Unit := do
  let accepted ← Async.toIO listener.accept
  let client ← TCP.Socket.Client.mk
  Async.block (client.connect address)
  let peer ← Async.block (Async.ofAsyncTask accepted)
  let stream ← Transport.Plain.ofSocket client
  Async.block do
    takeTransport "clean plain finish" (← stream.finishSend)
    let eof ← peer.recv? 16
    expect eof.isNone "plain peer did not observe the finished send direction"
    stream.retire
    try peer.shutdown catch _ => pure ()

def processFdCount? : IO (Option Nat) := do
  try
    pure (some (← (System.FilePath.mk "/proc/self/fd").readDir).size)
  catch _ => pure none

def repeatedPlainRetirementTest : IO Unit := do
  let listener ← TCP.Socket.Server.mk
  listener.bind (.v4 { addr := IPv4Addr.ofParts 127 0 0 1, port := 0 })
  listener.listen 8
  let address ← listener.getSockName
  -- Warm lazy runtime descriptors before taking the comparison baseline.
  retirePlainConnection listener address
  let before? ← processFdCount?
  for _ in [0:32] do
    retirePlainConnection listener address
  IO.sleep 10
  match before?, ← processFdCount? with
  | some before, some after =>
      expect (after <= before + 2)
        s!"clean plaintext retirement retained descriptors: {before} -> {after}"
  | _, _ => pure ()

def main : IO Unit := do
  byteStreamNormalizationTest
  initialInboundLifecycleTest
  cleanHttp2LifecycleTest
  faultyHttp2LifecycleTest
  plainTransportTest
  plainFinishIdempotencyTest
  repeatedPlainRetirementTest
  IO.println "transport lifecycle tests passed"
