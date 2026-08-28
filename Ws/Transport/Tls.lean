module

public import Std.Async.TCP
public import Std.Sync.Mutex
public import Http2.CancellationToken
public import Http2.Tls.Session
public import Ws.Transport.ByteStream

public section

namespace Ws.Transport.Tls

open Std
open Std.Async
open Std.Net

structure Config where
  readSize : UInt64 := 16384
  deriving Inhabited, Repr

private inductive ReadEvent where
  | received (bytes : Option ByteArray)
  | cancelled
  | writerFailed

private inductive FinishState where
  | open
  | running (completion : IO.Promise (Except Failure Unit))
  | finished (result : Except Failure Unit)
  | aborted

private inductive FinishClaim where
  | elected (completion : IO.Promise (Except Failure Unit))
  | waiting (completion : IO.Promise (Except Failure Unit))
  | completed (result : Except Failure Unit)
  | aborted

private partial def recvPlaintext (socket : TCP.Socket.Client) (readSize : UInt64)
    (feedInbound : ByteArray → IO (Option ByteArray))
    (writerFailure : Selector Unit) (abortToken : Std.CancellationToken) :
    Async (Except Failure (Option ByteArray)) := do
  try
    let event : ReadEvent ← Selectable.one #[
      Selectable.case (socket.recvSelector readSize) fun bytes => pure (.received bytes),
      Selectable.case abortToken.selector fun _ => pure .cancelled,
      Selectable.case writerFailure fun _ => pure .writerFailed
    ]
    match event with
    | .cancelled => pure (.error (Failure.cancelled "TLS transport was cancelled"))
    | .writerFailed => pure (.error (Failure.closed "TLS record writer failed"))
    | .received none => pure (.ok none)
    | .received (some bytes) =>
        match ← feedInbound bytes with
        | none => pure (.ok none)
        | some plaintext =>
            if plaintext.isEmpty then
              recvPlaintext socket readSize feedInbound writerFailure abortToken
            else
              pure (.ok (some plaintext))
  catch error =>
    pure (.error (Failure.io "TLS receive" error))

private def claimFinish (state : Std.Mutex FinishState) : IO FinishClaim := do
  let completion ← IO.Promise.new
  state.atomically do
    match ← get with
    | .open =>
        set (FinishState.running completion)
        pure (.elected completion)
    | .running existing => pure (.waiting existing)
    | .finished result => pure (.completed result)
    | .aborted => pure .aborted

private def awaitFinish (completion : IO.Promise (Except Failure Unit)) :
    Async (Except Failure Unit) := do
  match ← Async.ofTask completion.result? with
  | some result => pure result
  | none => pure (.error (Failure.closed "TLS close_notify completion was dropped"))

private def finishSend (state : Std.Mutex FinishState) (requested : IO.Promise Bool) :
    Async (Except Failure Unit) := do
  match ← claimFinish state with
  | .waiting completion => awaitFinish completion
  | .completed result => pure result
  | .aborted => pure (.error (Failure.cancelled "TLS transport was cancelled"))
  | .elected completion =>
      discard <| requested.resolve true
      awaitFinish completion

private def finishOwner (state : Std.Mutex FinishState) (requested : IO.Promise Bool)
    (closeNotify : IO Unit) : Async Unit := do
  match ← Async.ofTask requested.result? with
  | none | some false => pure ()
  | some true =>
      let shouldRun ← state.atomically do
        match ← get with
        | .running _ => pure true
        | _ => pure false
      if shouldRun then
        let result : Except Failure Unit ← try
          closeNotify
          pure (.ok ())
        catch error =>
          pure (.error (Failure.io "TLS close_notify" error))
        let (completion?, published) ← state.atomically do
          match ← get with
          | .running completion =>
              set (FinishState.finished result)
              pure (some completion, result)
          | .aborted =>
              pure (none, .error (Failure.cancelled "TLS transport was cancelled"))
          | .finished previous => pure (none, previous)
          | .open => pure (none, result)
        if let some completion := completion? then completion.resolve published

private def abortFinish (state : Std.Mutex FinishState) : IO Unit := do
  let completion? ← state.atomically do
    match ← get with
    | .open =>
        set FinishState.aborted
        pure none
    | .running completion =>
        set FinishState.aborted
        pure (some completion)
    | .finished _ => pure none
    | .aborted => pure none
  if let some completion := completion? then
    completion.resolve (.error (Failure.cancelled "TLS transport was cancelled"))

private def make (socket : TCP.Socket.Client) (initialInbound : ByteArray)
    (feedInbound : ByteArray → IO (Option ByteArray))
    (sendAcknowledged : ByteArray → Async Unit)
    (closeNotify : IO Unit) (abortSession : IO Unit) (closeSession : Async Unit)
    (writerFailure : Selector Unit) (config : Config) : IO ByteStream := do
  let config := if config.readSize == 0 then { config with readSize := 1 } else config
  let pending ← IO.mkRef (if initialInbound.isEmpty then none else some initialInbound)
  let abortToken ← Std.CancellationToken.new
  let finishState ← Std.Mutex.new FinishState.open
  let finishRequested ← IO.Promise.new
  let finishTask ← Async.toIO (finishOwner finishState finishRequested closeNotify)
  pure {
    version := .http1
    recvImpl := fun _ => do
      match ← pending.modifyGet fun current => (current, none) with
      | some bytes => pure (.ok (some bytes))
      | none => recvPlaintext socket config.readSize feedInbound writerFailure abortToken
    sendImpl := fun bytes => do
      try
        sendAcknowledged bytes
        pure (.ok ())
      catch error =>
        pure (.error (Failure.io "TLS send" error))
    finishSendImpl := fun _ => finishSend finishState finishRequested
    abortImpl := do
      discard <| Http2.CancellationToken.cancel abortToken
        (reason := Std.CancellationReason.cancel)
      abortFinish finishState
      discard <| finishRequested.resolve false
      -- The session owns its record writer.  Stopping it synchronously wakes
      -- acknowledged sends without launching teardown that could outlive the
      -- connection owner's retained retirement action.
      abortSession
    retireImpl := fun _ => do
      abortFinish finishState
      discard <| finishRequested.resolve false
      try Async.ofAsyncTask finishTask catch _ => pure ()
      try closeSession catch _ => pure ()
  }

/-- Adapt a verified client TLS session for HTTP/1 WebSocket traffic.  The
selected ALPN must be checked by the caller before construction. -/
def ofClientSession (session : Http2.Tls.ClientSession)
    (initialInbound : ByteArray := ByteArray.empty) (config : Config := {}) :
    IO ByteStream :=
  make session.socket initialInbound session.feedInbound session.sendAcknowledged
    session.closeNotify session.abort session.retireOwned session.writerFailureSelector config

/-- Adapt an established server TLS session for HTTP/1 WebSocket traffic. -/
def ofServerSession (session : Http2.Tls.ServerSession)
    (initialInbound : ByteArray := ByteArray.empty) (config : Config := {}) :
    IO ByteStream :=
  make session.socket initialInbound session.feedInbound session.sendAcknowledged
    session.closeNotify session.abort session.retireOwned session.writerFailureSelector config

end Ws.Transport.Tls
