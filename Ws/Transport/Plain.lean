module

public import Std.Async.TCP
public import Std.Sync.Channel
public import Std.Sync.Mutex
public import Grpc.CancellationToken
public import Ws.Transport.ByteStream

public section

namespace Ws.Transport.Plain

open Std
open Std.Async
open Std.Net

structure Config where
  readSize : UInt64 := 16384
  /-- Maximum cooperative wait for each retained writer/shutdown task during
  direct stream retirement. The connection owner applies its own outer bound. -/
  retireTimeoutMs : Nat := 100
  deriving Inhabited, Repr

private inductive SendPhase where
  | open
  | finishing
  | finished
  | aborted
  deriving Inhabited, BEq

private structure SendState where
  phase : SendPhase := .open
  active : Bool := false
  pending? : Option (IO.Promise (Except Failure Unit)) := none
  retired : Bool := false

private inductive WriteOperation where
  | send (bytes : ByteArray)
  | finish

private structure WriteRequest where
  operation : WriteOperation
  completion : IO.Promise (Except Failure Unit)

private inductive ReadEvent where
  | received (bytes : Option ByteArray)
  | cancelled

private inductive Claim where
  | claimed
  | waiting (completion : IO.Promise (Except Failure Unit))
  | busy
  | finished
  | aborted

private def claimSend (state : Std.Mutex SendState)
    (completion : IO.Promise (Except Failure Unit)) : BaseIO Claim :=
  state.atomically do
    let current ← get
    match current.phase with
    | .aborted => pure .aborted
    | .finishing | .finished => pure .finished
    | .open =>
        if current.active then
          pure .busy
        else
          set { current with active := true, pending? := some completion }
          pure .claimed

private def claimFinish (state : Std.Mutex SendState)
    (completion : IO.Promise (Except Failure Unit)) : BaseIO Claim :=
  state.atomically do
    let current ← get
    match current.phase with
    | .aborted => pure .aborted
    | .finished => pure .finished
    | .finishing =>
        match current.pending? with
        | some pending => pure (.waiting pending)
        | none => pure .busy
    | .open =>
        if current.active then
          pure .busy
        else
          set { current with
            phase := .finishing, active := true, pending? := some completion }
          pure .claimed

private def recv (socket : TCP.Socket.Client) (config : Config)
    (abortToken : Std.CancellationToken) : Async (Except Failure (Option ByteArray)) := do
  try
    let event : ReadEvent ← Selectable.one #[
      Selectable.case (socket.recvSelector config.readSize) fun bytes =>
        pure (ReadEvent.received bytes),
      Selectable.case abortToken.selector fun _ => pure ReadEvent.cancelled
    ]
    match event with
    | .received bytes => pure (.ok bytes)
    | .cancelled => pure (.error (Failure.cancelled "transport was cancelled"))
  catch error =>
    pure (.error (Failure.io "receive" error))

private def completeWrite (state : Std.Mutex SendState) (request : WriteRequest)
    (result : Except Failure Unit) : IO Unit := do
  state.atomically do
    let current ← get
    if current.phase != .aborted then
      let phase := match result with
        | .error _ => .finished
        | .ok _ => match request.operation with
          | .send _ => current.phase
          | .finish => .finished
      set { current with phase, active := false, pending? := none }
  request.completion.resolve result

private partial def writerLoop (socket : TCP.Socket.Client)
    (state : Std.Mutex SendState) (requests : Std.CloseableChannel WriteRequest) :
    Async Unit := do
  match ← await (← requests.recv) with
  | none => pure ()
  | some request =>
      let result : Except Failure Unit ← try
        match request.operation with
        | .send bytes =>
            socket.send bytes
            pure (.ok ())
        | .finish =>
            socket.shutdown
            pure (.ok ())
      catch error =>
        let operation := match request.operation with
          | .send _ => "send"
          | .finish => "finish send"
        pure (.error (Failure.io operation error))
      completeWrite state request result
      match result, request.operation with
      | .ok _, .send _ => writerLoop socket state requests
      | _, _ =>
          discard <| requests.close.toBaseIO
          pure ()

private def submit (state : Std.Mutex SendState)
    (requests : Std.CloseableChannel WriteRequest) (operation : WriteOperation) :
    Async (Except Failure Unit) := do
  let completion ← IO.Promise.new
  let claim ← match operation with
    | .send _ => claimSend state completion
    | .finish => claimFinish state completion
  match claim with
  | .busy =>
      pure (.error (Failure.protocol "concurrent transport writes are not supported"))
  | .finished =>
      match operation with
      | .finish => pure (.ok ())
      | .send _ => pure (.error (Failure.closed "transport send direction is closed"))
  | .aborted => pure (.error (Failure.cancelled "transport was cancelled"))
  | .waiting pending =>
      match ← Async.ofTask pending.result? with
      | some result => pure result
      | none => pure (.error (Failure.closed "transport writer completion was dropped"))
  | .claimed =>
      match (← (Std.CloseableChannel.Sync.send requests { operation, completion }).toBaseIO) with
      | .error _ =>
          let failure := Failure.closed "transport writer is closed"
          completeWrite state { operation, completion } (.error failure)
          pure (.error failure)
      | .ok _ =>
          match ← Async.ofTask completion.result? with
          | some result => pure result
          | none => pure (.error (Failure.closed "transport writer completion was dropped"))

private def waitTaskWithin (task : AsyncTask α) (timeoutMs : Nat) : Async Bool := do
  let mut finished ← IO.hasFinished task
  for _ in [0:timeoutMs] do
    if finished then break
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    finished ← IO.hasFinished task
  pure finished

private def retireFinishedTask (task : AsyncTask α) : Async Unit := do
  if ← IO.hasFinished task then
    try discard <| Async.ofAsyncTask task catch _ => pure ()

private def abortWriter (state : Std.Mutex SendState)
    (requests : Std.CloseableChannel WriteRequest) (owner : AsyncTask Unit) : IO Unit := do
  let pending? ← state.atomically do
    let current ← get
    set { current with phase := .aborted, active := false, pending? := none }
    pure current.pending?
  if let some completion := pending? then
    completion.resolve (.error (Failure.cancelled "transport was cancelled"))
  discard <| requests.close.toBaseIO
  IO.cancel owner

private def boundedShutdown (socket : TCP.Socket.Client) (timeoutMs : Nat) : Async Unit := do
  let task ← Async.toIO socket.shutdown
  unless ← waitTaskWithin task timeoutMs do IO.cancel task
  retireFinishedTask task

private def retire (socket : TCP.Socket.Client) (state : Std.Mutex SendState)
    (requests : Std.CloseableChannel WriteRequest) (owner : AsyncTask Unit)
    (config : Config) : Async Unit := do
  let elected ← state.atomically do
    let current ← get
    if current.retired then pure false
    else
      set { current with retired := true }
      pure true
  if elected then
    discard <| requests.close.toBaseIO
    unless ← waitTaskWithin owner config.retireTimeoutMs do
      abortWriter state requests owner
    retireFinishedTask owner
    let needsShutdown ← state.atomically do
      pure ((← get).phase != .finished)
    if needsShutdown then
      -- This is the strongest socket-retirement primitive exposed by the
      -- pinned TCP API. Cancellation bounds the Lean wait; an in-flight native
      -- write or shutdown promise may remain alive until libuv/OS settlement.
      boundedShutdown socket config.retireTimeoutMs

/-- Adapt an already-connected plaintext socket.  The returned stream does not
own connection establishment. Aborting synchronously stops the retained writer,
wakes its acknowledged caller and any pending receive, and leaves bounded
write-side shutdown to `retire`; the pinned socket API provides no separate
full-close primitive. -/
def ofSocket (socket : TCP.Socket.Client) (config : Config := {}) : IO ByteStream := do
  let abortToken ← Std.CancellationToken.new
  let sendState ← Std.Mutex.new {}
  let requests ← Std.CloseableChannel.new (some 1)
  let writer ← Async.toIO (writerLoop socket sendState requests)
  let config := if config.readSize == 0 then { config with readSize := 1 } else config
  pure {
    version := .http1
    recvImpl := fun _ => recv socket config abortToken
    sendImpl := fun bytes => submit sendState requests (.send bytes)
    finishSendImpl := fun _ => submit sendState requests .finish
    abortImpl := do
      discard <| Grpc.CancellationToken.cancel abortToken
        (reason := Std.CancellationReason.cancel)
      abortWriter sendState requests writer
    retireImpl := fun _ => retire socket sendState requests writer config
  }

end Ws.Transport.Plain
