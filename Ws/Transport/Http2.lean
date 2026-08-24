module

public import Grpc.CancellationToken
public import Grpc.Http2.ExtendedConnect
public import Ws.Transport.ByteStream

public section

namespace Ws.Transport.Http2

open Std.Async

private def asyncTaskSelector (task : AsyncTask α) : Selector α := {
  tryFn := do
    if ← IO.hasFinished task then some <$> Async.ofAsyncTask task else pure none
  registerFn := fun waiter => do
    discard <| IO.mapTask (t := task) (sync := true) fun result =>
      waiter.race (pure ()) fun promise => promise.resolve result
  unregisterFn := pure ()
}

private def waitTaskWithin (task : AsyncTask α) (timeoutMs : Nat) : Async Bool := do
  let mut finished ← IO.hasFinished task
  for _ in [0:timeoutMs] do
    if finished then break
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    finished ← IO.hasFinished task
  pure finished

private def cancelAndRetireTask (task : AsyncTask α) (timeoutMs : Nat) : Async Unit := do
  IO.cancel task
  if ← waitTaskWithin task timeoutMs then
    try discard <| Async.ofAsyncTask task catch _ => pure ()

private inductive LifecycleEvent where
  | tunnelEnded
  | abortRequested

private def lifecycleOwner (tunnel : Grpc.Http2.ExtendedConnect.Tunnel)
    (abortToken : Std.CancellationToken) : Async Unit := do
  -- One retained waiter owns observation and removal of the HTTP/2 stream for
  -- the adapter's entire lifetime.  Abort work is also retained here, so the
  -- synchronous ByteStream abort hook never launches detached teardown.
  let waitTask ← Async.toIO tunnel.wait
  let event : LifecycleEvent ← Selectable.one #[
    Selectable.case (asyncTaskSelector waitTask) fun _ => pure .tunnelEnded,
    Selectable.case abortToken.selector fun _ => pure .abortRequested
  ]
  match event with
  | .tunnelEnded =>
      try discard <| Async.ofAsyncTask waitTask catch _ => pure ()
  | .abortRequested =>
      let cancelTask ← Async.toIO tunnel.cancel
      if ← waitTaskWithin cancelTask 50 then
        try Async.ofAsyncTask cancelTask catch _ => pure ()
      else
        cancelAndRetireTask cancelTask 50
      -- Real tunnel cancellation wakes `wait`.  Faulty implementations still
      -- cannot retain this adapter owner forever.
      if ← waitTaskWithin waitTask 50 then
        try discard <| Async.ofAsyncTask waitTask catch _ => pure ()
      else
        cancelAndRetireTask waitTask 50

private def failure (status : Grpc.Status) : Failure :=
  match status.code with
  | .cancelled => Failure.cancelled status.messageD
  | .invalidArgument | .failedPrecondition => Failure.protocol status.messageD
  | code => Failure.reset code.toNat status.messageD

private def recv (tunnel : Grpc.Http2.ExtendedConnect.Tunnel) :
    Async (Except Failure (Option ByteArray)) := do
  match ← tunnel.recv? with
  | .ok bytes => pure (.ok bytes)
  | .error status => pure (.error (failure status))

private def send (tunnel : Grpc.Http2.ExtendedConnect.Tunnel) (bytes : ByteArray) :
    Async (Except Failure Unit) := do
  match ← tunnel.send bytes with
  | .ok _ => pure (.ok ())
  | .error status => pure (.error (failure status))

private def finishSend (tunnel : Grpc.Http2.ExtendedConnect.Tunnel) :
    Async (Except Failure Unit) := do
  match ← tunnel.closeSend with
  | .ok _ => pure (.ok ())
  | .error status => pure (.error (failure status))

/-- Adapt one successful RFC 8441 extended CONNECT stream. Abort signaling is
sticky and synchronous. A retained lifecycle owner observes `Tunnel.wait`,
performs the actual RST_STREAM request, and bounds cancellation of a faulty
tunnel implementation before `ByteStream.retire` joins that exact owner. -/
def ofTunnel (tunnel : Grpc.Http2.ExtendedConnect.Tunnel) : IO ByteStream := do
  let abortToken ← Std.CancellationToken.new
  let owner ← Async.toIO (lifecycleOwner tunnel abortToken)
  pure {
    version := .http2
    recvImpl := fun _ => recv tunnel
    sendImpl := send tunnel
    finishSendImpl := fun _ => finishSend tunnel
    abortImpl := do
      discard <| Grpc.CancellationToken.cancel abortToken
        (reason := Std.CancellationReason.cancel)
    retireImpl := fun _ => do
      try Async.ofAsyncTask owner catch _ => pure ()
  }

end Ws.Transport.Http2
