module

public import Std.Async

public section

namespace Ws.Transport

open Std.Async

/-- The HTTP mapping that owns a WebSocket byte stream. -/
inductive Version where
  | http1
  | http2
  deriving Inhabited, Repr, BEq, DecidableEq

/-- Transport failures are kept independent of protocol errors so callers can
preserve the reason a connection ended without parsing exception text. -/
inductive FailureKind where
  | io
  | closed
  | cancelled
  | reset
  | protocol
  deriving Inhabited, Repr, BEq, DecidableEq

structure Failure where
  kind : FailureKind
  message : String
  code : Option Nat := none
  deriving Inhabited, Repr, BEq, DecidableEq

namespace Failure

def io (operation : String) (error : IO.Error) : Failure :=
  { kind := .io, message := s!"{operation}: {error}" }

def closed (message : String := "transport is closed") : Failure :=
  { kind := .closed, message }

def cancelled (message : String := "transport was cancelled") : Failure :=
  { kind := .cancelled, message }

def reset (code : Nat) (message : String) : Failure :=
  { kind := .reset, message, code := some code }

def protocol (message : String) : Failure :=
  { kind := .protocol, message }

end Failure

/-- A single ordered, reliable byte stream.  Implementations must serialize
concurrent writes or reject them; a successful `send` means the bytes have
reached the underlying transport writer, not merely an unbounded staging
queue.  Exactly one task may call `recv?` at a time. -/
structure ByteStream where
  version : Version
  recvImpl : Unit → Async (Except Failure (Option ByteArray))
  sendImpl : ByteArray → Async (Except Failure Unit)
  finishSendImpl : Unit → Async (Except Failure Unit)
  abortImpl : IO Unit
  retireImpl : Unit → Async Unit

namespace ByteStream

partial def recv? (stream : ByteStream) : Async (Except Failure (Option ByteArray)) := do
  match ← stream.recvImpl () with
  | .ok (some bytes) =>
      if bytes.isEmpty then recv? stream else pure (.ok (some bytes))
  | result => pure result

def send (stream : ByteStream) (bytes : ByteArray) : Async (Except Failure Unit) :=
  if bytes.isEmpty then pure (.ok ()) else stream.sendImpl bytes

/-- Gracefully half-close this stream's local send direction.  The operation is
idempotent. -/
def finishSend (stream : ByteStream) : Async (Except Failure Unit) :=
  stream.finishSendImpl ()

/-- Request prompt, idempotent cancellation.  This never waits for a peer. -/
def abort (stream : ByteStream) : IO Unit :=
  stream.abortImpl

/-- Retire resources after graceful completion or `abort`.  The connection
owner retains and joins this exact action; implementations must not launch
detached teardown tasks from `abortImpl`. -/
def retire (stream : ByteStream) : Async Unit :=
  stream.retireImpl ()

end ByteStream

end Ws.Transport
