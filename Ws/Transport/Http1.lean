module

public import Ws.Handshake.Http1
public import Ws.Transport.ByteStream

public section

namespace Ws.Transport.Http1

open Std.Async

inductive UpgradeFailureKind where
  | transport
  | handshake
  | unexpectedEof
  deriving Inhabited, Repr, BEq, DecidableEq

structure UpgradeFailure where
  kind : UpgradeFailureKind
  message : String
  transport? : Option Transport.Failure := none
  protocol? : Option Ws.Error := none
  deriving Inhabited, Repr

private def transportFailure (failure : Transport.Failure) : UpgradeFailure :=
  { kind := .transport, message := failure.message, transport? := some failure }

private def protocolFailure (failure : Ws.Error) : UpgradeFailure :=
  { kind := .handshake, message := failure.message, protocol? := some failure }

private def unexpectedEof : UpgradeFailure :=
  { kind := .unexpectedEof,
    message := "transport ended before the HTTP/1 opening handshake completed" }

/-- Prepend bytes already read past an HTTP head to the upgraded stream. -/
def withInitialInbound (stream : ByteStream) (initialInbound : ByteArray) : IO ByteStream := do
  if initialInbound.isEmpty then return stream
  let pending ← IO.mkRef (if initialInbound.isEmpty then none else some initialInbound)
  pure {
    stream with
    recvImpl := fun _ => do
      match ← pending.modifyGet fun current => (current, none) with
      | some bytes => pure (.ok (some bytes))
      | none => stream.recv?
    abortImpl := do
      pending.set none
      stream.abort
    retireImpl := fun _ => do
      pending.set none
      stream.retire
  }

private partial def receiveHead (stream : ByteStream)
    (parser : Handshake.Http1.Parser) :
    Async (Except UpgradeFailure (Handshake.Http1.Head × ByteArray × Nat)) := do
  match ← stream.recv? with
  | .error failure => pure (.error (transportFailure failure))
  | .ok none => pure (.error unexpectedEof)
  | .ok (some bytes) =>
      match parser.feed bytes with
      | .error failure => pure (.error (protocolFailure failure))
      | .ok (.needMore parser) => receiveHead stream parser
      | .ok (.done head remaining) =>
          pure (.ok (head, remaining, parser.buffered.size + bytes.size - remaining.size))

private def receiveHeadFrom (stream : ByteStream) (parser : Handshake.Http1.Parser)
    (initial : ByteArray) :
    Async (Except UpgradeFailure (Handshake.Http1.Head × ByteArray × Nat)) := do
  if initial.isEmpty then receiveHead stream parser else
  match parser.feed initial with
  | .error failure => pure (.error (protocolFailure failure))
  | .ok (.needMore parser) => receiveHead stream parser
  | .ok (.done head remaining) =>
      pure (.ok (head, remaining, initial.size - remaining.size))

private def responseStatus? (head : Handshake.Http1.Head) : Option Nat :=
  match head.startLine with
  | .response line => some line.status
  | .request _ => none

private partial def receiveSwitchingProtocols (stream : ByteStream)
    (offer : Handshake.Http1.ClientOffer) (limits : Limits) (initial : ByteArray)
    (informationalCount consumedBytes : Nat) :
    Async (Except UpgradeFailure
      (Handshake.Http1.ClientAccepted × ByteStream)) := do
  match ← receiveHeadFrom stream (.response limits) initial with
  | .error failure => pure (.error failure)
  | .ok (head, remaining, consumed) =>
      let total := consumedBytes + consumed
      if total > limits.maxHandshakeBytes then
        pure (.error (protocolFailure (Ws.Error.handshake
          "HTTP informational responses exceed the configured handshake limit")))
      else
        match responseStatus? head with
        | some status =>
            if 100 <= status && status < 200 && status != 101 then
              if informationalCount >= 8 then
                pure (.error (protocolFailure (Ws.Error.handshake
                  "HTTP response contains too many informational heads")))
              else
                receiveSwitchingProtocols stream offer limits remaining
                  (informationalCount + 1) total
            else
              match Handshake.Http1.validateServerResponse offer head with
              | .error failure => pure (.error (protocolFailure failure))
              | .ok accepted =>
                  pure (.ok (accepted, ← withInitialInbound stream remaining))
        | none => pure (.error (protocolFailure
            (Ws.Error.handshake "expected an HTTP response head")))

/-- Send and validate an HTTP/1.1 Upgrade request. Bytes coalesced behind the
101 response are preserved as the first input to the returned stream. -/
def clientUpgrade (stream : ByteStream) (offer : Handshake.Http1.ClientOffer)
    (limits : Limits := {}) :
    Async (Except UpgradeFailure (Handshake.Http1.ClientAccepted × ByteStream)) := do
  let request ← match Handshake.Http1.buildClientRequest offer with
    | .ok bytes => pure bytes
    | .error failure => return .error (protocolFailure failure)
  match ← stream.send request with
  | .error failure => pure (.error (transportFailure failure))
  | .ok _ =>
      receiveSwitchingProtocols stream offer limits ByteArray.empty 0 0

/-- Read one HTTP/1 request head. Bytes coalesced behind the head remain
available on the returned stream. This lower-level entry point lets a server
choose a precise bounded rejection before WebSocket validation. -/
def receiveRequestHead (stream : ByteStream) (limits : Limits := {}) :
    Async (Except UpgradeFailure (Handshake.Http1.Head × ByteStream)) := do
  match ← receiveHead stream (.request limits) with
  | .error failure => pure (.error failure)
  | .ok (head, remaining, _) =>
      pure (.ok (head, ← withInitialInbound stream remaining))

/-- Read and validate one HTTP/1.1 WebSocket Upgrade request. Bytes coalesced
behind the request head remain available on the returned stream. -/
def receiveUpgrade (stream : ByteStream) (limits : Limits := {}) :
    Async (Except UpgradeFailure (Handshake.Http1.ServerRequest × ByteStream)) := do
  match ← receiveRequestHead stream limits with
  | .error failure => pure (.error failure)
  | .ok (head, stream) =>
      let request ← match Handshake.Http1.validateClientRequest head with
        | .ok request => pure request
        | .error failure => return .error (protocolFailure failure)
      pure (.ok (request, stream))

/-- Complete a previously validated HTTP/1.1 Upgrade. -/
def acceptUpgrade (stream : ByteStream) (request : Handshake.Http1.ServerRequest)
    (accept : Handshake.Http1.ServerAccept := {}) :
    Async (Except UpgradeFailure Unit) := do
  let response ← match Handshake.Http1.buildServerResponse request accept with
    | .ok bytes => pure bytes
    | .error failure => return .error (protocolFailure failure)
  match ← stream.send response with
  | .ok _ => pure (.ok ())
  | .error failure => pure (.error (transportFailure failure))

end Ws.Transport.Http1
