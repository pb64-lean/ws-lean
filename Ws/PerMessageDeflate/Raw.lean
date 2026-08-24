module

public section

namespace Ws.PerMessageDeflate.Raw

/-- Which half of zlib's raw-DEFLATE API a context drives. -/
inductive Mode where
  | compress
  | decompress
  deriving Inhabited, Repr, BEq, DecidableEq

/-- Errors reported by the native streaming boundary.  Keeping allocation,
peer-data, and configured-limit failures separate is important when deciding
whether a WebSocket close frame can still be sent. -/
inductive Error where
  | invalidWindow
  | outOfMemory
  | corruptData
  | outputLimit
  | closed
  | backend
  deriving Inhabited, Repr, BEq, DecidableEq

instance : ToString Error where
  toString
    | .invalidWindow => "invalid or unsupported DEFLATE window size"
    | .outOfMemory => "DEFLATE allocation failed"
    | .corruptData => "invalid compressed WebSocket message"
    | .outputLimit => "inflated WebSocket message exceeds its configured limit"
    | .closed => "DEFLATE context is closed"
    | .backend => "DEFLATE backend failure"

private opaque ContextImpl : NonemptyType

/-- A persistent zlib stream.  A context is thread-confined: callers serialize
operations on it, and `close` is called only after its last operation returns. -/
def Context : Type := ContextImpl.type

instance : Nonempty Context := ContextImpl.property

@[extern "ws_deflate_create"]
private opaque createRaw (compress : Bool) (windowBits : UInt8) : IO (Except Error Context)

@[extern "ws_deflate_process"]
private opaque processRaw (context : @& Context) (input : @& ByteArray) (maxOutput : UInt64)
    (resetBefore : Bool) : IO (Except Error ByteArray)

@[extern "ws_deflate_close"]
opaque Context.close (context : @& Context) : IO Unit

/-- Create a raw (no zlib or gzip wrapper) persistent stream.  zlib commonly
cannot produce an 8-bit raw window even though it can consume one; that backend
limitation is reported rather than silently negotiating a different value. -/
def create (mode : Mode) (windowBits : UInt8) : IO (Except Error Context) := do
  if windowBits < 8 || windowBits > 15 then
    pure (.error .invalidWindow)
  else
    createRaw (mode == .compress) windowBits

/-- Process exactly one per-message-deflate message.  Compression performs
`Z_SYNC_FLUSH` and removes its four-octet marker.  Decompression supplies that
marker virtually.  `resetBefore` implements negotiated no-context-takeover. -/
def process (context : Context) (input : ByteArray) (maxOutput : UInt64)
    (resetBefore : Bool := false) : IO (Except Error ByteArray) :=
  processRaw context input maxOutput resetBefore

end Ws.PerMessageDeflate.Raw
