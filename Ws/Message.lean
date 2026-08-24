module

public import Ws.Frame
public import Ws.Utf8

public section

namespace Ws.Message

inductive Kind where
  | text
  | binary
  deriving Inhabited, Repr, DecidableEq

/-- A complete data message. If `compressed` is true, `data` is the extension
payload and UTF-8 validation belongs to the negotiated extension after inflate. -/
structure Message where
  kind : Kind
  data : ByteArray := ByteArray.empty
  compressed : Bool := false
  deriving Inhabited, DecidableEq

/-- The parsed contents of a Close control frame. `reasonBytes` is retained so
applications that do not need a `String` do not have to encode it again. -/
structure Close where
  private mk ::
  code? : Option CloseCode := none
  reason : String := ""
  reasonBytes : ByteArray := ByteArray.empty
  deriving Inhabited, DecidableEq

inductive Event where
  | message (value : Message)
  | ping (payload : ByteArray)
  | pong (payload : ByteArray)
  | close (value : Close)
  deriving Inhabited, DecidableEq

/-- In-progress message state retained by `Decoder`. Applications normally
inspect only the events returned from `Decoder.feed`. -/
structure Fragment where
  kind : Kind
  chunks : Array ByteArray
  size : Nat
  compressed : Bool
  frames : Nat
  utf8 : Utf8.State
  deriving Inhabited

structure Decoder where
  role : Role
  limits : Limits := {}
  fragment? : Option Fragment := none
  receivedClose : Bool := false
  deriving Inhabited

namespace Close

/-- Construct an outbound close value and enforce the wire restrictions that
cannot be expressed by the structure alone. -/
def create (role : Role) (code? : Option CloseCode := none)
    (reason : String := "") : Except Error Close := do
  let reasonBytes := reason.toUTF8
  if code?.isNone && !reasonBytes.isEmpty then
    throw (Error.invalidArgument "a WebSocket close reason requires a status code")
  if let some code := code? then
    unless code.maySend role do
      throw (Error.invalidArgument "WebSocket close status cannot be sent by this endpoint")
  if reasonBytes.size > 123 then
    throw (Error.invalidArgument "WebSocket close reason exceeds 123 bytes")
  pure { code?, reason, reasonBytes }

def payload (role : Role) (close : Close) : Except Error ByteArray := do
  match close.code? with
  | none =>
      unless close.reasonBytes.isEmpty && close.reason.isEmpty do
        throw (Error.invalidArgument "a WebSocket close reason requires a status code")
      pure ByteArray.empty
  | some code =>
      unless code.maySend role do
        throw (Error.invalidArgument "WebSocket close status cannot be sent by this endpoint")
      Utf8.validate close.reasonBytes
      if close.reasonBytes.size > 123 then
        throw (Error.invalidArgument "WebSocket close reason exceeds 123 bytes")
      pure <| (ByteArray.empty
        |>.push (UInt8.ofNat (code.value / 256))
        |>.push (UInt8.ofNat code.value)).append close.reasonBytes

end Close

private def parseClose (senderRole : Role) (payload : ByteArray) : Except Error Close := do
  if payload.isEmpty then
    pure {}
  else if payload.size == 1 then
    throw (Error.protocol "a WebSocket close payload cannot contain one byte")
  else
    let value := payload[0]!.toNat * 256 + payload[1]!.toNat
    let some code := CloseCode.ofWire? value
      | throw (Error.protocol "invalid WebSocket close status")
    unless code.maySend senderRole do
      throw (Error.protocol "WebSocket close status cannot be sent by the peer")
    let reasonBytes := payload.extract 2 payload.size
    let reason ← Utf8.decode reasonBytes
    pure { code? := some code, reason, reasonBytes }

private def checkedSize (limits : Limits) (accumulated suffix : Nat) : Except Error Nat := do
  if suffix > limits.maxMessagePayloadBytes ||
      accumulated > limits.maxMessagePayloadBytes - suffix then
    throw (Error.messageTooBig "WebSocket message exceeds the configured payload limit")
  pure (accumulated + suffix)

private def joinChunks (chunks : Array ByteArray) (size : Nat) : ByteArray := Id.run do
  let mut data := ByteArray.emptyWithCapacity size
  for chunk in chunks do
    data := data.append chunk
  return data

private def kindOfOpcode : Frame.Opcode -> Option Kind
  | .text => some .text
  | .binary => some .binary
  | _ => none

namespace Decoder

def new (role : Role) (limits : Limits := {}) : Decoder := { role, limits }

private def initialData (decoder : Decoder) (frame : Frame.Frame) (kind : Kind) :
    Except Error (Decoder × Array Event) := do
  if decoder.fragment?.isSome then
    throw (Error.protocol "new WebSocket data frame during a fragmented message")
  if frame.payload.size > decoder.limits.maxMessagePayloadBytes then
    throw (Error.messageTooBig "WebSocket message exceeds the configured payload limit")
  if frame.fin then
    if kind == .text && !frame.rsv1 then
      Utf8.validate frame.payload
    pure (decoder, #[.message {
      kind, data := frame.payload, compressed := frame.rsv1
    }])
  else
    if decoder.limits.maxFragmentsPerMessage < 1 then
      throw (Error.messageTooBig "WebSocket message exceeds the configured fragment limit")
    let utf8 ←
      if kind == .text && !frame.rsv1 then Utf8.feed {} frame.payload
      else pure {}
    let fragment : Fragment := {
      kind, chunks := #[frame.payload], size := frame.payload.size,
      compressed := frame.rsv1, frames := 1, utf8
    }
    pure ({ decoder with fragment? := some fragment }, #[])

private def continuation (decoder : Decoder) (frame : Frame.Frame) :
    Except Error (Decoder × Array Event) := do
  if frame.rsv1 then
    throw (Error.protocol "RSV1 is set on a WebSocket continuation frame")
  let some fragment := decoder.fragment?
    | throw (Error.protocol "unexpected WebSocket continuation frame")
  let frames := fragment.frames + 1
  if frames > decoder.limits.maxFragmentsPerMessage then
    throw (Error.messageTooBig "WebSocket message exceeds the configured fragment limit")
  let size ← checkedSize decoder.limits fragment.size frame.payload.size
  let chunks := fragment.chunks.push frame.payload
  let utf8 ←
    if fragment.kind == Kind.text && !fragment.compressed then
      Utf8.feed fragment.utf8 frame.payload
    else pure fragment.utf8
  if frame.fin then
    if fragment.kind == Kind.text && !fragment.compressed then
      Utf8.finish utf8
    let data := joinChunks chunks size
    pure ({ decoder with fragment? := none }, #[.message {
      kind := fragment.kind, data, compressed := fragment.compressed
    }])
  else
    pure ({ decoder with fragment? := some {
      fragment with chunks, size, frames, utf8
    } }, #[])

/-- Consume one decoded frame. Fragmented data is reassembled while control
frames are emitted immediately and may interleave with a fragmented message. -/
def feed (decoder : Decoder) (frame : Frame.Frame) :
    Except Error (Decoder × Array Event) := do
  if decoder.receivedClose then
    if frame.opcode.control && (!frame.fin || frame.rsv1 || frame.payload.size > 125) then
      throw (Error.protocol "invalid WebSocket control frame after Close")
    match frame.opcode with
    | .pong => return (decoder, #[.pong frame.payload])
    | .ping | .close => return (decoder, #[])
    | _ => throw (Error.protocol "WebSocket data frame received after a Close frame")
  if frame.opcode.control then
    if !frame.fin || frame.rsv1 || frame.payload.size > 125 then
      throw (Error.protocol "invalid WebSocket control frame")
  match frame.opcode with
  | .continuation => continuation decoder frame
  | .text | .binary =>
      let some kind := kindOfOpcode frame.opcode
        | throw (Error.protocol "invalid WebSocket data opcode")
      initialData decoder frame kind
  | .ping => pure (decoder, #[.ping frame.payload])
  | .pong => pure (decoder, #[.pong frame.payload])
  | .close =>
      let close ← parseClose decoder.role.peer frame.payload
      pure ({ decoder with receivedClose := true }, #[.close close])

end Decoder

end Ws.Message
