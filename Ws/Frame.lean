module

public import Ws.Basic
public import Ws.Utf8

public section

namespace Ws.Frame

inductive Opcode where
  | continuation
  | text
  | binary
  | close
  | ping
  | pong
  deriving Inhabited, Repr, DecidableEq

namespace Opcode

def toNat : Opcode -> Nat
  | .continuation => 0x0
  | .text => 0x1
  | .binary => 0x2
  | .close => 0x8
  | .ping => 0x9
  | .pong => 0xa

def ofNat? : Nat -> Option Opcode
  | 0x0 => some .continuation
  | 0x1 => some .text
  | 0x2 => some .binary
  | 0x8 => some .close
  | 0x9 => some .ping
  | 0xa => some .pong
  | _ => none

def control : Opcode -> Bool
  | .close | .ping | .pong => true
  | _ => false

def data : Opcode -> Bool
  | .continuation | .text | .binary => true
  | _ => false

end Opcode

/-- A decoded frame. Masking has already been removed. RSV2/RSV3 and reserved
opcodes cannot be represented because the decoder rejects them. -/
structure Frame where
  fin : Bool := true
  rsv1 : Bool := false
  opcode : Opcode
  payload : ByteArray := ByteArray.empty
  deriving Inhabited, DecidableEq

private def maskByte (key : UInt32) (index : Nat) : UInt8 :=
  match index % 4 with
  | 0 => (key >>> 24).toUInt8
  | 1 => (key >>> 16).toUInt8
  | 2 => (key >>> 8).toUInt8
  | _ => key.toUInt8

def applyMask (key : UInt32) (payload : ByteArray) : ByteArray := Id.run do
  let mut output := ByteArray.emptyWithCapacity payload.size
  for i in [0:payload.size] do
    output := output.push (payload[i]! ^^^ maskByte key i)
  return output

private def applyMaskFrom (key : UInt32) (payloadOffset : Nat)
    (payload : ByteArray) : ByteArray := Id.run do
  let mut output := ByteArray.emptyWithCapacity payload.size
  for i in [0:payload.size] do
    output := output.push (payload[i]! ^^^ maskByte key (payloadOffset + i))
  return output

private def maskKeyAt (bytes : ByteArray) (offset : Nat) : UInt32 :=
  bytes[offset]!.toUInt32 <<< 24 |||
    bytes[offset + 1]!.toUInt32 <<< 16 |||
    bytes[offset + 2]!.toUInt32 <<< 8 |||
    bytes[offset + 3]!.toUInt32

private def readUnsigned (bytes : ByteArray) (offset count : Nat) : Nat :=
  (List.range count).foldl
    (fun value i => value * 256 + bytes[offset + i]!.toNat) 0

private structure HeaderInfo where
  fin : Bool
  rsv1 : Bool
  opcode : Opcode
  masked : Bool
  payloadLength : Nat
  headerLength : Nat
  maskKey? : Option UInt32

private inductive HeaderResult where
  | needMore
  | ready (header : HeaderInfo)

private def decodeHeader (role : Role) (limits : Limits) (allowRsv1 : Bool)
    (bytes : ByteArray) (offset : Nat) : Except Error HeaderResult := do
  let available := bytes.size - offset
  if available < 2 then
    pure .needMore
  else
    let first := bytes[offset]!
    let second := bytes[offset + 1]!
    let fin := (first &&& 0x80) != 0
    let rsv1 := (first &&& 0x40) != 0
    let rsv2 := (first &&& 0x20) != 0
    let rsv3 := (first &&& 0x10) != 0
    let opcodeValue := (first &&& 0x0f).toNat
    let some opcode := Opcode.ofNat? opcodeValue
      | throw (Error.protocol "reserved WebSocket opcode")
    if rsv2 || rsv3 then
      throw (Error.protocol "unexpected WebSocket RSV2 or RSV3 bit")
    if rsv1 && (!allowRsv1 || opcode.control || opcode == .continuation) then
      throw (Error.protocol "unexpected WebSocket RSV1 bit")
    if opcode.control && !fin then
      throw (Error.protocol "fragmented WebSocket control frame")
    let masked := (second &&& 0x80) != 0
    if masked != role.expectsMaskedInbound then
      throw (Error.protocol "WebSocket frame has the wrong masking direction")
    let lengthCode := (second &&& 0x7f).toNat
    let extraLengthBytes := if lengthCode < 126 then 0 else if lengthCode == 126 then 2 else 8
    let prefixLength := 2 + extraLengthBytes
    if available < prefixLength then
      pure .needMore
    else
      if lengthCode == 127 && (bytes[offset + 2]! &&& 0x80) != 0 then
        throw (Error.protocol "WebSocket 64-bit length has its high bit set")
      let payloadLength :=
        if lengthCode < 126 then lengthCode
        else readUnsigned bytes (offset + 2) extraLengthBytes
      if lengthCode == 126 && payloadLength < 126 then
        throw (Error.protocol "non-minimal 16-bit WebSocket payload length")
      if lengthCode == 127 && payloadLength < 65536 then
        throw (Error.protocol "non-minimal 64-bit WebSocket payload length")
      if opcode.control && payloadLength > 125 then
        throw (Error.protocol "WebSocket control payload exceeds 125 bytes")
      if payloadLength > limits.maxFramePayloadBytes then
        throw (Error.messageTooBig "WebSocket frame exceeds the configured payload limit")
      let headerLength := prefixLength + (if masked then 4 else 0)
      if available < headerLength then
        pure .needMore
      else
        let maskKey? := if masked then some (maskKeyAt bytes (offset + prefixLength)) else none
        pure (.ready {
          fin, rsv1, opcode, masked, payloadLength, headerLength, maskKey?
        })

structure Decoder where
  role : Role
  limits : Limits := {}
  allowRsv1 : Bool := false
  /-- Enable message-aware streaming validation of uncompressed text payloads.
  The connection runtime enables this so an invalid sequence can be rejected
  before the remainder of a large frame arrives. -/
  validateTextPayload : Bool := false
  buffered : ByteArray := ByteArray.empty
  fragmentedMessage : Bool := false
  fragmentTextUtf8? : Option Utf8.State := none
  partialTextUtf8? : Option Utf8.State := none
  partialTextBytes : Nat := 0
  deriving Inhabited

/-- The recoverable result of consuming one transport chunk. Frames completed
before a malformed later frame remain available in `frames`; `error?` is
terminal and applies only after that valid prefix. -/
structure FeedResult where
  decoder : Decoder
  frames : Array Frame := #[]
  error? : Option Error := none

namespace Decoder

def new (role : Role) (limits : Limits := {}) (allowRsv1 : Bool := false)
    (validateTextPayload : Bool := false) : Decoder :=
  {
    role := role
    limits := limits
    allowRsv1 := allowRsv1
    validateTextPayload := validateTextPayload
  }

private def payloadSlice (header : HeaderInfo) (bytes : ByteArray)
    (payloadStart relativeStart relativeStop : Nat) : ByteArray :=
  let wire := bytes.extract (payloadStart + relativeStart) (payloadStart + relativeStop)
  match header.maskKey? with
  | none => wire
  | some key => applyMaskFrom key relativeStart wire

private def textValidationBase? (validate : Bool) (fragmented : Bool)
    (fragmentTextUtf8? : Option Utf8.State) (header : HeaderInfo) : Option Utf8.State :=
  if !validate then none
  else
    match header.opcode with
    | .text =>
        if !fragmented && !header.rsv1 then some {} else none
    | .continuation =>
        if fragmented then fragmentTextUtf8? else none
    | _ => none

private def retainedSuffix (bytes : ByteArray) (offset : Nat) : ByteArray :=
  if offset == 0 then bytes
  else if offset == bytes.size then ByteArray.empty
  else bytes.extract offset bytes.size

/-- Consume a transport chunk without losing the valid prefix when a later
frame in the same chunk is malformed. An incomplete suffix is retained once,
and uncompressed text is optionally checked as payload bytes become available. -/
def feedBatch (decoder : Decoder) (chunk : ByteArray) : FeedResult := Id.run do
  let role := decoder.role
  let limits := decoder.limits
  let allowRsv1 := decoder.allowRsv1
  let validateTextPayload := decoder.validateTextPayload
  -- Compiled `ByteArray.append` grows geometrically when this retained buffer
  -- is uniquely owned, which is the normal streaming use of this API.
  let bytes := decoder.buffered.append chunk
  let mut offset := 0
  let mut frames : Array Frame := #[]
  let mut fragmentedMessage := decoder.fragmentedMessage
  let mut fragmentTextUtf8? := decoder.fragmentTextUtf8?
  let mut partialTextUtf8? := decoder.partialTextUtf8?
  let mut partialTextBytes := decoder.partialTextBytes
  let mut terminalError? : Option Error := none
  let mut done := false
  while !done && terminalError?.isNone do
    match decodeHeader role limits allowRsv1 bytes offset with
    | .error error =>
        terminalError? := some error
    | .ok .needMore =>
        done := true
    | .ok (.ready header) =>
        let payloadStart := offset + header.headerLength
        let availablePayload := min header.payloadLength (bytes.size - payloadStart)
        let complete := availablePayload == header.payloadLength
        let validationState? := match partialTextUtf8? with
          | some state => some state
          | none => textValidationBase? validateTextPayload fragmentedMessage
              fragmentTextUtf8? header
        let validatedBytes := if partialTextUtf8?.isSome then
            min partialTextBytes availablePayload
          else 0
        let available := payloadSlice header bytes payloadStart validatedBytes availablePayload
        let checkedStateResult : Except Error (Option Utf8.State) :=
          match validationState? with
          | none => .ok none
          | some state => some <$> Utf8.feed state available
        match checkedStateResult with
        | .error error =>
            terminalError? := some error
        | .ok checkedState? =>
            if !complete then
              partialTextUtf8? := checkedState?
              partialTextBytes := if checkedState?.isSome then availablePayload else 0
              done := true
            else
              let finishResult : Except Error Unit :=
                match checkedState? with
                | some state => if header.fin then Utf8.finish state else .ok ()
                | none => .ok ()
              match finishResult with
              | .error error =>
                  terminalError? := some error
              | .ok _ =>
                  let payload := payloadSlice header bytes payloadStart 0 header.payloadLength
                  let frame : Frame := {
                    fin := header.fin, rsv1 := header.rsv1,
                    opcode := header.opcode, payload
                  }
                  frames := frames.push frame
                  offset := payloadStart + header.payloadLength
                  partialTextUtf8? := none
                  partialTextBytes := 0
                  if !fragmentedMessage then
                    match header.opcode with
                    | .text | .binary =>
                        if !header.fin then
                          fragmentedMessage := true
                          fragmentTextUtf8? :=
                            if header.opcode == .text && !header.rsv1 then checkedState?
                            else none
                    | _ => pure ()
                  else
                    match header.opcode with
                    | .continuation =>
                        if header.fin then
                          fragmentedMessage := false
                          fragmentTextUtf8? := none
                        else if fragmentTextUtf8?.isSome then
                          fragmentTextUtf8? := checkedState?
                    | _ => pure ()
                  -- Close is terminal for the current protocol read. Retain,
                  -- but do not inspect, coalesced bytes that follow it.
                  if header.opcode == .close then done := true
  let buffered := retainedSuffix bytes offset
  {
    decoder := {
      role, limits, allowRsv1, validateTextPayload, buffered,
      fragmentedMessage, fragmentTextUtf8?, partialTextUtf8?, partialTextBytes
    }
    frames
    error? := terminalError?
  }

/-- Consume an arbitrary transport chunk. Completed frames are returned in
wire order and an incomplete suffix is retained exactly for the next call.
The decoder advances a cursor through each combined buffer and copies that
suffix at most once, so a chunk containing many small frames is processed in
linear time. -/
def feed (decoder : Decoder) (chunk : ByteArray) : Except Error (Decoder × Array Frame) := do
  let result := decoder.feedBatch chunk
  match result.error? with
  | some error => throw error
  | none => pure (result.decoder, result.frames)

end Decoder

private def appendUInt16 (out : ByteArray) (length : Nat) : ByteArray :=
  (out.push (UInt8.ofNat (length / 256))).push (UInt8.ofNat length)

private def appendUInt64 (out : ByteArray) (length : Nat) : ByteArray :=
  (#[56, 48, 40, 32, 24, 16, 8, 0] : Array Nat).foldl
    (fun out shift => out.push (UInt8.ofNat (length >>> shift))) out

/-- Encode one frame. The caller supplies a fresh unpredictable key for every
client frame; a server frame must use `none`. -/
def encode (role : Role) (maskKey? : Option UInt32) (frame : Frame) : Except Error ByteArray := do
  if frame.opcode.control && (!frame.fin || frame.payload.size > 125) then
    throw (Error.invalidArgument "invalid WebSocket control frame")
  if frame.rsv1 && (frame.opcode.control || frame.opcode == .continuation) then
    throw (Error.invalidArgument "RSV1 is only valid on an initial data frame")
  if role.masksOutbound != maskKey?.isSome then
    throw (Error.invalidArgument "WebSocket outbound mask key does not match endpoint role")
  if frame.payload.size >= (1 <<< 63) then
    throw (Error.invalidArgument "WebSocket payload exceeds the 63-bit wire limit")
  let first := UInt8.ofNat
    ((if frame.fin then 0x80 else 0) + (if frame.rsv1 then 0x40 else 0) + frame.opcode.toNat)
  let maskBit := if maskKey?.isSome then 0x80 else 0
  let mut out := ByteArray.empty.push first
  if frame.payload.size <= 125 then
    out := out.push (UInt8.ofNat (maskBit + frame.payload.size))
  else if frame.payload.size <= 65535 then
    out := appendUInt16 (out.push (UInt8.ofNat (maskBit + 126))) frame.payload.size
  else
    out := appendUInt64 (out.push (UInt8.ofNat (maskBit + 127))) frame.payload.size
  match maskKey? with
  | none => pure (out.append frame.payload)
  | some key =>
      let maskedHeader := out
        |>.push (key >>> 24).toUInt8
        |>.push (key >>> 16).toUInt8
        |>.push (key >>> 8).toUInt8
        |>.push key.toUInt8
      pure (maskedHeader.append (applyMask key frame.payload))

end Ws.Frame
