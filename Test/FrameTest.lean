import Ws.Frame

open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectProtocol {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error error =>
      expect (error.kind == .protocol && error.closeCode? == some .protocolError)
        s!"{label}: wrong protocol error mapping"
  | .ok _ => throw (IO.userError s!"{label}: expected a protocol error")

def expectInvalidPayload (label : String) (error? : Option Ws.Error) : IO Unit :=
  match error? with
  | some error =>
      expect (error.kind == .invalidPayload && error.closeCode? == some .invalidPayload)
        s!"{label}: wrong invalid-payload mapping"
  | none => throw (IO.userError s!"{label}: expected an invalid-payload error")

def payloadOfSize (size : Nat) : ByteArray :=
  ByteArray.mk <| Array.ofFn (n := size) fun index => UInt8.ofNat (index * 37 + 11)

def expectSplitRoundTrip (role : Role) (key? : Option UInt32)
    (frame : Frame.Frame) : IO Unit := do
  let wire ← take "encode split frame" (Frame.encode role key? frame)
  for split in [0:wire.size + 1] do
    let receiver := role.peer
    let decoder := Frame.Decoder.new receiver
    let (decoder, first) ← take "decode split prefix"
      (decoder.feed (wire.extract 0 split))
    let (decoder, second) ← take "decode split suffix"
      (decoder.feed (wire.extract split wire.size))
    expect (first.append second == #[frame] && decoder.buffered.isEmpty)
      s!"frame roundtrip failed at split {split}"

def main : IO Unit := do
  let hello : Frame.Frame := { opcode := .text, payload := "Hello".toUTF8 }
  let clientWire ← take "RFC client frame" (Frame.encode .client (some 0x37fa213d) hello)
  expect (clientWire == ByteArray.mk #[
    0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
  ]) "RFC 6455 masked Hello vector differs"
  let (serverDecoder, decoded) ← take "RFC client decode"
    ((Frame.Decoder.new .server).feed clientWire)
  expect (decoded == #[hello] && serverDecoder.buffered.isEmpty)
    "RFC client frame did not decode"

  expectSplitRoundTrip .client (some 0x01020304) hello
  expectSplitRoundTrip .server none { opcode := .binary, payload := payloadOfSize 130 }
  expectSplitRoundTrip .client (some 0xaabbccdd) {
    fin := false, opcode := .binary, payload := payloadOfSize 7
  }

  for size in #[0, 1, 125, 126, 65535, 65536] do
    let frame : Frame.Frame := { opcode := .binary, payload := payloadOfSize size }
    let wire ← take "boundary encode" (Frame.encode .server none frame)
    let code := (wire[1]! &&& 0x7f).toNat
    let expectedCode := if size <= 125 then size else if size <= 65535 then 126 else 127
    expect (code == expectedCode) s!"wrong length code at boundary {size}"
    let (decoder, frames) ← take "boundary decode" ((Frame.Decoder.new .client).feed wire)
    expect (frames == #[frame] && decoder.buffered.isEmpty)
      s!"boundary frame {size} did not roundtrip"

  let oneWire ← take "coalesced one" (Frame.encode .server none hello)
  let ping : Frame.Frame := { opcode := .ping, payload := "?".toUTF8 }
  let twoWire ← take "coalesced two" (Frame.encode .server none ping)
  let (decoder, frames) ← take "coalesced decode"
    ((Frame.Decoder.new .client).feed (oneWire.append twoWire))
  expect (frames == #[hello, ping] && decoder.buffered.isEmpty)
    "coalesced frames were not decoded in order"

  let validThenInvalid := clientWire.append (ByteArray.mk #[0x83, 0x80])
  let prefixedError := (Frame.Decoder.new .server).feedBatch validThenInvalid
  expect (prefixedError.frames == #[hello])
    "a malformed later frame discarded a completed valid prefix"
  match prefixedError.error? with
  | some error =>
      expect (error.kind == .protocol && error.closeCode? == some .protocolError)
        "the malformed suffix returned the wrong terminal error"
  | none => throw (IO.userError "the malformed suffix was not rejected")

  let invalidText : Frame.Frame := {
    opcode := .text
    payload := ByteArray.mk #[0x61, 0xf0, 0x28, 0x8c, 0xbc, 0x62]
  }
  let invalidTextWire ← take "encode invalid split text"
    (Frame.encode .client (some 0x10203040) invalidText)
  let invalidTextPrefix := invalidTextWire.extract 0 9
  let invalidTextResult := (Frame.Decoder.new .server
    (validateTextPayload := true)).feedBatch invalidTextPrefix
  expect invalidTextResult.frames.isEmpty
    "an incomplete invalid text frame was emitted"
  expectInvalidPayload "incremental text payload" invalidTextResult.error?

  let textFragment : Frame.Frame := {
    fin := false, opcode := .text, payload := ByteArray.mk #[0xf0]
  }
  let invalidContinuation : Frame.Frame := {
    opcode := .continuation, payload := ByteArray.mk #[0x28, 0x8c, 0xbc]
  }
  let textFragmentWire ← take "encode split text fragment"
    (Frame.encode .client (some 0x50607080) textFragment)
  let continuationWire ← take "encode invalid continuation fragment"
    (Frame.encode .client (some 0x90a0b0c0) invalidContinuation)
  let firstFragmentResult := (Frame.Decoder.new .server
    (validateTextPayload := true)).feedBatch textFragmentWire
  expect (firstFragmentResult.error?.isNone && firstFragmentResult.frames.size == 1)
    "a valid partial UTF-8 sequence at a fragment boundary was rejected"
  let invalidContinuationResult := firstFragmentResult.decoder.feedBatch
    (continuationWire.extract 0 7)
  expect invalidContinuationResult.frames.isEmpty
    "an incomplete invalid continuation frame was emitted"
  expectInvalidPayload "incremental continuation payload" invalidContinuationResult.error?

  let closeWire ← take "terminal Close encode"
    (Frame.encode .server none { opcode := .close })
  let invalidAfterClose := closeWire.append (ByteArray.mk #[0x83, 0])
  let (terminalDecoder, terminalFrames) ← take "terminal Close decode"
    ((Frame.Decoder.new .client).feed invalidAfterClose)
  expect (terminalFrames.size == 1 && terminalFrames[0]!.opcode == .close &&
    terminalDecoder.buffered == ByteArray.mk #[0x83, 0])
    "bytes after Close preempted or escaped terminal frame handling"

  -- Exercise the retained-buffer path with the most adversarial legal chunking.
  -- This also guards against accidentally rescanning or copying the full
  -- incomplete payload on every byte.
  let bytewiseFrame : Frame.Frame := {
    opcode := .binary, payload := payloadOfSize (256 * 1024)
  }
  let bytewiseWire ← take "bytewise stress encode"
    (Frame.encode .server none bytewiseFrame)
  let mut bytewiseDecoder := Frame.Decoder.new .client
  let mut bytewiseFrames : Array Frame.Frame := #[]
  for index in [0:bytewiseWire.size] do
    let (next, produced) ← take "bytewise stress decode"
      (bytewiseDecoder.feed (bytewiseWire.extract index (index + 1)))
    bytewiseDecoder := next
    for frame in produced do
      bytewiseFrames := bytewiseFrames.push frame
  expect (bytewiseFrames == #[bytewiseFrame] && bytewiseDecoder.buffered.isEmpty)
    "bytewise frame stress roundtrip failed"

  expectProtocol "unmasked client frame"
    ((Frame.Decoder.new .server).feed (ByteArray.mk #[0x81, 0x00]))
  expectProtocol "masked server frame"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x81, 0x80, 0, 0, 0, 0]))
  expectProtocol "reserved opcode"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x83, 0]))
  expectProtocol "RSV2"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0xa1, 0]))
  expectProtocol "unnegotiated RSV1"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0xc1, 0]))
  expectProtocol "RSV1 continuation"
    ((Frame.Decoder.new .client (allowRsv1 := true)).feed (ByteArray.mk #[0xc0, 0]))
  let (_, compressed) ← take "negotiated RSV1"
    ((Frame.Decoder.new .client (allowRsv1 := true)).feed (ByteArray.mk #[0xc1, 0]))
  expect (compressed.size == 1 && compressed[0]!.rsv1)
    "negotiated RSV1 data frame was rejected"
  expectProtocol "fragmented ping"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x09, 0]))
  expectProtocol "oversized ping"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x89, 126, 0, 126]))
  expectProtocol "nonminimal 16-bit length"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x82, 126, 0, 125]))
  expectProtocol "nonminimal 64-bit length"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[
      0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    ]))
  expectProtocol "high 64-bit length bit"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[
      0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0
    ]))
  match (Frame.Decoder.new .client { maxFramePayloadBytes := 4 }).feed
      (ByteArray.mk #[0x82, 5]) with
  | .error error =>
      expect (error.kind == .messageTooBig && error.closeCode? == some .messageTooBig)
        s!"frame limit used the wrong close code: {repr error}"
  | .ok _ => throw (IO.userError "configured frame limit was not enforced from the header")

  match Frame.encode .server (some 1) hello with
  | .error error => expect (error.kind == .invalidArgument) "server mask error kind differs"
  | .ok _ => throw (IO.userError "server frame accepted a mask key")
  match Frame.encode .client none hello with
  | .error error => expect (error.kind == .invalidArgument) "client mask error kind differs"
  | .ok _ => throw (IO.userError "client frame omitted its mask key")
  expectProtocol "manual fragmented control"
    ((Frame.Decoder.new .client).feed (ByteArray.mk #[0x08, 0]))
  match Frame.encode .server none { fin := false, opcode := .close } with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "encoder accepted fragmented Close")

  IO.println "frame tests passed"
