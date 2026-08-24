import Ws.Message

open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectCloseCode {α} (label : String) (code : CloseCode)
    (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error error =>
      expect (error.closeCode? == some code) s!"{label}: wrong close-code mapping"
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def main : IO Unit := do
  let text : Frame.Frame := { opcode := .text, payload := "hello".toUTF8 }
  let (decoder, events) ← take "unfragmented text"
    ((Message.Decoder.new .client).feed text)
  expect (events == #[.message { kind := .text, data := "hello".toUTF8 }])
    "unfragmented text event differs"
  expect decoder.fragment?.isNone "unfragmented text left fragment state"

  let first : Frame.Frame := {
    fin := false, opcode := .text, payload := ByteArray.mk #[0xe2]
  }
  let continuation : Frame.Frame := {
    opcode := .continuation, payload := ByteArray.mk #[0x82, 0xac]
  }
  let ping : Frame.Frame := { opcode := .ping, payload := "p".toUTF8 }
  let (fragmented, initialEvents) ← take "fragment start"
    ((Message.Decoder.new .client).feed first)
  expect initialEvents.isEmpty "fragment start emitted a message"
  let (fragmented, pingEvents) ← take "interleaved ping" (fragmented.feed ping)
  expect (pingEvents == #[.ping "p".toUTF8]) "interleaved ping event differs"
  let (fragmented, finalEvents) ← take "fragment finish" (fragmented.feed continuation)
  expect (finalEvents == #[.message {
    kind := .text, data := ByteArray.mk #[0xe2, 0x82, 0xac]
  }]) "fragmented UTF-8 message differs"
  expect fragmented.fragment?.isNone "fragment completion retained state"

  let badStart : Frame.Frame := {
    fin := false, opcode := .text, payload := ByteArray.mk #[0xe2]
  }
  let badEnd : Frame.Frame := {
    opcode := .continuation, payload := ByteArray.mk #[0x28]
  }
  let (badDecoder, _) ← take "bad UTF-8 start"
    ((Message.Decoder.new .client).feed badStart)
  expectCloseCode "bad fragmented UTF-8" .invalidPayload (badDecoder.feed badEnd)
  expectCloseCode "bad unfragmented UTF-8" .invalidPayload
    ((Message.Decoder.new .client).feed {
      opcode := .text, payload := ByteArray.mk #[0xc0, 0x80]
    })

  let (openFragment, _) ← take "open fragment"
    ((Message.Decoder.new .client).feed { fin := false, opcode := .binary })
  expectCloseCode "new data during fragment" .protocolError
    (openFragment.feed { opcode := .text })
  expectCloseCode "unexpected continuation" .protocolError
    ((Message.Decoder.new .client).feed { opcode := .continuation })

  let limited := Message.Decoder.new .client { maxMessagePayloadBytes := 2 }
  let (limited, _) ← take "limited start"
    (limited.feed { fin := false, opcode := .binary, payload := ByteArray.mk #[1, 2] })
  expectCloseCode "message byte limit" .messageTooBig
    (limited.feed { opcode := .continuation, payload := ByteArray.mk #[3] })
  let fragmentLimited := Message.Decoder.new .client { maxFragmentsPerMessage := 1 }
  let (fragmentLimited, _) ← take "fragment-limited start"
    (fragmentLimited.feed { fin := false, opcode := .binary })
  expectCloseCode "fragment count limit" .messageTooBig
    (fragmentLimited.feed { opcode := .continuation })

  -- Reassembly retains fragments and flattens once. At the default fragment
  -- limit this test would amplify into gigabytes of copying if every
  -- continuation appended to the accumulated message.
  let stressChunk := ByteArray.mk (Array.replicate 1024 0x5a)
  let mut stressDecoder := Message.Decoder.new .client
  let (started, _) ← take "fragment stress start" (stressDecoder.feed {
    fin := false, opcode := .binary, payload := stressChunk
  })
  stressDecoder := started
  for _ in [1:4095] do
    let (next, events) ← take "fragment stress continuation"
      (stressDecoder.feed {
        fin := false, opcode := .continuation, payload := stressChunk
      })
    expect events.isEmpty "nonterminal stress fragment emitted an event"
    stressDecoder := next
  let (_, stressEvents) ← take "fragment stress finish" (stressDecoder.feed {
    opcode := .continuation, payload := stressChunk
  })
  match stressEvents with
  | #[.message message] =>
      expect (message.kind == .binary && message.data.size == 4096 * 1024 &&
        message.data[0]! == 0x5a && message.data[message.data.size - 1]! == 0x5a)
        "fragment stress message differs"
  | _ => throw (IO.userError "fragment stress did not emit exactly one message")

  let (_, compressed) ← take "compressed text defers UTF-8"
    ((Message.Decoder.new .client).feed {
      rsv1 := true, opcode := .text, payload := ByteArray.mk #[0xff]
    })
  expect (compressed == #[.message {
    kind := .text, data := ByteArray.mk #[0xff], compressed := true
  }]) "compressed text was not marked or was prematurely UTF-8 validated"
  expectCloseCode "RSV1 control" .protocolError
    ((Message.Decoder.new .client).feed { rsv1 := true, opcode := .ping })

  let closePayload := ByteArray.mk #[0x03, 0xe8, 0x62, 0x79, 0x65]
  let (closed, closeEvents) ← take "valid close"
    ((Message.Decoder.new .client).feed { opcode := .close, payload := closePayload })
  match closeEvents with
  | #[.close close] =>
      expect (close.code?.map (·.value) == some 1000 && close.reason == "bye" &&
        close.reasonBytes == "bye".toUTF8) "parsed close value differs"
  | _ => throw (IO.userError "valid close did not emit one close event")
  expect closed.receivedClose "close state was not retained"
  let (closed, latePing) ← take "Ping after Close" (closed.feed ping)
  expect latePing.isEmpty "Ping after Close should be ignored"
  let latePong : Frame.Frame := { opcode := .pong, payload := "p".toUTF8 }
  let (closed, latePongEvents) ← take "Pong after Close" (closed.feed latePong)
  expect (latePongEvents == #[.pong "p".toUTF8])
    "an outstanding Pong after Close was not accepted"
  let (closed, duplicateClose) ← take "duplicate Close" (closed.feed {
    opcode := .close, payload := closePayload
  })
  expect duplicateClose.isEmpty "duplicate Close should be ignored"
  expectCloseCode "data frame after close" .protocolError
    (closed.feed { opcode := .binary })

  expectCloseCode "one-byte close" .protocolError
    ((Message.Decoder.new .client).feed {
      opcode := .close, payload := ByteArray.mk #[0x03]
    })
  expectCloseCode "reserved close code" .protocolError
    ((Message.Decoder.new .client).feed {
      opcode := .close, payload := ByteArray.mk #[0x03, 0xed]
    })
  for invalid in #[999, 1004, 1005, 1006, 1015, 2999, 5000, 65535] do
    expect (CloseCode.ofWire? invalid).isNone
      s!"reserved or out-of-range close status {invalid} was accepted"
  for valid in #[1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011,
      1012, 1013, 1014, 3000, 3999, 4000, 4999] do
    expect (CloseCode.ofWire? valid).isSome
      s!"registered or application close status {valid} was rejected"
  expectCloseCode "invalid close reason UTF-8" .invalidPayload
    ((Message.Decoder.new .client).feed {
      opcode := .close, payload := ByteArray.mk #[0x03, 0xe8, 0xc0, 0x80]
    })

  let mandatory := ByteArray.mk #[0x03, 0xf2]
  expectCloseCode "server-originated 1010" .protocolError
    ((Message.Decoder.new .client).feed { opcode := .close, payload := mandatory })
  let (_, clientMandatory) ← take "client-originated 1010"
    ((Message.Decoder.new .server).feed { opcode := .close, payload := mandatory })
  expect (clientMandatory.size == 1) "client-originated 1010 was rejected"

  let outbound ← take "client close create"
    (Message.Close.create .client (some .mandatoryExtension) "required")
  let outboundPayload ← take "client close payload" (outbound.payload .client)
  expect (outboundPayload.extract 0 2 == mandatory)
    "outbound client 1010 payload differs"
  match Message.Close.create .server (some .mandatoryExtension) "required" with
  | .error error =>
      expect (error.kind == .invalidArgument)
        "server 1010 construction returned the wrong error"
  | .ok _ => throw (IO.userError "server constructed forbidden 1010 close")
  match Message.Close.create .client none "reason" with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError "close reason without a status was accepted")

  IO.println "message tests passed"
