import Ws.PerMessageDeflate.Raw

open Ws.PerMessageDeflate.Raw

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error}")

def repeated (count : Nat) (value : String) : ByteArray := Id.run do
  let bytes := value.toUTF8
  let mut output := ByteArray.emptyWithCapacity (count * bytes.size)
  for _ in [0:count] do output := output.append bytes
  return output

def freshRoundTrip (message : ByteArray) (windowBits : UInt8 := 15) : IO Unit := do
  let compressor ← take "create compressor" (← create .compress windowBits)
  let inflater ← take "create inflater" (← create .decompress windowBits)
  let compressed ← take "compress" (← process compressor message (message.size + 1024).toUInt64)
  let restored ← take "decompress" (← process inflater compressed message.size.toUInt64)
  expect (restored == message) "fresh roundtrip differs"
  compressor.close
  inflater.close

def main : IO Unit := do
  freshRoundTrip ByteArray.empty
  freshRoundTrip "a".toUTF8
  freshRoundTrip (repeated 4096 "abcdefghabcdefgh") 9
  freshRoundTrip (repeated 4096 "abcdefghabcdefgh") 15

  -- RFC 7692 section 7.2.3 payload transformations, without WebSocket
  -- framing or the four-octet marker supplied virtually by Raw.process.
  let hello := "Hello".toUTF8
  let vectorInflater ← take "vector inflater" (← create .decompress 15)
  let oneBlock := ByteArray.mk #[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]
  let decodedOne ← take "one-block vector" (← process vectorInflater oneBlock 5 true)
  expect (decodedOne == hello) "one compressed block vector differs"
  let takeover := ByteArray.mk #[0xf2, 0x00, 0x11, 0x00, 0x00]
  let decodedTakeover ← take "takeover vector" (← process vectorInflater takeover 5)
  expect (decodedTakeover == hello) "context-takeover vector differs"
  let uncompressed := ByteArray.mk #[
    0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]
  let decodedUncompressed ← take "uncompressed-block vector"
    (← process vectorInflater uncompressed 5 true)
  expect (decodedUncompressed == hello) "uncompressed block vector differs"
  let finalBlock := ByteArray.mk #[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00]
  let decodedFinal ← take "BFINAL vector" (← process vectorInflater finalBlock 5 true)
  expect (decodedFinal == hello) "BFINAL vector differs"
  let decodedAfterFinal ← take "context takeover after BFINAL"
    (← process vectorInflater takeover 5)
  expect (decodedAfterFinal == hello)
    "BFINAL handling discarded the negotiated takeover dictionary"
  let twoBlocks := ByteArray.mk #[
    0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xca, 0xc9, 0xc9, 0x07, 0x00]
  let decodedTwo ← take "two-block vector" (← process vectorInflater twoBlocks 5 true)
  expect (decodedTwo == hello) "two-block vector differs"
  let emptyFragment ← take "empty-fragment vector"
    (← process vectorInflater (ByteArray.mk #[0x00]) 0 true)
  expect emptyFragment.isEmpty "empty-fragment vector produced data"
  vectorInflater.close

  let first := repeated 1024 "the first context dictionary "
  let second := repeated 1024 "the first context dictionary and a suffix "
  let compressor ← take "takeover compressor" (← create .compress 15)
  let inflater ← take "takeover inflater" (← create .decompress 15)
  let firstWire ← take "takeover first compress"
    (← process compressor first (first.size + 1024).toUInt64)
  let firstPlain ← take "takeover first inflate"
    (← process inflater firstWire first.size.toUInt64)
  expect (firstPlain == first) "first takeover message differs"
  let secondWire ← take "takeover second compress"
    (← process compressor second (second.size + 1024).toUInt64)
  let secondPlain ← take "takeover second inflate"
    (← process inflater secondWire second.size.toUInt64)
  expect (secondPlain == second) "second takeover message differs"
  expect (secondWire.size < firstWire.size + 128)
    "persistent compressor did not reuse its dictionary"

  -- A failed bounded write must not advance the compression dictionary.  The
  -- peer has only consumed `firstWire`, so retrying the rejected message must
  -- still decode against exactly that shared state.
  let retryMessage := repeated 257 "a distinct message after a rejected write "
  match ← process compressor retryMessage 0 with
  | .error .outputLimit => pure ()
  | _ => throw (IO.userError "bounded compression unexpectedly succeeded")
  let retryWire ← take "retry after bounded compression failure"
    (← process compressor retryMessage (retryMessage.size + 1024).toUInt64)
  let retryPlain ← take "inflate retry after bounded compression failure"
    (← process inflater retryWire retryMessage.size.toUInt64)
  expect (retryPlain == retryMessage)
    "compression failure advanced the context dictionary"

  -- Reset-before is transactional as well: failing the reset attempt cannot
  -- leave the context half-reset before a subsequent no-context message.
  match ← process compressor retryMessage 0 true with
  | .error .outputLimit => pure ()
  | _ => throw (IO.userError "bounded reset compression unexpectedly succeeded")
  let resetRetryWire ← take "retry after bounded reset compression failure"
    (← process compressor retryMessage (retryMessage.size + 1024).toUInt64 true)
  let resetRetryPlain ← take "inflate retry after bounded reset compression failure"
    (← process inflater resetRetryWire retryMessage.size.toUInt64 true)
  expect (resetRetryPlain == retryMessage)
    "failed reset compression changed the context state"

  let resetWire1 ← take "reset first compress"
    (← process compressor first (first.size + 1024).toUInt64 true)
  let resetPlain1 ← take "reset first inflate"
    (← process inflater resetWire1 first.size.toUInt64 true)
  let resetWire2 ← take "reset second compress"
    (← process compressor first (first.size + 1024).toUInt64 true)
  let resetPlain2 ← take "reset second inflate"
    (← process inflater resetWire2 first.size.toUInt64 true)
  expect (resetPlain1 == first && resetPlain2 == first)
    "reset roundtrip differs"
  expect (resetWire1 == resetWire2)
    "no-context-takeover output should be deterministic"

  let exact ← take "exact output limit"
    (← process inflater resetWire1 first.size.toUInt64 true)
  expect (exact == first) "exact decompression limit should succeed"
  match ← process inflater resetWire1 (first.size - 1).toUInt64 true with
  | .error .outputLimit => pure ()
  | _ => throw (IO.userError "decompression limit was not enforced")

  let corruptInflater ← take "corrupt inflater" (← create .decompress 15)
  match ← process corruptInflater (ByteArray.mk #[0xff, 0xff, 0xff, 0xff]) 4096 with
  | .error .corruptData => pure ()
  | _ => throw (IO.userError "corrupt compressed data was accepted")
  corruptInflater.close

  match ← create .compress 7 with
  | .error .invalidWindow => pure ()
  | _ => throw (IO.userError "window size 7 was accepted")
  match ← create .decompress 16 with
  | .error .invalidWindow => pure ()
  | _ => throw (IO.userError "window size 16 was accepted")
  match ← create .compress 8 with
  | .error .invalidWindow => pure ()
  | .error error =>
      throw (IO.userError s!"8-bit compressor returned the wrong error: {error}")
  | .ok context =>
      context.close
      throw (IO.userError "backend unexpectedly accepted an 8-bit compressor window")
  let eightBitInflater ← take "8-bit inflater" (← create .decompress 8)
  eightBitInflater.close

  compressor.close
  compressor.close
  inflater.close
  inflater.close
  match ← process compressor first 65536 with
  | .error .closed => pure ()
  | _ => throw (IO.userError "closed compressor accepted another message")
  match ← process inflater firstWire 65536 with
  | .error .closed => pure ()
  | _ => throw (IO.userError "closed inflater accepted another message")

  IO.println "permessage-deflate raw tests passed"
