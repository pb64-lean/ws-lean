module

public import Ws.Basic

public section

namespace Ws.Utf8

/-- Incremental RFC 3629 state. Bounds on the first continuation byte exclude
overlong forms, surrogates, and code points above U+10FFFF as early as possible. -/
structure State where
  remaining : Nat := 0
  codepoint : Nat := 0
  minimum : Nat := 0
  nextMinimum : Nat := 0x80
  nextMaximum : Nat := 0xbf
  deriving Inhabited, Repr, DecidableEq

def State.complete (state : State) : Bool := state.remaining == 0

private def beginSequence (byte : Nat) : Except Error State :=
  if byte <= 0x7f then
    pure {}
  else if 0xc2 <= byte && byte <= 0xdf then
    pure {
      remaining := 1, codepoint := byte &&& 0x1f, minimum := 0x80
    }
  else if byte == 0xe0 then
    pure {
      remaining := 2, codepoint := byte &&& 0x0f, minimum := 0x800,
      nextMinimum := 0xa0
    }
  else if (0xe1 <= byte && byte <= 0xec) || (0xee <= byte && byte <= 0xef) then
    pure {
      remaining := 2, codepoint := byte &&& 0x0f, minimum := 0x800
    }
  else if byte == 0xed then
    pure {
      remaining := 2, codepoint := byte &&& 0x0f, minimum := 0x800,
      nextMaximum := 0x9f
    }
  else if byte == 0xf0 then
    pure {
      remaining := 3, codepoint := byte &&& 0x07, minimum := 0x10000,
      nextMinimum := 0x90
    }
  else if 0xf1 <= byte && byte <= 0xf3 then
    pure {
      remaining := 3, codepoint := byte &&& 0x07, minimum := 0x10000
    }
  else if byte == 0xf4 then
    pure {
      remaining := 3, codepoint := byte &&& 0x07, minimum := 0x10000,
      nextMaximum := 0x8f
    }
  else
    throw (Error.invalidPayload "invalid UTF-8 leading byte")

def feedByte (state : State) (byte : UInt8) : Except Error State := do
  let value := byte.toNat
  if state.remaining == 0 then
    beginSequence value
  else
    unless state.nextMinimum <= value && value <= state.nextMaximum do
      throw (Error.invalidPayload "invalid UTF-8 continuation byte")
    let codepoint := (state.codepoint <<< 6) ||| (value &&& 0x3f)
    let remaining := state.remaining - 1
    if remaining == 0 then
      unless state.minimum <= codepoint && codepoint <= 0x10ffff &&
          !(0xd800 <= codepoint && codepoint <= 0xdfff) do
        throw (Error.invalidPayload "invalid UTF-8 scalar value")
      pure {}
    else
      pure {
        state with
        remaining, codepoint, nextMinimum := 0x80, nextMaximum := 0xbf
      }

def feed (state : State) (bytes : ByteArray) : Except Error State := do
  bytes.foldlM (init := state) feedByte

def finish (state : State) : Except Error Unit := do
  unless state.complete do
    throw (Error.invalidPayload "truncated UTF-8 sequence")

def validate (bytes : ByteArray) : Except Error Unit := do
  finish (← feed {} bytes)

def decode (bytes : ByteArray) : Except Error String := do
  validate bytes
  match String.fromUTF8? bytes with
  | some value => pure value
  | none => throw (Error.invalidPayload "invalid UTF-8")

end Ws.Utf8
