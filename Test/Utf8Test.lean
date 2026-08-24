import Ws.Utf8

open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectInvalid (label : String) (bytes : ByteArray) : IO Unit :=
  match Utf8.validate bytes with
  | .error error =>
      expect (error.kind == .invalidPayload && error.closeCode? == some .invalidPayload)
        s!"{label}: wrong error mapping"
  | .ok _ => throw (IO.userError s!"{label}: invalid UTF-8 was accepted")

def main : IO Unit := do
  let valid : Array ByteArray := #[
    ByteArray.empty,
    ByteArray.mk #[0x00, 0x41, 0x7f],
    ByteArray.mk #[0xc2, 0x80],
    ByteArray.mk #[0xdf, 0xbf],
    ByteArray.mk #[0xe0, 0xa0, 0x80],
    ByteArray.mk #[0xed, 0x9f, 0xbf],
    ByteArray.mk #[0xee, 0x80, 0x80],
    ByteArray.mk #[0xf0, 0x90, 0x80, 0x80],
    ByteArray.mk #[0xf4, 0x8f, 0xbf, 0xbf],
    "Hello, 世界 — 😀".toUTF8
  ]
  for bytes in valid do
    take "valid UTF-8" (Utf8.validate bytes)
    for split in [0:bytes.size + 1] do
      let state ← take "UTF-8 prefix" (Utf8.feed {} (bytes.extract 0 split))
      let state ← take "UTF-8 suffix" (Utf8.feed state (bytes.extract split bytes.size))
      take "UTF-8 finish" (Utf8.finish state)

  for (label, bytes) in #[
    ("lone continuation", ByteArray.mk #[0x80]),
    ("C0 overlong", ByteArray.mk #[0xc0, 0x80]),
    ("C1 overlong", ByteArray.mk #[0xc1, 0xbf]),
    ("E0 overlong", ByteArray.mk #[0xe0, 0x9f, 0xbf]),
    ("surrogate low edge", ByteArray.mk #[0xed, 0xa0, 0x80]),
    ("surrogate high edge", ByteArray.mk #[0xed, 0xbf, 0xbf]),
    ("F0 overlong", ByteArray.mk #[0xf0, 0x8f, 0xbf, 0xbf]),
    ("above Unicode maximum", ByteArray.mk #[0xf4, 0x90, 0x80, 0x80]),
    ("invalid leading F5", ByteArray.mk #[0xf5, 0x80, 0x80, 0x80]),
    ("invalid continuation ASCII", ByteArray.mk #[0xe2, 0x28, 0xa1]),
    ("truncated two-byte", ByteArray.mk #[0xc2]),
    ("truncated three-byte", ByteArray.mk #[0xe2, 0x82]),
    ("truncated four-byte", ByteArray.mk #[0xf0, 0x90, 0x80])
  ] do
    expectInvalid label bytes

  let incomplete ← take "incomplete incremental prefix"
    (Utf8.feed {} (ByteArray.mk #[0xe2, 0x82]))
  expect (!incomplete.complete) "incomplete UTF-8 state reported complete"
  match Utf8.finish incomplete with
  | .error error =>
      expect (error.closeCode? == some .invalidPayload)
        "truncated incremental UTF-8 used the wrong close code"
  | .ok _ => throw (IO.userError "truncated incremental UTF-8 was accepted")

  IO.println "UTF-8 tests passed"
