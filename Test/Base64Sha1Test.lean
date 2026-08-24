import Ws.Base64
import Ws.Crypto.Sha1
import Ws.Handshake.Common

open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectError {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def main : IO Unit := do
  expect (Crypto.Sha1.digest ByteArray.empty == ByteArray.mk #[
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
  ]) "SHA-1 empty-input vector differs"
  expect (Crypto.Sha1.digestString "abc" == ByteArray.mk #[
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
    0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
  ]) "SHA-1 abc vector differs"

  for (plain, encoded) in #[
    (ByteArray.empty, ""), ("f".toUTF8, "Zg=="), ("fo".toUTF8, "Zm8="),
    ("foo".toUTF8, "Zm9v"), ("foobar".toUTF8, "Zm9vYmFy")
  ] do
    expect (Base64.encode plain == encoded) s!"Base64 encoding differs for {encoded}"
    expect ((← take "Base64 decode" (Base64.decodeCanonical encoded)) == plain)
      s!"Base64 roundtrip differs for {encoded}"

  expectError "Base64 whitespace" (Base64.decodeCanonical "Z g==")
  expectError "Base64 unpadded" (Base64.decodeCanonical "Zg")
  expectError "Base64 early padding" (Base64.decodeCanonical "Z===")
  expectError "Base64 nonzero one-byte pad bits" (Base64.decodeCanonical "Zh==")
  expectError "Base64 nonzero two-byte pad bits" (Base64.decodeCanonical "Zm9=")

  let key := "dGhlIHNhbXBsZSBub25jZQ=="
  expect ((← take "client key" (Handshake.validateClientKey key)).size == 16)
    "client key did not decode to 16 bytes"
  expect (Handshake.acceptForKey key == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    "RFC 6455 accept vector differs"
  expectError "short client key" (Handshake.validateClientKey "YWJjZA==")
  expectError "noncanonical client key"
    (Handshake.validateClientKey "dGhlIHNhbXBsZSBub25jZQ")

  IO.println "Base64 and SHA-1 tests passed"
