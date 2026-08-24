module

public import Ws.Basic

public section

namespace Ws.Crypto.Sha1

private def rotateLeft (value count : UInt32) : UInt32 :=
  (value <<< count) ||| (value >>> (32 - count))

private def readWord (bytes : ByteArray) (offset : Nat) : UInt32 :=
  bytes[offset]!.toUInt32 <<< 24 |||
    bytes[offset + 1]!.toUInt32 <<< 16 |||
    bytes[offset + 2]!.toUInt32 <<< 8 |||
    bytes[offset + 3]!.toUInt32

private def appendWord (word : UInt32) (bytes : ByteArray) : ByteArray :=
  bytes
    |>.push (word >>> 24).toUInt8
    |>.push (word >>> 16).toUInt8
    |>.push (word >>> 8).toUInt8
    |>.push word.toUInt8

private def padded (input : ByteArray) : ByteArray := Id.run do
  let mut bytes := input.push 0x80
  while bytes.size % 64 != 56 do
    bytes := bytes.push 0
  let bitLength := UInt64.ofNat input.size * 8
  for shift in #[56, 48, 40, 32, 24, 16, 8, 0] do
    bytes := bytes.push (bitLength >>> shift).toUInt8
  return bytes

private structure Hash where
  h0 : UInt32 := 0x67452301
  h1 : UInt32 := 0xefcdab89
  h2 : UInt32 := 0x98badcfe
  h3 : UInt32 := 0x10325476
  h4 : UInt32 := 0xc3d2e1f0

private def processBlock (bytes : ByteArray) (offset : Nat) (hash : Hash) : Hash := Id.run do
  let mut words : Array UInt32 := Array.replicate 80 0
  for i in [0:16] do
    words := words.set! i (readWord bytes (offset + 4 * i))
  for i in [16:80] do
    let word := rotateLeft
      (words[i - 3]! ^^^ words[i - 8]! ^^^ words[i - 14]! ^^^ words[i - 16]!) 1
    words := words.set! i word

  let mut a := hash.h0
  let mut b := hash.h1
  let mut c := hash.h2
  let mut d := hash.h3
  let mut e := hash.h4
  for i in [0:80] do
    let (f, k) : UInt32 × UInt32 :=
      if i < 20 then
        ((b &&& c) ||| ((~~~b) &&& d), 0x5a827999)
      else if i < 40 then
        (b ^^^ c ^^^ d, 0x6ed9eba1)
      else if i < 60 then
        ((b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8f1bbcdc)
      else
        (b ^^^ c ^^^ d, 0xca62c1d6)
    let temporary := rotateLeft a 5 + f + e + k + words[i]!
    e := d
    d := c
    c := rotateLeft b 30
    b := a
    a := temporary
  return {
    h0 := hash.h0 + a,
    h1 := hash.h1 + b,
    h2 := hash.h2 + c,
    h3 := hash.h3 + d,
    h4 := hash.h4 + e
  }

/-- Pure SHA-1, used by the RFC 6455 opening handshake. -/
def digest (input : ByteArray) : ByteArray :=
  let bytes := padded input
  let hash := Id.run do
    let mut hash : Hash := {}
    for block in [0:bytes.size / 64] do
      hash := processBlock bytes (block * 64) hash
    return hash
  ByteArray.empty
    |> appendWord hash.h0
    |> appendWord hash.h1
    |> appendWord hash.h2
    |> appendWord hash.h3
    |> appendWord hash.h4

def digestString (input : String) : ByteArray :=
  digest input.toUTF8

end Ws.Crypto.Sha1
