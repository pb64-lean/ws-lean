module

public import Ws.Basic

public section

namespace Ws.Base64

private def alphabet : Array Char :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toList.toArray

private def alphabetAt (index : Nat) : Char := alphabet[index]!

private def decodeChar? (char : Char) : Option Nat :=
  if 'A' <= char && char <= 'Z' then
    some (char.toNat - 'A'.toNat)
  else if 'a' <= char && char <= 'z' then
    some (26 + char.toNat - 'a'.toNat)
  else if '0' <= char && char <= '9' then
    some (52 + char.toNat - '0'.toNat)
  else if char == '+' then
    some 62
  else if char == '/' then
    some 63
  else
    none

private def encodeLoop (bytes : ByteArray) (index : Nat) : List Char :=
  if h0 : index < bytes.size then
    let a := bytes[index].toNat
    if h1 : index + 1 < bytes.size then
      let b := bytes[index + 1].toNat
      if h2 : index + 2 < bytes.size then
        let c := bytes[index + 2].toNat
        alphabetAt (a / 4) ::
          alphabetAt ((a % 4) * 16 + b / 16) ::
          alphabetAt ((b % 16) * 4 + c / 64) ::
          alphabetAt (c % 64) :: encodeLoop bytes (index + 3)
      else
        [alphabetAt (a / 4), alphabetAt ((a % 4) * 16 + b / 16),
          alphabetAt ((b % 16) * 4), '=']
    else
      [alphabetAt (a / 4), alphabetAt ((a % 4) * 16), '=', '=']
  else
    []
termination_by bytes.size - index

def encode (bytes : ByteArray) : String :=
  String.ofList (encodeLoop bytes 0)

private def decodedQuad (a b : Nat) (c? d? : Option Nat) : ByteArray :=
  let out := ByteArray.empty.push (UInt8.ofNat (a * 4 + b / 16))
  match c? with
  | none => out
  | some c =>
      let out := out.push (UInt8.ofNat ((b % 16) * 16 + c / 4))
      match d? with
      | none => out
      | some d => out.push (UInt8.ofNat ((c % 4) * 64 + d))

private def decodeLoop (chars : List Char) (out : ByteArray) : Except Error ByteArray :=
  match chars with
  | [] => pure out
  | a :: b :: c :: d :: rest => do
      let some va := decodeChar? a
        | throw (Error.invalidArgument "invalid Base64 character")
      let some vb := decodeChar? b
        | throw (Error.invalidArgument "invalid Base64 character")
      let c? ←
        if c == '=' then pure none
        else match decodeChar? c with
          | some value => pure (some value)
          | none => throw (Error.invalidArgument "invalid Base64 character")
      let d? ←
        if d == '=' then pure none
        else match decodeChar? d with
          | some value => pure (some value)
          | none => throw (Error.invalidArgument "invalid Base64 character")
      if c == '=' && d != '=' then
        throw (Error.invalidArgument "invalid Base64 padding")
      if (c == '=' || d == '=') && !rest.isEmpty then
        throw (Error.invalidArgument "Base64 padding appeared before the end")
      decodeLoop rest (out.append (decodedQuad va vb c? d?))
  | _ => throw (Error.invalidArgument "Base64 length is not a multiple of four")

/-- Decode RFC 4648 padded Base64 and reject noncanonical encodings, including
nonzero unused pad bits. Whitespace and unpadded spellings are not accepted. -/
def decodeCanonical (value : String) : Except Error ByteArray := do
  if value.toList.length % 4 != 0 then
    throw (Error.invalidArgument "Base64 length is not a multiple of four")
  let decoded ← decodeLoop value.toList ByteArray.empty
  unless encode decoded == value do
    throw (Error.invalidArgument "Base64 encoding is not canonical")
  pure decoded

end Ws.Base64
