module

public import Ws.Base64
public import Ws.Crypto.Sha1
public import Ws.Header

public section

namespace Ws.Handshake

def websocketGuid : String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def acceptForKey (key : String) : String :=
  Base64.encode (Crypto.Sha1.digestString (key ++ websocketGuid))

/-- Validate the canonical RFC 4648 spelling and required 16-byte decoded
length of `Sec-WebSocket-Key`. -/
def validateClientKey (key : String) : Except Error ByteArray := do
  let decoded ← match Base64.decodeCanonical key with
    | .ok bytes => pure bytes
    | .error _ => throw (Error.handshake "Sec-WebSocket-Key is not canonical Base64")
  unless decoded.size == 16 do
    throw (Error.handshake "Sec-WebSocket-Key must decode to exactly 16 bytes")
  pure decoded

/-- Validate the HTTP field representation required for a serialized Origin. -/
def validateOriginValue (origin : String) : Except Error Unit := do
  let header ← Header.ofString "origin" origin
  unless (Header.asciiString? header.value).isSome do
    throw (Error.invalidArgument "WebSocket Origin must contain ASCII")

/-- A WebSocket subprotocol token. Comparisons are deliberately case-sensitive. -/
structure Subprotocol where
  private mk ::
  value : String
  deriving Repr, DecidableEq

namespace Subprotocol

def parse (value : String) : Except Error Subprotocol := do
  unless Header.validNameBytes value.toUTF8 do
    throw (Error.handshake "invalid WebSocket subprotocol token")
  pure ⟨value⟩

end Subprotocol

structure ExtensionParam where
  /-- Normalized lowercase parameter name. -/
  name : String
  value? : Option String := none
  /-- Whether the value used quoted-string syntax on the wire. -/
  quoted : Bool := false
  deriving Inhabited, Repr, DecidableEq

structure Extension where
  /-- Normalized lowercase extension token. -/
  name : String
  parameters : Array ExtensionParam := #[]
  deriving Inhabited, Repr, DecidableEq

private def skipOws (bytes : ByteArray) (start : Nat) : Nat := Id.run do
  let mut index := start
  while index < bytes.size && Byte.isOws bytes[index]! do
    index := index + 1
  return index

private def parseTokenAt (bytes : ByteArray) (start : Nat) (description : String) :
    Except Error (String × Nat) := do
  let mut index := start
  while index < bytes.size && Byte.isToken bytes[index]! do
    index := index + 1
  if index == start then
    throw (Error.handshake s!"missing or invalid {description}")
  let tokenBytes := bytes.extract start index
  let some token := Header.asciiString? tokenBytes
    | throw (Error.handshake s!"non-ASCII {description}")
  pure (token, index)

private def parseQuotedToken (bytes : ByteArray) (start : Nat) :
    Except Error (String × Nat) := do
  if start >= bytes.size || bytes[start]! != 0x22 then
    throw (Error.handshake "missing WebSocket extension quoted string")
  let mut index := start + 1
  let mut decoded := ByteArray.empty
  let mut closed := false
  while index < bytes.size && !closed do
    let byte := bytes[index]!
    if byte == 0x22 then
      closed := true
      index := index + 1
    else if byte == 0x5c then
      index := index + 1
      if index >= bytes.size then
        throw (Error.handshake "unterminated WebSocket extension quoted escape")
      let escaped := bytes[index]!
      unless escaped == 0x09 || (0x20 <= escaped && escaped <= 0x7e) || 0x80 <= escaped do
        throw (Error.handshake "invalid WebSocket extension quoted escape")
      decoded := decoded.push escaped
      index := index + 1
    else
      unless byte == 0x09 || byte == 0x20 || byte == 0x21 ||
          (0x23 <= byte && byte <= 0x5b) || (0x5d <= byte && byte <= 0x7e) ||
          0x80 <= byte do
        throw (Error.handshake "invalid WebSocket extension quoted string")
      decoded := decoded.push byte
      index := index + 1
  unless closed do
    throw (Error.handshake "unterminated WebSocket extension quoted string")
  -- RFC 6455 further restricts the decoded quoted-string to token syntax.
  unless Header.validNameBytes decoded do
    throw (Error.handshake "quoted WebSocket extension value is not a token")
  let some value := Header.asciiString? decoded
    | throw (Error.handshake "non-ASCII WebSocket extension value")
  pure (value, index)

def parseExtensionItem (raw : ByteArray) : Except Error Extension := do
  let bytes := Header.trimOws raw
  let (name, afterName) ← parseTokenAt bytes 0 "WebSocket extension token"
  let mut index := skipOws bytes afterName
  let mut parameters : Array ExtensionParam := #[]
  while index < bytes.size do
    unless bytes[index]! == 0x3b do
      throw (Error.handshake "invalid WebSocket extension separator")
    index := skipOws bytes (index + 1)
    let (parameterName, afterParameterName) ←
      parseTokenAt bytes index "WebSocket extension parameter"
    index := skipOws bytes afterParameterName
    let mut value? : Option String := none
    let mut quoted := false
    if index < bytes.size && bytes[index]! == 0x3d then
      index := skipOws bytes (index + 1)
      if index < bytes.size && bytes[index]! == 0x22 then
        let (value, next) ← parseQuotedToken bytes index
        value? := some value
        quoted := true
        index := next
      else
        let (value, next) ← parseTokenAt bytes index "WebSocket extension value"
        value? := some value
        index := next
      index := skipOws bytes index
    parameters := parameters.push {
      name := parameterName.toLower, value?, quoted
    }
  pure { name := name.toLower, parameters }

def parseExtensions (headers : Headers) : Except Error (Array Extension) := do
  let rawValues := Headers.getAll headers "sec-websocket-extensions"
  let items ← Headers.commaItems headers "sec-websocket-extensions"
  if !rawValues.isEmpty && items.isEmpty then
    throw (Error.handshake "Sec-WebSocket-Extensions contains no extension")
  items.mapM parseExtensionItem

def parseSubprotocols (headers : Headers) : Except Error (Array Subprotocol) := do
  let rawValues := Headers.getAll headers "sec-websocket-protocol"
  let values ← Headers.tokenItems headers "sec-websocket-protocol"
  if !rawValues.isEmpty && values.isEmpty then
    throw (Error.handshake "Sec-WebSocket-Protocol contains no subprotocol")
  let mut protocols : Array Subprotocol := #[]
  let mut seen : Std.HashSet String := {}
  for value in values do
    if seen.contains value then
      throw (Error.handshake "duplicate WebSocket subprotocol token")
    seen := seen.insert value
    protocols := protocols.push (← Subprotocol.parse value)
  pure protocols

def selectedSubprotocol (headers : Headers) (offered : Array Subprotocol) :
    Except Error (Option Subprotocol) := do
  let selected ← parseSubprotocols headers
  match selected with
  | #[] => pure none
  | #[protocol] =>
      unless offered.any fun candidate => candidate == protocol do
        throw (Error.handshake "server selected a WebSocket subprotocol that was not offered")
      pure (some protocol)
  | _ => throw (Error.handshake "server selected more than one WebSocket subprotocol")

def validateNegotiatedExtensions (offered negotiated : Array Extension) : Except Error Unit := do
  for extension in negotiated do
    unless offered.any fun candidate => candidate.name == extension.name do
      throw (Error.handshake "server selected a WebSocket extension that was not offered")

private def appendQuoted (out : ByteArray) (value : String) : ByteArray := Id.run do
  let mut result := out.push 0x22
  for byte in value.toUTF8 do
    if byte == 0x22 || byte == 0x5c then
      result := result.push 0x5c
    result := result.push byte
  return result.push 0x22

def serializeExtensions (extensions : Array Extension) : Except Error String := do
  let mut out := ByteArray.empty
  for i in [0:extensions.size] do
    let extension := extensions[i]!
    unless Header.validNameBytes extension.name.toUTF8 do
      throw (Error.invalidArgument "invalid WebSocket extension token")
    if i > 0 then out := out.append ", ".toUTF8
    out := out.append extension.name.toUTF8
    for parameter in extension.parameters do
      unless Header.validNameBytes parameter.name.toUTF8 do
        throw (Error.invalidArgument "invalid WebSocket extension parameter")
      out := out.append "; ".toUTF8
      out := out.append parameter.name.toUTF8
      if let some value := parameter.value? then
        unless Header.validNameBytes value.toUTF8 do
          throw (Error.invalidArgument "invalid WebSocket extension value")
        out := out.push 0x3d
        if parameter.quoted then out := appendQuoted out value
        else out := out.append value.toUTF8
  let some value := String.fromUTF8? out
    | throw (Error.invalidArgument "WebSocket extension serialization was not UTF-8")
  pure value

def serializeSubprotocols (protocols : Array Subprotocol) : String :=
  String.intercalate ", " (protocols.toList.map (·.value))

end Ws.Handshake
