module

public import Ws.Basic

public section

namespace Ws

structure Header where
  private mk ::
  /-- Lowercase ASCII field name. -/
  name : String
  /-- Field value after removal of leading and trailing optional whitespace. -/
  value : ByteArray
  deriving Inhabited, DecidableEq

abbrev Headers := Array Header

namespace Header

def validNameBytes (bytes : ByteArray) : Bool :=
  !bytes.isEmpty && bytes.toList.all Byte.isToken

def validValueBytes (bytes : ByteArray) : Bool :=
  bytes.toList.all fun byte =>
    byte == 0x09 || (0x20 <= byte && byte <= 0x7e) || 0x80 <= byte

def trimOws (bytes : ByteArray) : ByteArray :=
  let rec firstNonOws (i : Nat) : Nat :=
    if h : i < bytes.size then
      if Byte.isOws bytes[i] then firstNonOws (i + 1) else i
    else
      bytes.size
  termination_by bytes.size - i
  let start := firstNonOws 0
  let rec lastNonOws (i : Nat) : Nat :=
    if i > start then
      if Byte.isOws bytes[i - 1]! then lastNonOws (i - 1) else i
    else
      start
  termination_by i
  bytes.extract start (lastNonOws bytes.size)

def asciiString? (bytes : ByteArray) : Option String :=
  if bytes.toList.all Byte.isAscii then String.fromUTF8? bytes else none

def ofBytes (name : String) (value : ByteArray) : Except Error Header := do
  let nameBytes := name.toUTF8
  unless validNameBytes nameBytes do
    throw (Error.handshake "invalid HTTP field name")
  unless validValueBytes value do
    throw (Error.handshake "invalid HTTP field value")
  pure { name := name.toLower, value := trimOws value }

def ofString (name value : String) : Except Error Header :=
  ofBytes name value.toUTF8

def valueString? (header : Header) : Option String :=
  asciiString? header.value

end Header

namespace Headers

def empty : Headers := #[]

def insertBytes (headers : Headers) (name : String) (value : ByteArray) :
    Except Error Headers := do
  pure (headers.push (← Header.ofBytes name value))

def insert (headers : Headers) (name value : String) : Except Error Headers := do
  pure (headers.push (← Header.ofString name value))

def getAll (headers : Headers) (name : String) : Array ByteArray :=
  let normalized := name.toLower
  headers.filterMap fun header =>
    if header.name == normalized then some header.value else none

def getAllStrings (headers : Headers) (name : String) : Except Error (Array String) := do
  (getAll headers name).mapM fun bytes =>
    match Header.asciiString? bytes with
    | some value => pure value
    | none => throw (Error.handshake s!"HTTP field {name} must contain ASCII")

def getUnique? (headers : Headers) (name : String) : Except Error (Option ByteArray) := do
  match getAll headers name with
  | #[] => pure none
  | #[value] => pure (some value)
  | _ => throw (Error.handshake s!"HTTP field {name} occurred more than once")

def requireUniqueAscii (headers : Headers) (name : String) : Except Error String := do
  let some bytes ← getUnique? headers name
    | throw (Error.handshake s!"required HTTP field {name} is missing")
  let some value := Header.asciiString? bytes
    | throw (Error.handshake s!"HTTP field {name} must contain ASCII")
  pure value

private structure CommaState where
  items : Array ByteArray := #[]
  current : ByteArray := ByteArray.empty
  quoted : Bool := false
  escaped : Bool := false

private def pushItem (state : CommaState) : Except Error CommaState := do
  let item := Header.trimOws state.current
  -- HTTP list syntax permits empty members.  They do not contribute to the
  -- element count and recipients ignore them.
  pure {
    state with
    items := if item.isEmpty then state.items else state.items.push item
    current := ByteArray.empty
  }

private def scanCommaValue (state : CommaState) (value : ByteArray) :
    Except Error CommaState := do
  let mut state := state
  for byte in value do
    if state.escaped then
      state := { state with current := state.current.push byte, escaped := false }
    else if state.quoted && byte == 0x5c then
      state := { state with current := state.current.push byte, escaped := true }
    else if byte == 0x22 then
      state := { state with current := state.current.push byte, quoted := !state.quoted }
    else if byte == 0x2c && !state.quoted then
      state ← pushItem state
    else
      state := { state with current := state.current.push byte }
  pure state

/-- Combine repeated list-valued field lines and split commas outside quoted
strings. Empty elements are ignored as required by HTTP list syntax; dangling
escapes and unterminated quotes are rejected. -/
def commaItems (headers : Headers) (name : String) : Except Error (Array ByteArray) := do
  let values := getAll headers name
  if values.isEmpty then
    pure #[]
  else
    let mut state : CommaState := {}
    for i in [0:values.size] do
      if i > 0 then
        if state.quoted || state.escaped then
          throw (Error.handshake s!"HTTP field {name} has an unterminated quoted string")
        state ← pushItem state
      state ← scanCommaValue state values[i]!
    if state.quoted || state.escaped then
      throw (Error.handshake s!"HTTP field {name} has an unterminated quoted string")
    state ← pushItem state
    pure state.items

def tokenItems (headers : Headers) (name : String) : Except Error (Array String) := do
  (← commaItems headers name).mapM fun item => do
    unless Header.validNameBytes item do
      throw (Error.handshake s!"HTTP field {name} contains an invalid token")
    let some token := Header.asciiString? item
      | throw (Error.handshake s!"HTTP field {name} contains non-ASCII")
    pure token

private def asciiEqualCiBytes (left right : ByteArray) : Bool :=
  left.size == right.size && Id.run do
    for i in [0:left.size] do
      if Byte.asciiLower left[i]! != Byte.asciiLower right[i]! then
        return false
    return true

def containsTokenCi (headers : Headers) (name token : String) : Except Error Bool := do
  let target := token.toUTF8
  unless Header.validNameBytes target do
    throw (Error.invalidArgument "HTTP token query is invalid")
  let items ← commaItems headers name
  for item in items do
    unless Header.validNameBytes item do
      throw (Error.handshake s!"HTTP field {name} contains an invalid token")
  pure (items.any fun item => asciiEqualCiBytes item target)

def serializedSize (headers : Headers) : Nat :=
  headers.foldl (fun total h => total + h.name.utf8ByteSize + 2 + h.value.size + 2) 0

def serialize (headers : Headers) : Except Error ByteArray := do
  let mut out := ByteArray.emptyWithCapacity (serializedSize headers)
  for header in headers do
    let checked ← Header.ofBytes header.name header.value
    out := out.append checked.name.toUTF8
    out := out.append ": ".toUTF8
    out := out.append checked.value
    out := out.append "\r\n".toUTF8
  pure out

end Headers

end Ws
