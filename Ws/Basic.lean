module

public import Std

public section

namespace Ws

/-- The endpoint role fixes the masking direction for every frame. -/
inductive Role where
  | client
  | server
  deriving Inhabited, Repr, DecidableEq

namespace Role

def peer : Role -> Role
  | .client => .server
  | .server => .client

def masksOutbound : Role -> Bool
  | .client => true
  | .server => false

def expectsMaskedInbound : Role -> Bool
  | .client => false
  | .server => true

end Role

/-- A WebSocket close status code. Construction through `ofWire` checks that
the value is one that may occur in a Close frame. -/
structure CloseCode where
  private mk ::
  value : Nat
  deriving Repr, DecidableEq

namespace CloseCode

def normalClosure : CloseCode := ⟨1000⟩
def goingAway : CloseCode := ⟨1001⟩
def protocolError : CloseCode := ⟨1002⟩
def unsupportedData : CloseCode := ⟨1003⟩
def invalidPayload : CloseCode := ⟨1007⟩
def policyViolation : CloseCode := ⟨1008⟩
def messageTooBig : CloseCode := ⟨1009⟩
def mandatoryExtension : CloseCode := ⟨1010⟩
def internalError : CloseCode := ⟨1011⟩
def serviceRestart : CloseCode := ⟨1012⟩
def tryAgainLater : CloseCode := ⟨1013⟩
def badGateway : CloseCode := ⟨1014⟩

/-- Codes currently valid on the wire. Values in 3000--4999 are available
for registered libraries, frameworks, and private applications. -/
def isValidWireValue (value : Nat) : Bool :=
  ((1000 <= value && value <= 1014) &&
      value != 1004 && value != 1005 && value != 1006) ||
    (3000 <= value && value <= 4999)

def ofWire? (value : Nat) : Option CloseCode :=
  if isValidWireValue value then some ⟨value⟩ else none

/-- A server cannot originate 1010; that status is reserved for a client
reporting extensions missing from the server handshake. -/
def maySend (role : Role) (code : CloseCode) : Bool :=
  isValidWireValue code.value && !(role == .server && code.value == 1010)

end CloseCode

instance : Inhabited CloseCode := ⟨CloseCode.normalClosure⟩

inductive ErrorKind where
  | invalidArgument
  | handshake
  | protocol
  | invalidPayload
  | messageTooBig
  | policy
  deriving Inhabited, Repr, DecidableEq

/-- Pure protocol failures. `closeCode?` is present only after a WebSocket
connection is open and the failure has an RFC 6455 Close-code mapping. -/
structure Error where
  kind : ErrorKind
  message : String
  closeCode? : Option CloseCode := none
  deriving Inhabited, Repr, DecidableEq

namespace Error

def invalidArgument (message : String) : Error :=
  { kind := .invalidArgument, message }

def handshake (message : String) : Error :=
  { kind := .handshake, message }

def policy (message : String) : Error :=
  { kind := .policy, message }

def protocol (message : String) : Error :=
  { kind := .protocol, message, closeCode? := some .protocolError }

def invalidPayload (message : String) : Error :=
  { kind := .invalidPayload, message, closeCode? := some .invalidPayload }

def messageTooBig (message : String) : Error :=
  { kind := .messageTooBig, message, closeCode? := some .messageTooBig }

end Error

/-- All limits are finite and are checked before allocating storage based on
peer-controlled lengths. -/
structure Limits where
  maxHandshakeBytes : Nat := 65536
  maxStartLineBytes : Nat := 8192
  maxHeaderCount : Nat := 100
  maxHeaderNameBytes : Nat := 256
  maxHeaderValueBytes : Nat := 8192
  maxLeadingEmptyLines : Nat := 2
  maxFramePayloadBytes : Nat := 16 * 1024 * 1024
  maxMessagePayloadBytes : Nat := 16 * 1024 * 1024
  maxFragmentsPerMessage : Nat := 4096
  deriving Inhabited, Repr, DecidableEq

namespace Byte

def isAscii (byte : UInt8) : Bool := byte < 0x80

def isDigit (byte : UInt8) : Bool := 0x30 <= byte && byte <= 0x39

def isHexDigit (byte : UInt8) : Bool :=
  isDigit byte || (0x41 <= byte && byte <= 0x46) ||
    (0x61 <= byte && byte <= 0x66)

def asciiLower (byte : UInt8) : UInt8 :=
  if 0x41 <= byte && byte <= 0x5a then byte + 0x20 else byte

/-- RFC 9110 `tchar`. -/
def isToken (byte : UInt8) : Bool :=
  (0x30 <= byte && byte <= 0x39) ||
  (0x41 <= byte && byte <= 0x5a) ||
  (0x61 <= byte && byte <= 0x7a) ||
  byte == 0x21 || byte == 0x23 || byte == 0x24 || byte == 0x25 ||
  byte == 0x26 || byte == 0x27 || byte == 0x2a || byte == 0x2b ||
  byte == 0x2d || byte == 0x2e || byte == 0x5e || byte == 0x5f ||
  byte == 0x60 || byte == 0x7c || byte == 0x7e

def isVisibleAscii (byte : UInt8) : Bool := 0x21 <= byte && byte <= 0x7e

def isOws (byte : UInt8) : Bool := byte == 0x20 || byte == 0x09

end Byte

end Ws
