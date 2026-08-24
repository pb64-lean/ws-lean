module

public import Ws.Handshake.Common

public section

namespace Ws.PerMessageDeflate

private def extensionName : String := "permessage-deflate"

abbrev Extension := Handshake.Extension

/-- Parse every extension item across repeated HTTP field lines. -/
def parseHeaders (headers : Headers) : Except Error (Array Extension) := do
  Handshake.parseExtensions headers

def validWindowBits (bits : UInt8) : Bool :=
  8 <= bits && bits <= 15

private def parseWindowBits (name value : String) : Except Error UInt8 := do
  if value.length > 1 && value.startsWith "0" then
    throw (Error.handshake s!"{name} must not contain a leading zero")
  let some number := value.toNat?
    | throw (Error.handshake s!"{name} is not a decimal window size")
  if number < 8 || number > 15 then
    throw (Error.handshake s!"{name} must be between 8 and 15")
  pure (UInt8.ofNat number)

inductive ClientMaxWindowBits where
  | absent
  | any
  | atMost (bits : UInt8)
  deriving Inhabited, Repr, DecidableEq

/-- One syntactically and semantically valid client offer. -/
structure ClientOffer where
  serverNoContextTakeover : Bool := false
  clientNoContextTakeover : Bool := false
  serverMaxWindowBits? : Option UInt8 := none
  clientMaxWindowBits : ClientMaxWindowBits := .absent
  deriving Inhabited, Repr, DecidableEq

/-- The parameters selected for both directions.  `server*` always describes
the server's compressor and `client*` the client's compressor, independent of
which endpoint is reading the value. -/
structure Parameters where
  serverNoContextTakeover : Bool := false
  clientNoContextTakeover : Bool := false
  serverMaxWindowBits : UInt8 := 15
  clientMaxWindowBits : UInt8 := 15
  deriving Inhabited, Repr, DecidableEq

private structure Decoded where
  serverNoContextTakeover : Bool := false
  clientNoContextTakeover : Bool := false
  serverMaxWindowBits? : Option UInt8 := none
  clientMaxWindowBitsSeen : Bool := false
  clientMaxWindowBits? : Option UInt8 := none

private def decode (extension : Extension) (isResponse : Bool) : Except Error Decoded := do
  unless extension.name == extensionName do
    throw (Error.handshake s!"unexpected WebSocket extension {extension.name}")
  let mut decoded : Decoded := {}
  for parameter in extension.parameters do
    match parameter.name with
    | "server_no_context_takeover" =>
        if decoded.serverNoContextTakeover then
          throw (Error.handshake "duplicate server_no_context_takeover parameter")
        if parameter.value?.isSome then
          throw (Error.handshake "server_no_context_takeover must not have a value")
        decoded := { decoded with serverNoContextTakeover := true }
    | "client_no_context_takeover" =>
        if decoded.clientNoContextTakeover then
          throw (Error.handshake "duplicate client_no_context_takeover parameter")
        if parameter.value?.isSome then
          throw (Error.handshake "client_no_context_takeover must not have a value")
        decoded := { decoded with clientNoContextTakeover := true }
    | "server_max_window_bits" =>
        if decoded.serverMaxWindowBits?.isSome then
          throw (Error.handshake "duplicate server_max_window_bits parameter")
        let some value := parameter.value?
          | throw (Error.handshake "server_max_window_bits requires a value")
        decoded := { decoded with serverMaxWindowBits? := some (← parseWindowBits parameter.name value) }
    | "client_max_window_bits" =>
        if decoded.clientMaxWindowBitsSeen then
          throw (Error.handshake "duplicate client_max_window_bits parameter")
        let value? ← match parameter.value? with
          | none =>
              if isResponse then
                throw (Error.handshake "client_max_window_bits requires a response value")
              else
                pure none
          | some value => pure (some (← parseWindowBits parameter.name value))
        decoded := { decoded with
          clientMaxWindowBitsSeen := true, clientMaxWindowBits? := value? }
    | name =>
        throw (Error.handshake s!"unknown permessage-deflate parameter {name}")
  pure decoded

def ClientOffer.ofExtension (extension : Extension) : Except Error ClientOffer := do
  let decoded ← decode extension false
  pure {
    serverNoContextTakeover := decoded.serverNoContextTakeover
    clientNoContextTakeover := decoded.clientNoContextTakeover
    serverMaxWindowBits? := decoded.serverMaxWindowBits?
    clientMaxWindowBits :=
      if decoded.clientMaxWindowBitsSeen then
        match decoded.clientMaxWindowBits? with
        | none => .any
        | some bits => .atMost bits
      else
        .absent
  }

private def validateOffer (offer : ClientOffer) : Except Error Unit := do
  match offer.serverMaxWindowBits? with
  | some bits => unless validWindowBits bits do
      throw (Error.invalidArgument "server_max_window_bits must be between 8 and 15")
  | none => pure ()
  match offer.clientMaxWindowBits with
  | .atMost bits => unless validWindowBits bits do
      throw (Error.invalidArgument "client_max_window_bits must be between 8 and 15")
  | _ => pure ()

def ClientOffer.extensionValue (offer : ClientOffer) : Except Error String := do
  validateOffer offer
  let mut value := extensionName
  if offer.serverNoContextTakeover then
    value := value ++ "; server_no_context_takeover"
  if offer.clientNoContextTakeover then
    value := value ++ "; client_no_context_takeover"
  match offer.serverMaxWindowBits? with
  | some bits => value := value ++ "; server_max_window_bits=" ++ toString bits
  | none => pure ()
  match offer.clientMaxWindowBits with
  | .absent => pure ()
  | .any => value := value ++ "; client_max_window_bits"
  | .atMost bits => value := value ++ "; client_max_window_bits=" ++ toString bits
  pure value

/-- Server selection policy.  Window values are hard maxima, not preferences.
The local compressor is never negotiated below 9 because the raw-DEFLATE
backend cannot guarantee production of an 8-bit stream. -/
structure ServerConfig where
  enabled : Bool := false
  serverNoContextTakeover : Bool := false
  clientNoContextTakeover : Bool := false
  requireClientNoContextTakeover : Bool := false
  maxServerWindowBits : UInt8 := 15
  maxClientWindowBits : UInt8 := 15
  deriving Inhabited, Repr, DecidableEq

structure Selection where
  parameters : Parameters
  responseValue : String
  deriving Inhabited, Repr, DecidableEq

private def responseValue (parameters : Parameters) (offer : ClientOffer) : String := Id.run do
  let mut value := extensionName
  if parameters.serverNoContextTakeover then
    value := value ++ "; server_no_context_takeover"
  if parameters.clientNoContextTakeover then
    value := value ++ "; client_no_context_takeover"
  if offer.serverMaxWindowBits?.isSome || parameters.serverMaxWindowBits != 15 then
    value := value ++ "; server_max_window_bits=" ++ toString parameters.serverMaxWindowBits
  match offer.clientMaxWindowBits with
  | .absent => pure ()
  | _ => value := value ++ "; client_max_window_bits=" ++ toString parameters.clientMaxWindowBits
  return value

private def choose (config : ServerConfig) (offer : ClientOffer) : Option Selection := do
  let serverBits := match offer.serverMaxWindowBits? with
    | none => 15
    | some offered => min offered config.maxServerWindowBits
  let serverBits := min serverBits config.maxServerWindowBits
  if serverBits < 9 || serverBits > 15 then none else pure ()
  let clientBits := match offer.clientMaxWindowBits with
    | .absent => 15
    | .any => config.maxClientWindowBits
    | .atMost offered => min offered config.maxClientWindowBits
  if !validWindowBits clientBits then none else pure ()
  if offer.clientMaxWindowBits == .absent && config.maxClientWindowBits < 15 then none else pure ()
  let parameters : Parameters := {
    serverNoContextTakeover := config.serverNoContextTakeover || offer.serverNoContextTakeover
    clientNoContextTakeover := config.clientNoContextTakeover ||
      config.requireClientNoContextTakeover || offer.clientNoContextTakeover
    serverMaxWindowBits := serverBits
    clientMaxWindowBits := clientBits
  }
  pure { parameters, responseValue := responseValue parameters offer }

/-- Select the first compatible, valid permessage-deflate offer.  A malformed
instance is declined and later instances remain eligible, as extension offers
are alternatives. -/
def selectServer (config : ServerConfig) (extensions : Array Extension) :
    Except Error (Option Selection) := do
  if !config.enabled then pure none else
  unless validWindowBits config.maxServerWindowBits &&
      validWindowBits config.maxClientWindowBits do
    throw (Error.invalidArgument "server permessage-deflate window limit is outside 8..15")
  let mut selected : Option Selection := none
  for extension in extensions do
    if selected.isNone && extension.name == extensionName then
      match ClientOffer.ofExtension extension with
      | .error _ => pure ()
      | .ok offer => selected := choose config offer
  pure selected

/-- Validate the server's single extension response against the exact offer.
An empty response means compression was declined. -/
def validateClientResponse (offer : ClientOffer) (extensions : Array Extension) :
    Except Error (Option Parameters) := do
  validateOffer offer
  match extensions with
  | #[] => pure none
  | #[extension] =>
      let decoded ← decode extension true
      if offer.serverNoContextTakeover && !decoded.serverNoContextTakeover then
        throw (Error.handshake "server did not honor server_no_context_takeover")
      match decoded.serverMaxWindowBits?, offer.serverMaxWindowBits? with
      | some _, none => pure ()
      | some selected, some offered =>
          if selected > offered then
            throw (Error.handshake "server_max_window_bits exceeds the client offer")
      | none, some _ =>
          throw (Error.handshake "server omitted the offered server_max_window_bits parameter")
      | none, none => pure ()
      if decoded.clientMaxWindowBitsSeen then
        match offer.clientMaxWindowBits with
        | .absent =>
            throw (Error.handshake "server selected unoffered client_max_window_bits")
        | .any => pure ()
        | .atMost _ => pure ()
      else
        pure ()
      let selectedClientBits := decoded.clientMaxWindowBits?.getD 15
      let effectiveClientBits := match offer.clientMaxWindowBits with
        | .absent | .any => selectedClientBits
        -- A valued client offer is a hint when the response omits or loosens
        -- it. Retaining the smaller local window is a conservative policy.
        | .atMost offered => min offered selectedClientBits
      let parameters : Parameters := {
        serverNoContextTakeover := decoded.serverNoContextTakeover
        clientNoContextTakeover := decoded.clientNoContextTakeover ||
          -- This offer parameter is also a hint. Voluntarily continuing
          -- without context is always within the peer's response policy.
          offer.clientNoContextTakeover
        serverMaxWindowBits := decoded.serverMaxWindowBits?.getD 15
        clientMaxWindowBits := effectiveClientBits
      }
      -- The bundled compressor cannot guarantee an 8-bit stream.  Rejecting
      -- here is safer than silently emitting data outside the negotiated limit.
      if parameters.clientMaxWindowBits < 9 then
        throw (Error.handshake "backend cannot produce the selected client window size")
      pure (some parameters)
  | _ => throw (Error.handshake "server selected more than one WebSocket extension")

end Ws.PerMessageDeflate
