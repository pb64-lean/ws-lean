module

public import Http2.ExtendedConnect
public import Ws.Endpoint
public import Ws.Handshake.Common

public section

namespace Ws.Http2.Handshake

abbrev Request := Http2.ExtendedConnect.Request
abbrev Response := Http2.ExtendedConnect.Response

private def statusError (status : Http2.Error) : Error :=
  Error.handshake status.message

private def addHandshakeBytes (limit total amount : Nat) : Except Error Nat := do
  if amount > limit || total > limit - amount then
    throw (Error.handshake "HTTP/2 WebSocket handshake exceeds the configured byte limit")
  pure (total + amount)

private def fieldListEntrySize (name value : String) : Nat :=
  name.utf8ByteSize + value.utf8ByteSize + 32

private def headerListEntrySize (header : Http2.Header) : Nat :=
  (Http2.Header.nameOctets header).size +
    (Http2.Header.valueOctets header).size + 32

private def validateMetadataLimits (metadata : Http2.Headers) (limits : Limits)
    (initialBytes : Nat) : Except Error Unit := do
  if metadata.size > limits.maxHeaderCount then
    throw (Error.handshake "HTTP/2 WebSocket handshake exceeds the configured field-count limit")
  let mut total ← addHandshakeBytes limits.maxHandshakeBytes 0 initialBytes
  for header in metadata do
    if (Http2.Header.nameOctets header).size > limits.maxHeaderNameBytes then
      throw (Error.handshake "HTTP/2 field name exceeds the configured limit")
    if (Http2.Header.valueOctets header).size > limits.maxHeaderValueBytes then
      throw (Error.handshake "HTTP/2 field value exceeds the configured limit")
    total ← addHandshakeBytes limits.maxHandshakeBytes total (headerListEntrySize header)

private def validateRequestLimits (request : Http2.ExtendedConnect.Request)
    (limits : Limits) : Except Error Unit := do
  let startLineBytes := "CONNECT".utf8ByteSize + request.protocol.utf8ByteSize +
    request.scheme.utf8ByteSize + request.authority.utf8ByteSize + request.path.utf8ByteSize
  if startLineBytes > limits.maxStartLineBytes then
    throw (Error.handshake "HTTP/2 WebSocket request pseudo-fields exceed the configured limit")
  let pseudoBytes := fieldListEntrySize ":method" "CONNECT" +
    fieldListEntrySize ":protocol" request.protocol +
    fieldListEntrySize ":scheme" request.scheme +
    fieldListEntrySize ":authority" request.authority +
    fieldListEntrySize ":path" request.path
  validateMetadataLimits request.headers limits pseudoBytes

private def validateResponseLimits (response : Http2.ExtendedConnect.Response)
    (limits : Limits) : Except Error Unit :=
  validateMetadataLimits response.headers limits
    (fieldListEntrySize ":status" (toString response.status))

private def toWsHeaders (metadata : Http2.Headers) : Except Error Headers := do
  let mut headers : Headers := #[]
  for header in metadata do
    let some name := String.fromUTF8? (Http2.Header.nameOctets header)
      | throw (Error.handshake "HTTP/2 field name must contain ASCII")
    match Header.ofBytes name (Http2.Header.valueOctets header) with
    | .ok value => headers := headers.push value
    | .error error => throw error
  pure headers

private def toMetadata (headers : Headers) : Except Error Http2.Headers := do
  let mut metadata := Http2.Headers.empty
  for header in headers do
    let checked ← Header.ofBytes header.name header.value
    let (value, valueOctets?) := Http2.Header.decodeWireString checked.value
    metadata := metadata.push { name := checked.name, value, valueOctets? }
  pure metadata

private def protectedRequestName (name : String) : Bool :=
  name == "connection" || name == "upgrade" || name == "host" ||
    name == "content-length" || name == "transfer-encoding" ||
    name == "sec-websocket-key" || name == "sec-websocket-accept" ||
    name == "sec-websocket-version" || name == "sec-websocket-protocol" ||
    name == "sec-websocket-extensions" || name == "origin"

private def protectedResponseName (name : String) : Bool :=
  name == "connection" || name == "upgrade" || name == "host" || name == "origin" ||
    name == "content-length" ||
    name == "transfer-encoding" || name == "sec-websocket-key" ||
    name == "sec-websocket-version" || name == "sec-websocket-accept" ||
    name == "sec-websocket-protocol" ||
    name == "sec-websocket-extensions"

private def validateExtras (headers : Headers) (isProtected : String → Bool) :
    Except Error Unit := do
  for header in headers do
    let checked ← Header.ofBytes header.name header.value
    if isProtected checked.name then
      throw (Error.invalidArgument s!"extra HTTP field {checked.name} is managed by ws-lean")

private def validateProtocols (protocols : Array Ws.Handshake.Subprotocol) :
    Except Error Unit := do
  let mut seen : Std.HashSet String := {}
  for protocol in protocols do
    if seen.contains protocol.value then
      throw (Error.invalidArgument "duplicate WebSocket subprotocol offer")
    seen := seen.insert protocol.value

structure ClientOffer where
  endpoint : Endpoint
  subprotocols : Array Ws.Handshake.Subprotocol := #[]
  extensions : Array Ws.Handshake.Extension := #[]
  origin? : Option String := none
  extraHeaders : Headers := #[]

namespace ClientOffer

def create (endpoint : Endpoint)
    (subprotocols : Array Ws.Handshake.Subprotocol := #[])
    (extensions : Array Ws.Handshake.Extension := #[])
    (origin? : Option String := none) (extraHeaders : Headers := #[]) :
    Except Error ClientOffer := do
  validateProtocols subprotocols
  validateExtras extraHeaders protectedRequestName
  if let some origin := origin? then Ws.Handshake.validateOriginValue origin
  pure { endpoint, subprotocols, extensions, origin?, extraHeaders }

end ClientOffer

structure ServerRequest where
  scheme : String
  authority : String
  target : String
  origin? : Option String
  subprotocols : Array Ws.Handshake.Subprotocol
  extensions : Array Ws.Handshake.Extension
  headers : Headers

structure ServerAccept where
  subprotocol? : Option Ws.Handshake.Subprotocol := none
  extensions : Array Ws.Handshake.Extension := #[]
  extraHeaders : Headers := #[]

structure ClientAccepted where
  subprotocol? : Option Ws.Handshake.Subprotocol
  extensions : Array Ws.Handshake.Extension
  headers : Headers

def buildClientRequest (offer : ClientOffer) : Except Error Request := do
  validateProtocols offer.subprotocols
  validateExtras offer.extraHeaders protectedRequestName
  if let some origin := offer.origin? then Ws.Handshake.validateOriginValue origin
  let mut headers := Http2.Headers.empty.insert "sec-websocket-version" "13"
  if let some origin := offer.origin? then headers := headers.insert "origin" origin
  unless offer.subprotocols.isEmpty do
    headers := headers.insert "sec-websocket-protocol"
      (Ws.Handshake.serializeSubprotocols offer.subprotocols)
  unless offer.extensions.isEmpty do
    headers := headers.insert "sec-websocket-extensions"
      (← Ws.Handshake.serializeExtensions offer.extensions)
  headers := headers.append (← toMetadata offer.extraHeaders)
  let request : Request := {
    protocol := "websocket"
    scheme := offer.endpoint.scheme.httpName
    authority := offer.endpoint.authority
    path := offer.endpoint.http2RequestTarget
    headers
  }
  match Http2.ExtendedConnect.encodeRequest request with
  | .ok _ => pure request
  | .error status => throw (statusError status)

private def requireNoBodyFields (headers : Headers) : Except Error Unit := do
  unless (Headers.getAll headers "content-length").isEmpty do
    throw (Error.handshake "HTTP/2 WebSocket opening handshake forbids Content-Length")
  unless (Headers.getAll headers "transfer-encoding").isEmpty do
    throw (Error.handshake "HTTP/2 WebSocket opening handshake forbids Transfer-Encoding")

private def validateTarget (scheme authority target : String) : Except Error Unit := do
  unless scheme == "http" || scheme == "https" do
    throw (Error.handshake "WebSocket extended CONNECT scheme must be http or https")
  unless target.startsWith "/" do
    throw (Error.handshake "WebSocket extended CONNECT path must use origin form")
  let websocketScheme := if scheme == "https" then "wss" else "ws"
  let endpoint ← Endpoint.parse (websocketScheme ++ "://" ++ authority ++ target)
  unless endpoint.authority == authority && endpoint.http2RequestTarget == target do
    throw (Error.handshake "WebSocket extended CONNECT authority or path is invalid")

def validateServerRequest (request : Request) (limits : Limits := {}) :
    Except Error ServerRequest := do
  validateRequestLimits request limits
  match Http2.ExtendedConnect.encodeRequest request with
  | .error status => throw (statusError status)
  | .ok _ => pure ()
  unless request.protocol == "websocket" do
    throw (Error.handshake "extended CONNECT :protocol must be websocket")
  validateTarget request.scheme request.authority request.path
  let headers ← toWsHeaders request.headers
  requireNoBodyFields headers
  unless (Headers.getAll headers "connection").isEmpty &&
      (Headers.getAll headers "upgrade").isEmpty &&
      (Headers.getAll headers "host").isEmpty &&
      (Headers.getAll headers "sec-websocket-key").isEmpty &&
      (Headers.getAll headers "sec-websocket-accept").isEmpty do
    throw (Error.handshake "HTTP/1 WebSocket fields are forbidden in extended CONNECT")
  let version ← Headers.requireUniqueAscii headers "sec-websocket-version"
  unless version == "13" do
    throw (Error.handshake "unsupported WebSocket version; version 13 is required")
  let origin? ← match ← Headers.getUnique? headers "origin" with
    | none => pure none
    | some bytes =>
        let some value := Header.asciiString? bytes
          | throw (Error.handshake "Origin must contain ASCII")
        pure (some value)
  pure {
    scheme := request.scheme, authority := request.authority, target := request.path,
    origin?, subprotocols := ← Ws.Handshake.parseSubprotocols headers,
    extensions := ← Ws.Handshake.parseExtensions headers, headers
  }

def buildServerResponse (request : ServerRequest) (accept : ServerAccept) :
    Except Error Response := do
  validateExtras accept.extraHeaders protectedResponseName
  if let some selected := accept.subprotocol? then
    unless request.subprotocols.any fun offered => offered == selected do
      throw (Error.invalidArgument "selected WebSocket subprotocol was not offered")
  Ws.Handshake.validateNegotiatedExtensions request.extensions accept.extensions
  let mut headers := Http2.Headers.empty
  if let some selected := accept.subprotocol? then
    headers := headers.insert "sec-websocket-protocol" selected.value
  unless accept.extensions.isEmpty do
    headers := headers.insert "sec-websocket-extensions"
      (← Ws.Handshake.serializeExtensions accept.extensions)
  headers := headers.append (← toMetadata accept.extraHeaders)
  let response : Response := { status := 200, headers }
  match Http2.ExtendedConnect.encodeResponse response with
  | .ok _ => pure response
  | .error status => throw (statusError status)

def validateServerResponse (offer : ClientOffer) (response : Response) (limits : Limits := {}) :
    Except Error ClientAccepted := do
  validateResponseLimits response limits
  match Http2.ExtendedConnect.encodeResponse response with
  | .error status => throw (statusError status)
  | .ok _ => pure ()
  unless 200 <= response.status && response.status < 300 do
    throw (Error.handshake s!"WebSocket extended CONNECT response status is {response.status}, not 2xx")
  let headers ← toWsHeaders response.headers
  requireNoBodyFields headers
  unless (Headers.getAll headers "connection").isEmpty &&
      (Headers.getAll headers "upgrade").isEmpty &&
      (Headers.getAll headers "host").isEmpty &&
      (Headers.getAll headers "origin").isEmpty &&
      (Headers.getAll headers "sec-websocket-key").isEmpty &&
      (Headers.getAll headers "sec-websocket-version").isEmpty &&
      (Headers.getAll headers "sec-websocket-accept").isEmpty do
    throw (Error.handshake "HTTP/1 WebSocket fields are forbidden in extended CONNECT response")
  let subprotocol? ← Ws.Handshake.selectedSubprotocol headers offer.subprotocols
  if (Headers.getAll headers "sec-websocket-extensions").size > 1 then
    throw (Error.handshake
      "opening response contains more than one Sec-WebSocket-Extensions field")
  let extensions ← Ws.Handshake.parseExtensions headers
  Ws.Handshake.validateNegotiatedExtensions offer.extensions extensions
  pure { subprotocol?, extensions, headers }

end Ws.Http2.Handshake
