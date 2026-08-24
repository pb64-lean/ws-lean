module

public import Ws.Endpoint
public import Ws.Handshake.Common

public section

namespace Ws.Handshake.Http1

structure Version where
  major : Nat
  minor : Nat
  deriving Inhabited, Repr, DecidableEq

namespace Version

def supportsWebSocket (version : Version) : Bool :=
  version.major == 1 && version.minor >= 1

end Version

structure RequestLine where
  method : String
  target : String
  version : Version
  deriving Inhabited, Repr, DecidableEq

structure StatusLine where
  version : Version
  status : Nat
  reason : ByteArray := ByteArray.empty
  deriving Inhabited, DecidableEq

inductive StartLine where
  | request (line : RequestLine)
  | response (line : StatusLine)
  deriving Inhabited, DecidableEq

structure Head where
  startLine : StartLine
  headers : Headers := #[]
  deriving Inhabited, DecidableEq

inductive ParserMode where
  | request
  | response
  deriving Inhabited, Repr, DecidableEq

structure Parser where
  mode : ParserMode
  limits : Limits := {}
  buffered : ByteArray := ByteArray.empty
  /-- Offset of the first buffered byte that has not been inspected yet. -/
  scanOffset : Nat := 0
  /-- Number of leading empty-line bytes to omit from a request head. -/
  leadingBytes : Nat := 0
  leadingEmptyLines : Nat := 0
  scanningLeadingLines : Bool := true
  currentLineHasBytes : Bool := false
  pendingCr : Bool := false
  deriving Inhabited

inductive FeedResult where
  | needMore (parser : Parser)
  | done (head : Head) (remaining : ByteArray)

private def splitCrlf (bytes : ByteArray) : Array ByteArray := Id.run do
  let mut lines : Array ByteArray := #[]
  let mut start := 0
  let mut index := 0
  while index + 1 < bytes.size do
    if bytes[index]! == 0x0d && bytes[index + 1]! == 0x0a then
      lines := lines.push (bytes.extract start index)
      start := index + 2
      index := index + 2
    else
      index := index + 1
  return lines.push (bytes.extract start bytes.size)

private def splitSpaces (bytes : ByteArray) : Array ByteArray := Id.run do
  let mut parts : Array ByteArray := #[]
  let mut start := 0
  for index in [0:bytes.size] do
    if bytes[index]! == 0x20 then
      parts := parts.push (bytes.extract start index)
      start := index + 1
  return parts.push (bytes.extract start bytes.size)

private def ascii! (bytes : ByteArray) (description : String) : Except Error String := do
  let some value := Header.asciiString? bytes
    | throw (Error.handshake s!"{description} must contain ASCII")
  pure value

private def parseVersion (bytes : ByteArray) : Except Error Version := do
  if bytes.size != 8 || bytes.extract 0 5 != "HTTP/".toUTF8 ||
      !Byte.isDigit bytes[5]! || bytes[6]! != 0x2e || !Byte.isDigit bytes[7]! then
    throw (Error.handshake "invalid HTTP version")
  pure {
    major := bytes[5]!.toNat - 0x30,
    minor := bytes[7]!.toNat - 0x30
  }

private def parseRequestLine (bytes : ByteArray) : Except Error RequestLine := do
  let parts := splitSpaces bytes
  unless parts.size == 3 && parts.toList.all (fun part => !part.isEmpty) do
    throw (Error.handshake "invalid HTTP request line")
  let methodBytes := parts[0]!
  unless Header.validNameBytes methodBytes do
    throw (Error.handshake "invalid HTTP method")
  let targetBytes := parts[1]!
  unless targetBytes.toList.all Byte.isVisibleAscii do
    throw (Error.handshake "invalid HTTP request target")
  pure {
    method := ← ascii! methodBytes "HTTP method",
    target := ← ascii! targetBytes "HTTP request target",
    version := ← parseVersion parts[2]!
  }

private def parseStatusLine (bytes : ByteArray) : Except Error StatusLine := do
  if bytes.size < 12 || bytes[8]! != 0x20 then
    throw (Error.handshake "invalid HTTP status line")
  let version ← parseVersion (bytes.extract 0 8)
  let code := bytes.extract 9 12
  unless code.size == 3 && code.toList.all Byte.isDigit do
    throw (Error.handshake "invalid HTTP status code")
  let status := code.foldl (fun value byte => value * 10 + byte.toNat - 0x30) 0
  let reason ←
    if bytes.size == 12 then pure ByteArray.empty
    else if bytes[12]! != 0x20 then
      throw (Error.handshake "invalid HTTP status reason separator")
    else pure (bytes.extract 13 bytes.size)
  unless Header.validValueBytes reason do
    throw (Error.handshake "invalid HTTP status reason")
  pure { version, status, reason }

private def colonIndex? (bytes : ByteArray) : Option Nat := Id.run do
  for i in [0:bytes.size] do
    if bytes[i]! == 0x3a then return some i
  return none

private def parseHeaders (lines : Array ByteArray) (limits : Limits) : Except Error Headers := do
  if lines.size > limits.maxHeaderCount then
    throw (Error.handshake "HTTP head exceeds the configured field-count limit")
  let mut headers : Headers := #[]
  for line in lines do
    if line.isEmpty then
      throw (Error.handshake "unexpected empty HTTP field line")
    if line[0]! == 0x20 || line[0]! == 0x09 then
      throw (Error.handshake "obsolete folded HTTP field line is forbidden")
    let some colon := colonIndex? line
      | throw (Error.handshake "HTTP field line is missing a colon")
    let name := line.extract 0 colon
    let rawValue := line.extract (colon + 1) line.size
    if name.size > limits.maxHeaderNameBytes then
      throw (Error.handshake "HTTP field name exceeds the configured limit")
    if rawValue.size > limits.maxHeaderValueBytes then
      throw (Error.handshake "HTTP field value exceeds the configured limit")
    let name ← ascii! name "HTTP field name"
    headers := headers.push (← Header.ofBytes name rawValue)
  pure headers

private def parseHead (mode : ParserMode) (limits : Limits) (bytes : ByteArray) :
    Except Error Head := do
  let lines := splitCrlf bytes
  if lines.isEmpty || lines[0]!.isEmpty then
    throw (Error.handshake "HTTP head is missing a start line")
  if lines[0]!.size > limits.maxStartLineBytes then
    throw (Error.handshake "HTTP start line exceeds the configured limit")
  let startLine ← match mode with
    | .request => pure (.request (← parseRequestLine lines[0]!))
    | .response => pure (.response (← parseStatusLine lines[0]!))
  let headerLines := lines.extract 1 lines.size
  pure { startLine, headers := ← parseHeaders headerLines limits }

namespace Parser

def request (limits : Limits := {}) : Parser := { mode := .request, limits }

def response (limits : Limits := {}) : Parser := { mode := .response, limits }

/-- Parse one HTTP/1 head from arbitrary chunks. Each buffered byte is scanned
once while looking for the head terminator. Bare line endings and obsolete
folding are rejected; bytes after the terminator are returned unchanged. -/
def feed (parser : Parser) (chunk : ByteArray) : Except Error FeedResult := do
  let bytes := parser.buffered.append chunk
  let mut index := min parser.scanOffset parser.buffered.size
  let mut leadingBytes := parser.leadingBytes
  let mut leadingEmptyLines := parser.leadingEmptyLines
  let mut scanningLeadingLines := parser.scanningLeadingLines
  let mut currentLineHasBytes := parser.currentLineHasBytes
  let mut pendingCr := parser.pendingCr
  while index < bytes.size do
    let byte := bytes[index]!
    let consumed := index + 1
    if pendingCr then
      unless byte == 0x0a do
        throw (Error.handshake "HTTP head contains a bare CR")
      pendingCr := false
      if scanningLeadingLines then
        leadingEmptyLines := leadingEmptyLines + 1
        if parser.mode == .response then
          throw (Error.handshake "HTTP response must begin with its status line")
        if leadingEmptyLines > parser.limits.maxLeadingEmptyLines then
          throw (Error.handshake "HTTP head has too many leading empty lines")
        leadingBytes := consumed
      else if currentLineHasBytes then
        currentLineHasBytes := false
      else
        if consumed > parser.limits.maxHandshakeBytes then
          throw (Error.handshake "HTTP head exceeds the configured byte limit")
        let marker := consumed - 4
        let head ← parseHead parser.mode parser.limits
          (bytes.extract leadingBytes marker)
        return .done head (bytes.extract consumed bytes.size)
    else if byte == 0x0a then
      throw (Error.handshake "HTTP head contains a bare LF")
    else if byte == 0x0d then
      pendingCr := true
    else
      scanningLeadingLines := false
      currentLineHasBytes := true
    if consumed > parser.limits.maxHandshakeBytes then
      throw (Error.handshake "HTTP head exceeds the configured byte limit")
    index := consumed
  pure (.needMore {
    parser with
    buffered := bytes
    scanOffset := bytes.size
    leadingBytes
    leadingEmptyLines
    scanningLeadingLines
    currentLineHasBytes
    pendingCr
  })

end Parser

private def ensureNoMessageBody (headers : Headers) : Except Error Unit := do
  unless (Headers.getAll headers "transfer-encoding").isEmpty do
    throw (Error.handshake "WebSocket opening handshake cannot use Transfer-Encoding")
  let rawLengths := Headers.getAll headers "content-length"
  let lengths ← Headers.commaItems headers "content-length"
  if !rawLengths.isEmpty && lengths.isEmpty then
    throw (Error.handshake "WebSocket opening handshake has an invalid Content-Length")
  for value in lengths do
    unless !value.isEmpty && value.toList.all Byte.isDigit do
      throw (Error.handshake "WebSocket opening handshake has an invalid Content-Length")
    unless value.toList.all (· == 0x30) do
      throw (Error.handshake "WebSocket opening handshake has a nonzero Content-Length")

private def ensureNoResponseBodyFields (headers : Headers) : Except Error Unit := do
  unless (Headers.getAll headers "transfer-encoding").isEmpty do
    throw (Error.handshake "WebSocket opening response cannot use Transfer-Encoding")
  unless (Headers.getAll headers "content-length").isEmpty do
    throw (Error.handshake "a 101 WebSocket response cannot contain Content-Length")

private def requireUpgradeFields (headers : Headers) : Except Error Unit := do
  let connection ← Headers.tokenItems headers "connection"
  unless connection.any fun value => value.toLower == "upgrade" do
    throw (Error.handshake "HTTP Connection field does not contain Upgrade")
  let upgrades ← Headers.commaItems headers "upgrade"
  let mut websocket := false
  for item in upgrades do
    let slashCount := item.toList.count 0x2f
    unless slashCount <= 1 do
      throw (Error.handshake "HTTP Upgrade field contains an invalid protocol")
    let (name, version?) :=
      match item.toList.splitOnP (· == 0x2f) with
      | [name] => (ByteArray.mk name.toArray, none)
      | [name, version] => (ByteArray.mk name.toArray, some (ByteArray.mk version.toArray))
      | _ => (ByteArray.empty, none)
    unless Header.validNameBytes name do
      throw (Error.handshake "HTTP Upgrade field contains an invalid protocol name")
    if let some version := version? then
      unless Header.validNameBytes version do
        throw (Error.handshake "HTTP Upgrade field contains an invalid protocol version")
    if (← ascii! name "HTTP Upgrade protocol").toLower == "websocket" && version?.isNone then
      websocket := true
  unless websocket do
    throw (Error.handshake "HTTP Upgrade field does not contain websocket")

private def optionalUniqueAscii (headers : Headers) (name : String) :
    Except Error (Option String) := do
  match ← Headers.getUnique? headers name with
  | none => pure none
  | some bytes =>
      let some value := Header.asciiString? bytes
        | throw (Error.handshake s!"HTTP field {name} must contain ASCII")
      pure (some value)

private def parseAuthority (scheme : Scheme) (authority : String) : Except Error Endpoint := do
  if authority.isEmpty then
    throw (Error.handshake "WebSocket Host field is empty")
  match Endpoint.parse (scheme.websocketName ++ "://" ++ authority) with
  | .error _ => throw (Error.handshake "WebSocket Host field is invalid")
  | .ok endpoint =>
      unless endpoint.authority == authority && endpoint.path == "/" &&
          endpoint.query?.isNone do
        throw (Error.handshake "WebSocket Host field contains a path or query")
      pure endpoint

private def sameHost (left right : String) : Bool :=
  match Std.Net.IPv4Addr.ofString left, Std.Net.IPv4Addr.ofString right with
  | some left, some right => left == right
  | some _, none | none, some _ => false
  | none, none =>
      match Std.Net.IPv6Addr.ofString left, Std.Net.IPv6Addr.ofString right with
      | some left, some right => left == right
      | some _, none | none, some _ => false
      | none, none => left.toLower == right.toLower

/-- Validate origin-form or proxy absolute-form and return the resource name. -/
private def validateRequestTarget (target authority : String) : Except Error String := do
  if target.startsWith "/" then
    discard <| parseAuthority .ws authority
    match Endpoint.parse ("ws://websocket.invalid" ++ target) with
    | .ok endpoint => pure endpoint.http1RequestTarget
    | .error _ => throw (Error.handshake "WebSocket opening request target is invalid")
  else
    let lower := target.toLower
    let (scheme, remainder) ←
      if lower.startsWith "http://" then
        pure (.ws, (target.drop 7).toString)
      else if lower.startsWith "https://" then
        pure (.wss, (target.drop 8).toString)
      else
        throw (Error.handshake
          "WebSocket opening request target must use origin or absolute form")
    let endpoint ← match Endpoint.parse
        (scheme.websocketName ++ "://" ++ remainder) with
      | .ok endpoint => pure endpoint
      | .error _ => throw (Error.handshake "WebSocket absolute request target is invalid")
    let hostEndpoint ← parseAuthority scheme authority
    unless endpoint.port == hostEndpoint.port &&
        sameHost endpoint.serverName hostEndpoint.serverName do
      throw (Error.handshake "WebSocket absolute request target does not match Host")
    pure endpoint.http1RequestTarget

private def protectedRequestName (name : String) : Bool :=
  name == "host" || name == "upgrade" || name == "connection" ||
    name == "origin" || name == "content-length" || name == "transfer-encoding" ||
    name == "sec-websocket-key" || name == "sec-websocket-version" ||
    name == "sec-websocket-accept" ||
    name == "sec-websocket-protocol" || name == "sec-websocket-extensions"

private def protectedResponseName (name : String) : Bool :=
  name == "upgrade" || name == "connection" || name == "host" || name == "origin" ||
    name == "content-length" ||
    name == "transfer-encoding" || name == "sec-websocket-accept" ||
    name == "sec-websocket-key" || name == "sec-websocket-version" ||
    name == "sec-websocket-protocol" || name == "sec-websocket-extensions"

private def validateExtraHeaders (headers : Headers) (isProtected : String -> Bool) :
    Except Error Unit := do
  for header in headers do
    let checked ← Header.ofBytes header.name header.value
    if isProtected checked.name then
      throw (Error.invalidArgument s!"extra HTTP field {checked.name} is managed by ws-lean")

structure ClientOffer where
  endpoint : Endpoint
  key : String
  subprotocols : Array Subprotocol := #[]
  extensions : Array Extension := #[]
  origin? : Option String := none
  extraHeaders : Headers := #[]

namespace ClientOffer

private def validateProtocols (protocols : Array Subprotocol) : Except Error Unit := do
  let mut seen : Std.HashSet String := {}
  for protocol in protocols do
    if seen.contains protocol.value then
      throw (Error.invalidArgument "duplicate WebSocket subprotocol offer")
    seen := seen.insert protocol.value

def create (endpoint : Endpoint) (nonce : ByteArray)
    (subprotocols : Array Subprotocol := #[]) (extensions : Array Extension := #[])
    (origin? : Option String := none) (extraHeaders : Headers := #[]) :
    Except Error ClientOffer := do
  unless nonce.size == 16 do
    throw (Error.invalidArgument "a WebSocket client nonce must contain exactly 16 bytes")
  validateProtocols subprotocols
  validateExtraHeaders extraHeaders protectedRequestName
  if let some origin := origin? then validateOriginValue origin
  pure {
    endpoint, key := Base64.encode nonce, subprotocols, extensions, origin?, extraHeaders
  }

end ClientOffer

structure ServerRequest where
  target : String
  version : Version
  authority : String
  key : String
  nonce : ByteArray
  origin? : Option String
  subprotocols : Array Subprotocol
  extensions : Array Extension
  headers : Headers

structure ServerAccept where
  subprotocol? : Option Subprotocol := none
  extensions : Array Extension := #[]
  extraHeaders : Headers := #[]

structure ClientAccepted where
  subprotocol? : Option Subprotocol
  extensions : Array Extension
  headers : Headers

private def appendField (headers : Headers) (name value : String) : Except Error Headers :=
  headers.insert name value

def buildClientRequest (offer : ClientOffer) : Except Error ByteArray := do
  discard <| validateClientKey offer.key
  ClientOffer.validateProtocols offer.subprotocols
  validateExtraHeaders offer.extraHeaders protectedRequestName
  if let some origin := offer.origin? then validateOriginValue origin
  let mut headers : Headers := #[]
  headers ← appendField headers "Host" offer.endpoint.authority
  headers ← appendField headers "Upgrade" "websocket"
  headers ← appendField headers "Connection" "Upgrade"
  headers ← appendField headers "Sec-WebSocket-Key" offer.key
  headers ← appendField headers "Sec-WebSocket-Version" "13"
  if let some origin := offer.origin? then
    headers ← appendField headers "Origin" origin
  unless offer.subprotocols.isEmpty do
    headers ← appendField headers "Sec-WebSocket-Protocol"
      (serializeSubprotocols offer.subprotocols)
  unless offer.extensions.isEmpty do
    headers ← appendField headers "Sec-WebSocket-Extensions"
      (← serializeExtensions offer.extensions)
  headers := headers.append offer.extraHeaders
  let start := s!"GET {offer.endpoint.http1RequestTarget} HTTP/1.1\r\n".toUTF8
  pure <| (start.append (← Headers.serialize headers)).append "\r\n".toUTF8

def validateClientRequest (head : Head) : Except Error ServerRequest := do
  let line ← match head.startLine with
    | .request line => pure line
    | .response _ => throw (Error.handshake "expected an HTTP request head")
  unless line.method == "GET" do
    throw (Error.handshake "WebSocket opening request method must be GET")
  unless line.version.supportsWebSocket do
    throw (Error.handshake "WebSocket opening request requires HTTP/1.1 or later")
  ensureNoMessageBody head.headers
  requireUpgradeFields head.headers
  let authority ← Headers.requireUniqueAscii head.headers "host"
  let target ← validateRequestTarget line.target authority
  let key ← Headers.requireUniqueAscii head.headers "sec-websocket-key"
  unless (Headers.getAll head.headers "sec-websocket-accept").isEmpty do
    throw (Error.handshake "opening request must not contain Sec-WebSocket-Accept")
  let nonce ← validateClientKey key
  let version ← Headers.requireUniqueAscii head.headers "sec-websocket-version"
  unless version == "13" do
    throw (Error.handshake "unsupported WebSocket version; version 13 is required")
  let origin? ← optionalUniqueAscii head.headers "origin"
  pure {
    target, version := line.version, authority, key, nonce, origin?,
    subprotocols := ← parseSubprotocols head.headers,
    extensions := ← parseExtensions head.headers,
    headers := head.headers
  }

def buildServerResponse (request : ServerRequest) (accept : ServerAccept) :
    Except Error ByteArray := do
  validateExtraHeaders accept.extraHeaders protectedResponseName
  if let some selected := accept.subprotocol? then
    unless request.subprotocols.any fun offered => offered == selected do
      throw (Error.invalidArgument "selected WebSocket subprotocol was not offered")
  validateNegotiatedExtensions request.extensions accept.extensions
  let mut headers : Headers := #[]
  headers ← appendField headers "Upgrade" "websocket"
  headers ← appendField headers "Connection" "Upgrade"
  headers ← appendField headers "Sec-WebSocket-Accept" (acceptForKey request.key)
  if let some selected := accept.subprotocol? then
    headers ← appendField headers "Sec-WebSocket-Protocol" selected.value
  unless accept.extensions.isEmpty do
    headers ← appendField headers "Sec-WebSocket-Extensions"
      (← serializeExtensions accept.extensions)
  headers := headers.append accept.extraHeaders
  pure <| ("HTTP/1.1 101 Switching Protocols\r\n".toUTF8.append
    (← Headers.serialize headers)).append "\r\n".toUTF8

def validateServerResponse (offer : ClientOffer) (head : Head) :
    Except Error ClientAccepted := do
  discard <| validateClientKey offer.key
  ClientOffer.validateProtocols offer.subprotocols
  let line ← match head.startLine with
    | .response line => pure line
    | .request _ => throw (Error.handshake "expected an HTTP response head")
  unless line.version.supportsWebSocket do
    throw (Error.handshake "WebSocket opening response requires HTTP/1.1 or later")
  unless line.status == 101 do
    throw (Error.handshake s!"WebSocket opening response status is {line.status}, not 101")
  ensureNoResponseBodyFields head.headers
  requireUpgradeFields head.headers
  let accepted ← Headers.requireUniqueAscii head.headers "sec-websocket-accept"
  unless (Headers.getAll head.headers "host").isEmpty &&
      (Headers.getAll head.headers "origin").isEmpty &&
      (Headers.getAll head.headers "sec-websocket-key").isEmpty &&
      (Headers.getAll head.headers "sec-websocket-version").isEmpty do
    throw (Error.handshake "opening response contains request-only WebSocket fields")
  unless accepted == acceptForKey offer.key do
    throw (Error.handshake "Sec-WebSocket-Accept does not match the client key")
  let subprotocol? ← selectedSubprotocol head.headers offer.subprotocols
  if (Headers.getAll head.headers "sec-websocket-extensions").size > 1 then
    throw (Error.handshake
      "opening response contains more than one Sec-WebSocket-Extensions field")
  let extensions ← parseExtensions head.headers
  validateNegotiatedExtensions offer.extensions extensions
  pure { subprotocol?, extensions, headers := head.headers }

end Ws.Handshake.Http1
