module

public import Ws.Basic
public import Std.Net.Addr

public section

namespace Ws

inductive Scheme where
  | ws
  | wss
  deriving Inhabited, Repr, DecidableEq

namespace Scheme

def secure : Scheme -> Bool
  | .ws => false
  | .wss => true

def defaultPort : Scheme -> Nat
  | .ws => 80
  | .wss => 443

def websocketName : Scheme -> String
  | .ws => "ws"
  | .wss => "wss"

def httpName : Scheme -> String
  | .ws => "http"
  | .wss => "https"

end Scheme

/-- A normalized WebSocket endpoint. `host` retains brackets around an IPv6
literal, while `serverName` removes them for TLS SNI and hostname checks. -/
structure Endpoint where
  private mk ::
  scheme : Scheme
  host : String
  serverName : String
  port : Nat
  explicitPort : Bool := false
  path : String := "/"
  query? : Option String := none
  deriving Repr, DecidableEq

namespace Endpoint

private def splitAuthority : List Char -> List Char × List Char
  | [] => ([], [])
  | chars@(c :: rest) =>
      if c == '/' || c == '?' then
        ([], chars)
      else
        let (authority, suffix) := splitAuthority rest
        (c :: authority, suffix)

private def splitFirst (needle : Char) : List Char -> List Char × Option (List Char)
  | [] => ([], none)
  | c :: rest =>
      if c == needle then
        ([], some rest)
      else
        let (before, after) := splitFirst needle rest
        (c :: before, after)

private def splitLastColon (chars : List Char) : List Char × Option (List Char) :=
  let rec loop (remaining before : List Char) (last? : Option (List Char × List Char)) :=
    match remaining with
    | [] =>
        match last? with
        | none => (chars, none)
        | some (host, port) => (host, some port)
    | c :: rest =>
        let last? := if c == ':' then some (before.reverse, rest) else last?
        loop rest (c :: before) last?
  loop chars [] none

private def validPercentEscapes : List Char -> Bool
  | [] => true
  | '%' :: a :: b :: rest =>
      a.toNat < 128 && b.toNat < 128 &&
        Byte.isHexDigit (UInt8.ofNat a.toNat) &&
        Byte.isHexDigit (UInt8.ofNat b.toNat) && validPercentEscapes rest
  | '%' :: _ => false
  | c :: rest => c.toNat < 128 && validPercentEscapes rest

private def validRegNameChar (c : Char) : Bool :=
  let b := UInt8.ofNat c.toNat
  c.toNat < 128 && ((0x30 <= b && b <= 0x39) ||
    (0x41 <= b && b <= 0x5a) ||
    (0x61 <= b && b <= 0x7a) ||
    c == '-' || c == '.' || c == '_' || c == '~' || c == '%' ||
    c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' ||
    c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c == '=')

private def validRegName (chars : List Char) : Bool :=
  -- Connector, SNI, and certificate identity must use one canonical spelling.
  -- Percent-encoded reg-names need URI host decoding and IDNA policy that this
  -- ASCII endpoint type deliberately does not claim.
  !chars.isEmpty && !chars.contains '%' && chars.all validRegNameChar

private def validIpLiteral (chars : List Char) : Bool :=
  let value := String.ofList chars
  -- Zone identifiers and IPvFuture need additional connector and SNI
  -- semantics, so this endpoint type intentionally accepts plain IPv6 only.
  !chars.isEmpty && !chars.contains '%' &&
    (Std.Net.IPv6Addr.ofString value).isSome

private def legacyNumericPart (chars : List Char) : Bool :=
  match chars with
  | '0' :: marker :: digits =>
      if marker == 'x' || marker == 'X' then
        !digits.isEmpty && digits.all fun c =>
          c.toNat < 128 && Byte.isHexDigit (UInt8.ofNat c.toNat)
      else
        chars.all fun c => c.toNat < 128 && Byte.isDigit (UInt8.ofNat c.toNat)
  | _ => !chars.isEmpty && chars.all fun c =>
      c.toNat < 128 && Byte.isDigit (UInt8.ofNat c.toNat)

/-- Detect numeric-looking dotted names and the one- through four-part legacy
decimal, octal-like, and hexadecimal forms that resolvers may reinterpret. -/
private def looksLikeLegacyIpv4 (chars : List Char) : Bool :=
  let decimalAndDots := chars.all fun c =>
    c == '.' || (c.toNat < 128 && Byte.isDigit (UInt8.ofNat c.toNat))
  let core := if chars.getLast? == some '.' then chars.dropLast else chars
  let parts := core.splitOnP (· == '.')
  decimalAndDots || (parts.length <= 4 && parts.all legacyNumericPart)

private def validCanonicalIpv4 (chars : List Char) : Bool :=
  let parts := chars.splitOnP (· == '.')
  parts.length == 4 && parts.all fun part =>
    !part.isEmpty && (part.length == 1 || part.head? != some '0') &&
      part.all (fun c => c.toNat < 128 && Byte.isDigit (UInt8.ofNat c.toNat)) &&
      part.foldl (fun value c => value * 10 + c.toNat - '0'.toNat) 0 <= 255

private def parsePort (chars : List Char) : Except Error Nat := do
  if chars.isEmpty then
    throw (Error.invalidArgument "WebSocket URI has an empty port")
  let port ← chars.foldlM (init := 0) fun value c => do
    let byte := UInt8.ofNat c.toNat
    unless c.toNat < 128 && Byte.isDigit byte do
      throw (Error.invalidArgument "WebSocket URI port is not decimal")
    let next := value * 10 + (byte.toNat - 0x30)
    if next > 65535 then
      throw (Error.invalidArgument "WebSocket URI port exceeds 65535")
    pure next
  if port == 0 then
    throw (Error.invalidArgument "WebSocket URI port must be positive")
  pure port

private def parseAuthority (scheme : Scheme) (chars : List Char) :
    Except Error (String × String × Nat × Bool) := do
  if chars.isEmpty then
    throw (Error.invalidArgument "WebSocket URI has an empty host")
  if chars.contains '@' then
    throw (Error.invalidArgument "WebSocket URI must not contain user information")
  match chars with
  | '[' :: rest =>
      let (inside, suffix?) := splitFirst ']' rest
      let some suffix := suffix?
        | throw (Error.invalidArgument "WebSocket URI has an unterminated IP literal")
      unless validIpLiteral inside do
        throw (Error.invalidArgument "WebSocket URI has an invalid IP literal")
      let host := String.ofList ('[' :: inside ++ [']'])
      let serverName := String.ofList inside
      match suffix with
      | [] => pure (host, serverName, scheme.defaultPort, false)
      | ':' :: portChars =>
          pure (host, serverName, ← parsePort portChars, true)
      | _ => throw (Error.invalidArgument "invalid characters after WebSocket IP literal")
  | _ =>
      let colonCount := chars.count ':'
      if colonCount > 1 then
        throw (Error.invalidArgument "an IPv6 WebSocket host must be bracketed")
      let (hostChars, portChars?) := splitLastColon chars
      unless validRegName hostChars do
        throw (Error.invalidArgument "WebSocket URI has an invalid host")
      let host := String.ofList hostChars
      if looksLikeLegacyIpv4 hostChars then
        unless validCanonicalIpv4 hostChars do
          throw (Error.invalidArgument "numeric WebSocket hosts must use canonical IPv4 syntax")
      match portChars? with
      | none => pure (host, host, scheme.defaultPort, false)
      | some portChars => pure (host, host, ← parsePort portChars, true)

private def validTargetChar (c : Char) : Bool :=
  let b := UInt8.ofNat c.toNat
  c.toNat < 128 && ((0x30 <= b && b <= 0x39) || (0x41 <= b && b <= 0x5a) ||
    (0x61 <= b && b <= 0x7a) || c == '-' || c == '.' || c == '_' ||
    c == '~' || c == '!' || c == '$' || c == '&' || c == '\'' ||
    c == '(' || c == ')' || c == '*' || c == '+' || c == ',' ||
    c == ';' || c == '=' || c == ':' || c == '@' || c == '/' ||
    c == '?' || c == '%')

private def validTargetChars (chars : List Char) : Bool :=
  validPercentEscapes chars && chars.all validTargetChar

/-- Parse an ASCII absolute `ws` or `wss` URI whose reg-name host is already an
IDNA A-label. Fragments, user information, percent-encoded hosts, IPvFuture,
IPv6 zone identifiers, IRIs, and ambiguous noncanonical numeric names are
intentionally rejected; an absent path is normalized to `/`. -/
def parse (uri : String) : Except Error Endpoint := do
  let lower := uri.toLower
  let (scheme, remainder) ←
    if lower.startsWith "ws://" then
      pure (.ws, (uri.drop 5).toString)
    else if lower.startsWith "wss://" then
      pure (.wss, (uri.drop 6).toString)
    else
      throw (Error.invalidArgument "WebSocket URI must use ws or wss")
  if remainder.toList.contains '#' then
    throw (Error.invalidArgument "WebSocket URI must not contain a fragment")
  let (authorityChars, suffix) := splitAuthority remainder.toList
  let (host, serverName, port, explicitPort) ← parseAuthority scheme authorityChars
  let (pathChars, query?) :=
    match suffix with
    | [] => (['/'], none)
    | '?' :: query => (['/'], some query)
    | chars =>
        let (path, query?) := splitFirst '?' chars
        (path, query?)
  unless !pathChars.isEmpty && pathChars.head? == some '/' && validTargetChars pathChars do
    throw (Error.invalidArgument "WebSocket URI has an invalid path")
  match query? with
  | some query =>
      unless validTargetChars query do
        throw (Error.invalidArgument "WebSocket URI has an invalid query")
  | none => pure ()
  pure {
    scheme, host, serverName, port, explicitPort,
    path := String.ofList pathChars,
    query? := query?.map String.ofList
  }

def authority (endpoint : Endpoint) : String :=
  if endpoint.explicitPort || endpoint.port != endpoint.scheme.defaultPort then
    endpoint.host ++ ":" ++ toString endpoint.port
  else
    endpoint.host

/-- RFC 6455 resource name for an HTTP/1 Upgrade request. -/
def http1RequestTarget (endpoint : Endpoint) : String :=
  match endpoint.query? with
  | some query =>
      if query.isEmpty then endpoint.path else endpoint.path ++ "?" ++ query
  | none => endpoint.path

/-- Path pseudo-header value for an RFC 8441 extended CONNECT request. -/
def http2RequestTarget (endpoint : Endpoint) : String :=
  match endpoint.query? with
  | none => endpoint.path
  | some query => endpoint.path ++ "?" ++ query

def uri (endpoint : Endpoint) : String :=
  let suffix := match endpoint.query? with
    | none => endpoint.path
    | some query => endpoint.path ++ "?" ++ query
  endpoint.scheme.websocketName ++ "://" ++ endpoint.authority ++ suffix

end Endpoint

end Ws
