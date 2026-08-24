import Ws.Handshake.Http1

open Ws
open Ws.Handshake
open Ws.Handshake.Http1

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectError {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def parseWhole (mode : ParserMode) (wire : ByteArray) : IO (Head × ByteArray) := do
  let parser := match mode with
    | .request => Parser.request
    | .response => Parser.response
  match ← take "HTTP head parse" (parser.feed wire) with
  | .needMore _ => throw (IO.userError "complete HTTP head requested more bytes")
  | .done head remaining => pure (head, remaining)

def parseBytewiseRequest (wire : ByteArray) : IO Head := do
  let mut parser := Parser.request
  let mut completed? : Option Head := none
  for index in [0:wire.size] do
    if completed?.isNone then
      match ← take "bytewise request parse"
          (parser.feed (wire.extract index (index + 1))) with
      | .needMore next => parser := next
      | .done head remaining =>
          expect (remaining.isEmpty && index + 1 == wire.size)
            "bytewise request completed before its terminator"
          completed? := some head
  let some head := completed?
    | throw (IO.userError "bytewise request never completed")
  pure head

def parseBytewiseResponse (wire : ByteArray) : IO Head := do
  let mut parser := Parser.response
  let mut completed? : Option Head := none
  for index in [0:wire.size] do
    if completed?.isNone then
      match ← take "bytewise response parse"
          (parser.feed (wire.extract index (index + 1))) with
      | .needMore next => parser := next
      | .done head remaining =>
          expect (remaining.isEmpty && index + 1 == wire.size)
            "bytewise response completed before its terminator"
          completed? := some head
  let some head := completed?
    | throw (IO.userError "bytewise response never completed")
  pure head

def parseRequestAtEverySplit (wire tail : ByteArray) : IO Unit := do
  for split in [0:wire.size] do
    let first := wire.extract 0 split
    let second := (wire.extract split wire.size).append tail
    match ← take "first split request chunk" ((Parser.request).feed first) with
    | .done _ _ =>
        throw (IO.userError s!"request completed before split {split}")
    | .needMore parser =>
        expect (parser.scanOffset == first.size)
          s!"parser did not retain its incremental scan offset at split {split}"
        match ← take "second split request chunk" (parser.feed second) with
        | .needMore _ => throw (IO.userError s!"split {split} requested more bytes")
        | .done head remaining =>
            expect (remaining == tail) s!"split {split} changed the binary tail"
            discard <| take s!"split {split} request validation"
              (validateClientRequest head)

def requestWith (extra : String := "") (version : String := "HTTP/1.1") : String :=
  "GET /chat?room=blue " ++ version ++ "\r\n" ++
  "Host: server.example.com\r\n" ++
  "Upgrade: websocket\r\n" ++
  "Connection: keep-alive, Upgrade\r\n" ++
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
  "Sec-WebSocket-Version: 13\r\n" ++ extra ++ "\r\n"

set_option maxRecDepth 2048 in
def main : IO Unit := do
  let requestText := requestWith
    ("Origin: http://example.com\r\n" ++
     "Sec-WebSocket-Protocol: chat, superchat\r\n")
  let head ← parseBytewiseRequest requestText.toUTF8
  let request ← take "validate RFC request" (validateClientRequest head)
  expect (request.target == "/chat?room=blue" && request.authority == "server.example.com")
    "validated request target or authority differs"
  expect (request.key == "dGhlIHNhbXBsZSBub25jZQ==" && request.nonce.size == 16)
    "validated request key differs"
  expect (request.origin? == some "http://example.com" &&
    request.subprotocols.map (·.value) == #["chat", "superchat"])
    "validated origin or protocols differ"

  let emptyMemberRequest := requestText
    |>.replace "Upgrade: websocket" "Upgrade: , websocket,,"
    |>.replace "Connection: keep-alive, Upgrade" "Connection: ,keep-alive,, Upgrade,"
  let (emptyMemberHead, _) ← parseWhole .request emptyMemberRequest.toUTF8
  discard <| take "HTTP list empty members" (validateClientRequest emptyMemberHead)

  let absoluteRequest := requestText.replace
    "GET /chat?room=blue HTTP/1.1" "GET http://SERVER.example.com:80/chat?room=blue HTTP/1.1"
  let (absoluteHead, _) ← parseWhole .request absoluteRequest.toUTF8
  let absolute ← take "absolute-form request target" (validateClientRequest absoluteHead)
  expect (absolute.target == "/chat?room=blue")
    "absolute-form request target was not normalized to its resource name"
  let mismatchedAbsolute := absoluteRequest.replace
    "http://SERVER.example.com:80" "http://other.example.com"
  let (mismatchedAbsoluteHead, _) ← parseWhole .request mismatchedAbsolute.toUTF8
  expectError "absolute-form target Host mismatch"
    (validateClientRequest mismatchedAbsoluteHead)
  let wrongAbsoluteScheme := requestText.replace
    "GET /chat?room=blue HTTP/1.1" "GET ws://server.example.com/chat HTTP/1.1"
  let (wrongAbsoluteSchemeHead, _) ← parseWhole .request wrongAbsoluteScheme.toUTF8
  expectError "WebSocket scheme in HTTP request target"
    (validateClientRequest wrongAbsoluteSchemeHead)

  let binaryTail := ByteArray.mk #[0x82, 0x02, 0x0a, 0x0d]
  let (tailedRequest, requestRemaining) ← parseWhole .request
    (requestText.toUTF8.append binaryTail)
  expect (requestRemaining == binaryTail) "request parser modified binary leftover"
  discard <| take "tailed request validate" (validateClientRequest tailedRequest)

  let responseText :=
    "HTTP/1.1 101 Switching Protocols\r\n" ++
    "Upgrade: websocket\r\n" ++
    "Connection: Upgrade\r\n" ++
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
  let (_, responseRemaining) ← parseWhole .response
    (responseText.toUTF8.append binaryTail)
  expect (responseRemaining == binaryTail) "response parser inspected or modified binary leftover"
  discard <| parseBytewiseResponse responseText.toUTF8
  parseRequestAtEverySplit requestText.toUTF8 binaryTail

  let largeValue := String.ofList (List.replicate 8000 'a')
  let largeRequest := requestWith
    ("X-Large-One: " ++ largeValue ++ "\r\n" ++
     "X-Large-Two: " ++ largeValue ++ "\r\n")
  let largeHead ← parseBytewiseRequest largeRequest.toUTF8
  discard <| take "large bytewise request validation" (validateClientRequest largeHead)

  expectError "bare LF"
    ((Parser.request).feed "GET / HTTP/1.1\nHost: x\r\n\r\n".toUTF8)
  expectError "bare CR"
    ((Parser.request).feed "GET / HTTP/1.1\rX".toUTF8)
  expectError "obsolete line folding"
    ((Parser.request).feed "GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n".toUTF8)
  expectError "whitespace before colon"
    ((Parser.request).feed "GET / HTTP/1.1\r\nHost : x\r\n\r\n".toUTF8)
  expectError "leading response empty line"
    ((Parser.response).feed ("\r\n" ++ responseText).toUTF8)
  expectError "start-line limit"
    ((Parser.request { maxStartLineBytes := 4 }).feed
      "GET / HTTP/1.1\r\n\r\n".toUTF8)
  expectError "header count limit"
    ((Parser.request { maxHeaderCount := 1 }).feed
      "GET / HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n".toUTF8)
  let leadingRequest := ("\r\n" ++ requestWith).toUTF8
  let (leadingHead, _) ← parseWhole .request leadingRequest
  discard <| take "leading request validate" (validateClientRequest leadingHead)
  expectError "too many leading request lines"
    ((Parser.request { maxLeadingEmptyLines := 1 }).feed
      ("\r\n\r\n" ++ requestWith).toUTF8)

  let (http2Head, _) ← parseWhole .request (requestWith "" "HTTP/2.0").toUTF8
  expectError "textual HTTP/2 upgrade" (validateClientRequest http2Head)
  let (http10Head, _) ← parseWhole .request (requestWith "" "HTTP/1.0").toUTF8
  expectError "HTTP/1.0 upgrade" (validateClientRequest http10Head)

  let (zeroLengthHead, _) ← parseWhole .request
    (requestWith "Content-Length: , 00,, 000,\r\n").toUTF8
  discard <| take "decimal zero content length" (validateClientRequest zeroLengthHead)
  let (emptyLengthHead, _) ← parseWhole .request
    (requestWith "Content-Length: , ,\r\n").toUTF8
  expectError "empty content length list" (validateClientRequest emptyLengthHead)
  let (nonzeroHead, _) ← parseWhole .request
    (requestWith "Content-Length: 1\r\n").toUTF8
  expectError "nonzero content length" (validateClientRequest nonzeroHead)
  let (transferHead, _) ← parseWhole .request
    (requestWith "Transfer-Encoding: chunked\r\n").toUTF8
  expectError "transfer encoding" (validateClientRequest transferHead)

  let invalidKeyText := (requestWith).replace
    "dGhlIHNhbXBsZSBub25jZQ==" "YWJjZA=="
  let (invalidKeyHead, _) ← parseWhole .request invalidKeyText.toUTF8
  expectError "wrong nonce size" (validateClientRequest invalidKeyHead)
  let duplicateProtocols := requestWith
    "Sec-WebSocket-Protocol: chat, chat\r\n"
  let (duplicateHead, _) ← parseWhole .request duplicateProtocols.toUTF8
  expectError "duplicate request protocol" (validateClientRequest duplicateHead)
  let invalidTarget := (requestWith).replace "/chat?room=blue" "/<bad>"
  let (invalidTargetHead, _) ← parseWhole .request invalidTarget.toUTF8
  expectError "invalid origin target" (validateClientRequest invalidTargetHead)
  for (label, invalidAuthority) in #[
    ("Host with path", "example.com/path"),
    ("Host with trailing slash", "example.com/"),
    ("Host with empty query", "example.com?"),
    ("Host with path and empty query", "example.com/?")
  ] do
    let invalidHost := (requestWith).replace "server.example.com" invalidAuthority
    let (invalidHostHead, _) ← parseWhole .request invalidHost.toUTF8
    expectError label (validateClientRequest invalidHostHead)

  let validUpgrade := (requestWith).replace "Upgrade: websocket"
    "Upgrade: h2c/1, WebSocket"
  let (validUpgradeHead, _) ← parseWhole .request validUpgrade.toUTF8
  discard <| take "versioned alternate Upgrade token" (validateClientRequest validUpgradeHead)
  let invalidUpgrade := (requestWith).replace "Upgrade: websocket"
    "Upgrade: h2c//1, websocket"
  let (invalidUpgradeHead, _) ← parseWhole .request invalidUpgrade.toUTF8
  expectError "malformed alternate Upgrade token" (validateClientRequest invalidUpgradeHead)

  let mut extensionHeaders : Headers := #[]
  extensionHeaders ← take "extension header" <| extensionHeaders.insert
    "Sec-WebSocket-Extensions"
    "PERMESSAGE-DEFLATE; client_max_window_bits=\"12\"; server_no_context_takeover, x-test; p=value"
  let extensions ← take "extension grammar" (parseExtensions extensionHeaders)
  expect (extensions.size == 2 && extensions[0]!.name == "permessage-deflate" &&
    extensions[0]!.parameters.size == 2 && extensions[0]!.parameters[0]!.value? == some "12" &&
    extensions[0]!.parameters[0]!.quoted) "valid extension grammar decoded incorrectly"
  let serialized ← take "extension serialize" (serializeExtensions extensions)
  let roundtripHeaders ← take "roundtrip extension header"
    (Headers.empty.insert "sec-websocket-extensions" serialized)
  expect ((← take "extension roundtrip" (parseExtensions roundtripHeaders)) == extensions)
    "extension parse/serialize roundtrip differs"
  let extensionEmpties ← take "extension list empty members setup"
    (Headers.empty.insert "sec-websocket-extensions"
      ", permessage-deflate,,x-test; p=value,")
  expect ((← take "extension list empty members" (parseExtensions extensionEmpties)).size == 2)
    "empty members changed a valid extension list"
  for malformed in #[
    "permessage-deflate; =12",
    "permessage-deflate; p=",
    "permessage-deflate; p=\"unterminated",
    "permessage-deflate; p=\"has space\""
  ] do
    let malformedHeaders ← take "malformed extension setup"
      (Headers.empty.insert "sec-websocket-extensions" malformed)
    expectError s!"malformed extension {malformed}" (parseExtensions malformedHeaders)
  let onlyEmptyExtensions ← take "empty extensions setup"
    (Headers.empty.insert "sec-websocket-extensions" ", ,")
  expectError "extension field without an extension" (parseExtensions onlyEmptyExtensions)
  let onlyEmptyProtocols ← take "empty protocols setup"
    (Headers.empty.insert "sec-websocket-protocol" ", ,")
  expectError "subprotocol field without a subprotocol" (parseSubprotocols onlyEmptyProtocols)
  let manyProtocolNames := (List.range 4096).map fun index => s!"p{index}"
  let manyProtocolHeaders ← take "many protocols setup"
    (Headers.empty.insert "sec-websocket-protocol"
      (String.intercalate ", " manyProtocolNames))
  let manyProtocols ← take "many unique protocols" (parseSubprotocols manyProtocolHeaders)
  expect (manyProtocols.size == manyProtocolNames.length)
    "large subprotocol offer lost or duplicated values"

  let endpoint ← take "client endpoint" (Endpoint.parse "wss://server.example.com/chat")
  let chat ← take "chat protocol" (Subprotocol.parse "chat")
  let superchat ← take "superchat protocol" (Subprotocol.parse "superchat")
  let offer ← take "client offer" <| Http1.ClientOffer.create endpoint
    "the sample nonce".toUTF8 (subprotocols := #[chat, superchat])
    (extensions := extensions)
  let clientWire ← take "build client request" (buildClientRequest offer)
  let (builtClientHead, builtClientRemaining) ← parseWhole .request clientWire
  expect builtClientRemaining.isEmpty "built client request had unexplained bytes"
  let builtRequest ← take "validate built client request"
    (validateClientRequest builtClientHead)
  let serverWire ← take "build server response" <| buildServerResponse builtRequest {
    subprotocol? := some chat,
    extensions := extensions
  }
  let (builtServerHead, builtServerRemaining) ← parseWhole .response serverWire
  expect builtServerRemaining.isEmpty "built server response had unexplained bytes"
  let accepted ← take "validate built server response"
    (validateServerResponse offer builtServerHead)
  expect (accepted.subprotocol? == some chat && accepted.extensions == extensions)
    "validated server negotiation differs"
  let some serverText := String.fromUTF8? serverWire
    | throw (IO.userError "built server response was not UTF-8")
  let repeatedExtensionText := serverText.replace "\r\n\r\n"
    "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
  let (repeatedExtensionHead, _) ← parseWhole .response repeatedExtensionText.toUTF8
  expectError "repeated response extension field"
    (validateServerResponse offer repeatedExtensionHead)

  let emptyQueryEndpoint ← take "empty-query client endpoint"
    (Endpoint.parse "ws://server.example.com/?")
  let emptyQueryOffer ← take "empty-query client offer" <|
    Http1.ClientOffer.create emptyQueryEndpoint "the sample nonce".toUTF8
  let emptyQueryWire ← take "empty-query client request"
    (buildClientRequest emptyQueryOffer)
  let emptyQueryStart := "GET / HTTP/1.1\r\n".toUTF8
  expect (emptyQueryWire.extract 0 emptyQueryStart.size == emptyQueryStart)
    "empty query was not omitted from the HTTP/1 resource name"

  expectError "duplicate protocols in offer creation" <|
    Http1.ClientOffer.create endpoint "the sample nonce".toUTF8
      (subprotocols := #[chat, chat])
  expectError "duplicate protocols in forged offer build" <|
    buildClientRequest { offer with subprotocols := #[chat, chat] }
  expectError "non-ASCII Origin in offer creation" <|
    Http1.ClientOffer.create endpoint "the sample nonce".toUTF8
      (origin? := some "https://exämple.test")
  expectError "non-ASCII Origin in forged offer build" <|
    buildClientRequest { offer with origin? := some "https://exämple.test" }

  let wrongAccept := responseText.replace
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  let (wrongAcceptHead, _) ← parseWhole .response wrongAccept.toUTF8
  expectError "wrong server accept" (validateServerResponse offer wrongAcceptHead)
  let unofferedResponse := responseText.replace "\r\n\r\n"
    "\r\nSec-WebSocket-Protocol: other\r\n\r\n"
  let (unofferedHead, _) ← parseWhole .response unofferedResponse.toUTF8
  expectError "unoffered selected protocol" (validateServerResponse offer unofferedHead)
  let unofferedExtension := responseText.replace "\r\n\r\n"
    "\r\nSec-WebSocket-Extensions: not-offered\r\n\r\n"
  let (unofferedExtensionHead, _) ← parseWhole .response unofferedExtension.toUTF8
  expectError "unoffered selected extension"
    (validateServerResponse offer unofferedExtensionHead)
  let responseWithLength := responseText.replace "\r\n\r\n"
    "\r\nContent-Length: 0\r\n\r\n"
  let (responseWithLengthHead, _) ← parseWhole .response responseWithLength.toUTF8
  expectError "Content-Length on 101 response"
    (validateServerResponse offer responseWithLengthHead)

  IO.println "HTTP/1 handshake tests passed"
