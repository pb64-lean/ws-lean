import Ws.Http2.Handshake

open Ws
open Ws.Handshake

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def expectError {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def main : IO Unit := do
  let endpoint ← take "endpoint" (Endpoint.parse "wss://server.example/chat?room=blue")
  let chat ← take "chat subprotocol" (Subprotocol.parse "chat")
  let compression ← take "compression extension"
    (parseExtensionItem "permessage-deflate; client_max_window_bits".toUTF8)
  let offer ← take "client offer" <| Ws.Http2.Handshake.ClientOffer.create endpoint
    (subprotocols := #[chat]) (extensions := #[compression])
    (origin? := some "https://example.test")
  expectError "non-ASCII HTTP/2 Origin in offer creation" <|
    Ws.Http2.Handshake.ClientOffer.create endpoint
      (origin? := some "https://exämple.test")
  expectError "non-ASCII HTTP/2 Origin in forged offer build" <|
    Ws.Http2.Handshake.buildClientRequest {
      endpoint, origin? := some "https://exämple.test"
    }
  let request ← take "build request" (Ws.Http2.Handshake.buildClientRequest offer)
  expect (request.protocol == "websocket" && request.scheme == "https" &&
    request.authority == "server.example" && request.path == "/chat?room=blue")
    "extended CONNECT pseudo-fields differ"
  let serverRequest ← take "validate request" (Ws.Http2.Handshake.validateServerRequest request)
  expect (serverRequest.origin? == some "https://example.test" &&
    serverRequest.subprotocols == #[chat] && serverRequest.extensions == #[compression])
    "extended CONNECT request metadata differs"

  let response ← take "build response" <| Ws.Http2.Handshake.buildServerResponse serverRequest {
    subprotocol? := some chat
    extensions := #[compression]
  }
  expect (response.status == 200) "extended CONNECT acceptance did not use status 200"
  let accepted ← take "validate response" (Ws.Http2.Handshake.validateServerResponse offer response)
  expect (accepted.subprotocol? == some chat && accepted.extensions == #[compression])
    "extended CONNECT negotiation differs"

  expectError "wrong extended protocol"
    (Ws.Http2.Handshake.validateServerRequest { request with protocol := "not-websocket" })
  expectError "wrong extended scheme"
    (Ws.Http2.Handshake.validateServerRequest { request with scheme := "ws" })
  expectError "absolute-form extended path"
    (Ws.Http2.Handshake.validateServerRequest { request with path := "https://server.example/chat" })
  expectError "missing WebSocket version" <| Ws.Http2.Handshake.validateServerRequest {
    request with
    headers := request.headers.filter (·.name != "sec-websocket-version")
  }
  expectError "HTTP/1 field in extended request" <| Ws.Http2.Handshake.validateServerRequest {
    request with headers := request.headers.insert "connection" "upgrade"
  }

  expectError "non-success extended response"
    (Ws.Http2.Handshake.validateServerResponse offer { response with status := 403 })
  let alternateSuccess ← take "alternate success response"
    (Ws.Http2.Handshake.validateServerResponse offer { response with status := 204 })
  expect (alternateSuccess.subprotocol? == some chat)
    "a valid non-200 2xx extended response was rejected"
  expectError "HTTP/1 field in extended response" <| Ws.Http2.Handshake.validateServerResponse offer {
    response with headers := response.headers.insert "upgrade" "websocket"
  }
  expectError "repeated response extension field" <| Ws.Http2.Handshake.validateServerResponse offer {
    response with
    headers := response.headers.insert "sec-websocket-extensions"
      "permessage-deflate; client_max_window_bits=12"
  }

  let emptyEndpoint ← take "empty-query endpoint" (Endpoint.parse "ws://server.example/?")
  let emptyOffer ← take "empty-query offer"
    (Ws.Http2.Handshake.ClientOffer.create emptyEndpoint)
  let emptyRequest ← take "empty-query request"
    (Ws.Http2.Handshake.buildClientRequest emptyOffer)
  expect (emptyRequest.path == "/?")
    "empty query delimiter was not preserved in the extended CONNECT path"

  IO.println "HTTP/2 WebSocket handshake tests passed"
