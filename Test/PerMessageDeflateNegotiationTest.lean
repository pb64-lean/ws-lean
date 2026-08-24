import Ws.PerMessageDeflate.Negotiation

open Ws
open Ws.PerMessageDeflate

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def take {α} (label : String) : Except Ws.Error α → IO α
  | .ok value => pure value
  | .error error => throw (IO.userError s!"{label}: {error.message}")

def extensions (values : Array String) : IO (Array Extension) := do
  let mut headers : Headers := #[]
  for value in values do
    headers ← take "extension header" (headers.insert "sec-websocket-extensions" value)
  take "extension parse" (parseHeaders headers)

def expectError {α} (label : String) (result : Except Ws.Error α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

def main : IO Unit := do
  let offered ← extensions #[
    "PERMESSAGE-DEFLATE; server_no_context_takeover; client_no_context_takeover; " ++
      "server_max_window_bits=12; client_max_window_bits=\"11\""
  ]
  expect (offered.size == 1) "one offer should parse"
  let offer ← take "decode offer" (ClientOffer.ofExtension offered[0]!)
  expect (offer == {
    serverNoContextTakeover := true
    clientNoContextTakeover := true
    serverMaxWindowBits? := some 12
    clientMaxWindowBits := .atMost 11
  }) "complete offer decoded incorrectly"

  let encoded ← take "encode offer" offer.extensionValue
  expect (encoded == "permessage-deflate; server_no_context_takeover; " ++
    "client_no_context_takeover; server_max_window_bits=12; " ++
    "client_max_window_bits=11") "offer serialization is not canonical"

  let alternatives ← extensions #[
    "permessage-deflate; server_max_window_bits=8, " ++
      "permessage-deflate; server_max_window_bits=13; client_max_window_bits"
  ]
  let selected? ← take "server selection" (selectServer {
    enabled := true
    serverNoContextTakeover := true
    clientNoContextTakeover := true
    maxServerWindowBits := 11
    maxClientWindowBits := 10
  } alternatives)
  let some selected := selected?
    | throw (IO.userError "server should select the second compatible alternative")
  expect (selected.parameters == {
    serverNoContextTakeover := true
    clientNoContextTakeover := true
    serverMaxWindowBits := 11
    clientMaxWindowBits := 10
  }) "server chose incorrect parameters"
  expect (selected.responseValue == "permessage-deflate; server_no_context_takeover; " ++
    "client_no_context_takeover; server_max_window_bits=11; client_max_window_bits=10")
    "server response serialization is incorrect"

  let disabled ← take "disabled selection" (selectServer {} alternatives)
  expect disabled.isNone "disabled compression must decline every offer"

  let duplicate ← extensions #[
    "permessage-deflate; server_no_context_takeover; server_no_context_takeover"
  ]
  expectError "duplicate semantic parameter" (ClientOffer.ofExtension duplicate[0]!)
  let duplicateSelection ← take "decline duplicate" (selectServer { enabled := true } duplicate)
  expect duplicateSelection.isNone "server must decline a malformed alternative"

  let clientOffer : ClientOffer := {
    serverNoContextTakeover := false
    clientNoContextTakeover := true
    serverMaxWindowBits? := some 12
    clientMaxWindowBits := .atMost 11
  }
  let response ← extensions #[
    "permessage-deflate; server_no_context_takeover; client_no_context_takeover; " ++
      "server_max_window_bits=10; client_max_window_bits=9"
  ]
  let negotiated? ← take "validate response"
    (validateClientResponse clientOffer response)
  expect (negotiated? == some {
    serverNoContextTakeover := true
    clientNoContextTakeover := true
    serverMaxWindowBits := 10
    clientMaxWindowBits := 9
  }) "valid response decoded incorrectly"

  let unofferedClientNo ← extensions #[
    "permessage-deflate; client_no_context_takeover"
  ]
  let unofferedClientNoResult ← take "unsolicited client takeover constraint"
    (validateClientResponse {} unofferedClientNo)
  expect (unofferedClientNoResult.map (·.clientNoContextTakeover) == some true)
    "client must honor an unsolicited client_no_context_takeover response"

  let unofferedWindow ← extensions #[
    "permessage-deflate; server_max_window_bits=12"
  ]
  let unofferedWindowResult ← take "unsolicited server window"
    (validateClientResponse {} unofferedWindow)
  expect (unofferedWindowResult.map (·.serverMaxWindowBits) == some 12)
    "client must accept an unsolicited server_max_window_bits response"

  let unsafeClientWindow ← extensions #[
    "permessage-deflate; client_max_window_bits=8"
  ]
  expectError "unsupported compressor window"
    (validateClientResponse { clientMaxWindowBits := .any } unsafeClientWindow)

  let multiple ← extensions #["permessage-deflate, x-example"]
  expectError "multiple negotiated extensions"
    (validateClientResponse {} multiple)

  let omittedRestricted ← extensions #["permessage-deflate"]
  expectError "omitted server maximum"
    (validateClientResponse { serverMaxWindowBits? := some 12 } omittedRestricted)
  expectError "omitted explicit default server maximum"
    (validateClientResponse { serverMaxWindowBits? := some 15 } omittedRestricted)
  let omittedClientHint ← take "omitted client maximum"
    (validateClientResponse { clientMaxWindowBits := .atMost 12 } omittedRestricted)
  expect (omittedClientHint.map (·.clientMaxWindowBits) == some 12)
    "client window hint must remain effective when the response omits it"
  let loosenedClient ← extensions #["permessage-deflate; client_max_window_bits=15"]
  let loosenedClientResult ← take "loosened client maximum"
    (validateClientResponse { clientMaxWindowBits := .atMost 12 } loosenedClient)
  expect (loosenedClientResult.map (·.clientMaxWindowBits) == some 12)
    "client window hint must remain effective when the response is looser"

  let conservativeClient ← take "conservative client takeover policy"
    (validateClientResponse { clientNoContextTakeover := true } omittedRestricted)
  expect (conservativeClient.map (·.clientNoContextTakeover) == some true)
    "client should conservatively honor its takeover hint when omitted"
  expectError "server ignored takeover request"
    (validateClientResponse { serverNoContextTakeover := true } omittedRestricted)

  let leadingZero ← extensions #["permessage-deflate; server_max_window_bits=08"]
  expectError "leading-zero window" (ClientOffer.ofExtension leadingZero[0]!)

  let malformedHeaders : Headers ← take "malformed header setup"
    (Headers.empty.insert "sec-websocket-extensions" "permessage-deflate; =12")
  expectError "malformed extension grammar" (parseHeaders malformedHeaders)

  IO.println "permessage-deflate negotiation tests passed"
