import Ws.Client

open Std.Async
open Ws

def expect (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

def testEndpoint : IO Endpoint :=
  match Endpoint.parse "ws://no-network.invalid/socket" with
  | .ok endpoint => pure endpoint
  | .error error => throw (IO.userError error.message)

def cancelledConnect (config : Client.Config) : IO Client.Error := do
  let cancellation ← Std.CancellationToken.new
  cancellation.cancel
  let startedAt ← IO.monoMsNow
  let result ← Async.block (Client.connectAsyncWithCancellation config cancellation)
  let elapsed := (← IO.monoMsNow) - startedAt
  expect (elapsed < 200) "pre-cancelled connect performed opening work"
  match result with
  | .error error => pure error
  | .ok connected =>
      Connection.requestAbort connected.connection
      throw (IO.userError "pre-cancelled connect unexpectedly succeeded")

def cancellationPreflightTests : IO Unit := do
  let endpoint ← testEndpoint
  let error ← cancelledConnect { endpoint }
  expect (error.kind == .cancelled) "pre-cancelled connect returned the wrong error"

  let error ← cancelledConnect {
    endpoint,
    compression? := some { clientMaxWindowBits := .any }
  }
  expect (error.kind == .cancelled) "unvalued client_max_window_bits offer was rejected"

  let error ← cancelledConnect {
    endpoint,
    compression? := some { clientMaxWindowBits := .atMost 9 }
  }
  expect (error.kind == .cancelled) "9-bit client_max_window_bits offer was rejected"

  let cancellation ← Std.CancellationToken.new
  cancellation.cancel
  match ← Async.block (Client.connectAsyncWithCancellation {
      endpoint,
      compression? := some { clientMaxWindowBits := .atMost 8 }
    } cancellation) with
  | .error error =>
      expect (error.kind == .invalidArgument)
        "unsupported 8-bit compressor offer returned the wrong error"
  | .ok connected =>
      Connection.requestAbort connected.connection
      throw (IO.userError "unsupported 8-bit compressor offer succeeded")

def invalidConfigTests : IO Unit := do
  let endpoint ← testEndpoint
  match ← Client.connect { endpoint, openingTimeoutMs := 0 } with
  | .error error => expect (error.kind == .invalidArgument) "zero deadline was accepted"
  | .ok connected =>
      Connection.requestAbort connected.connection
      throw (IO.userError "zero deadline connected")
  match ← Client.connect {
      endpoint, connection := { incomingCapacity := 0 }
    } with
  | .error error =>
      expect (error.kind == .invalidArgument) "zero incoming capacity was accepted"
  | .ok connected =>
      Connection.requestAbort connected.connection
      throw (IO.userError "zero incoming capacity connected")

def main : IO Unit := do
  cancellationPreflightTests
  invalidConfigTests
  IO.println "client preflight tests passed"
