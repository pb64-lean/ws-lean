import Ws.Client

namespace Ws.Conformance.LoadClient

open Std.Async

private inductive CompressionMode where
  | disabled
  | takeover
  | reset

private def modeFromString (value : String) : IO CompressionMode :=
  match value with
  | "none" => pure .disabled
  | "takeover" => pure .takeover
  | "reset" => pure .reset
  | _ => throw (IO.userError "compression mode must be none, takeover, or reset")

private def natArgument (label value : String) : IO Nat :=
  match value.toNat? with
  | some number => pure number
  | none => throw (IO.userError s!"invalid {label} {value.quote}")

private structure Options where
  mode : CompressionMode := .takeover
  messages : Nat := 1000
  payloadBytes : Nat := 16384
  connections : Nat := 1

private def optionsFromArgs (args : List String) : IO Options := do
  let mode ← match args with
  | value :: _ => modeFromString value
  | [] => pure .takeover
  let messages ← match args.drop 1 with
  | value :: _ => natArgument "message count" value
  | [] => pure 1000
  let payloadBytes ← match args.drop 2 with
  | value :: _ => natArgument "payload size" value
  | [] => pure 16384
  let connections ← match args.drop 3 with
  | value :: _ => natArgument "connection count" value
  | [] => pure 1
  pure { mode, messages, payloadBytes, connections }

private def payload (size : Nat) : IO ByteArray :=
  IO.getRandomBytes size.toUSize

private partial def receiveMessage (connection : Connection.Connection) : Async Message.Message := do
  match ← Connection.receive connection with
  | .ok (some (.message message)) => pure message
  | .ok (some (.ping _)) | .ok (some (.pong _)) => receiveMessage connection
  | .ok (some (.close _)) => throw (IO.userError "peer closed before echoing the message")
  | .ok none => throw (IO.userError "peer ended before echoing the message")
  | .error error => throw (IO.userError s!"receive failed: {error.message}")

private def exercise (connection : Connection.Connection) (data : ByteArray)
    (messages : Nat) : Async Unit := do
  for index in [0:messages] do
    match ← Connection.sendBinary connection data with
    | .error error => throw (IO.userError s!"send failed: {error.message}")
    | .ok _ => pure ()
    let echoed ← receiveMessage connection
    unless echoed.kind == .binary && echoed.data == data do
      throw (IO.userError s!"echo mismatch at message {index}")

private def offer : CompressionMode → Option PerMessageDeflate.ClientOffer
  | .disabled => none
  | .takeover => some {}
  | .reset => some {
      serverNoContextTakeover := true
      clientNoContextTakeover := true
    }

private def runConnection (endpoint : Endpoint) (options : Options)
    (data : ByteArray) : IO Unit := do
  let connected ← match ← Client.connect {
      endpoint
      versionPolicy := .http1Only
      compression? := offer options.mode
      connection := {
        fragmentSize := 256
        compressionThreshold := 0
        incomingCapacity := 64
      }
    } with
  | .ok connected => pure connected
  | .error error => throw (IO.userError s!"connect failed: {error.message}")
  Async.block (exercise connected.connection data options.messages)
  match ← Async.block (Connection.close connected.connection) with
  | .ok _ => pure ()
  | .error error => throw (IO.userError s!"close failed: {error.message}")

end Ws.Conformance.LoadClient

def main (args : List String) : IO Unit := do
  let options ← Ws.Conformance.LoadClient.optionsFromArgs args
  let endpoint ← match Ws.Endpoint.parse "ws://127.0.0.1:9001/" with
  | .ok endpoint => pure endpoint
  | .error error => throw (IO.userError error.message)
  let data ← Ws.Conformance.LoadClient.payload options.payloadBytes
  for _ in [0:options.connections] do
    Ws.Conformance.LoadClient.runConnection endpoint options data
  IO.println (s!"completed {options.connections} connection(s), " ++
    s!"{options.messages} message(s) each, {options.payloadBytes} payload bytes")
