import Std.Async.TCP
import Ws.Server
import Ws.Transport.Plain

namespace Ws.Conformance.EchoServer

open Std
open Std.Async
open Std.Net

private def loopback (port : UInt16) : SocketAddress :=
  .v4 { addr := IPv4Addr.ofParts 127 0 0 1, port }

private inductive CompressionMode where
  | disabled
  | takeover
  | reset

private def compressionModeFromString (value : String) : IO CompressionMode :=
  match value with
  | "none" => pure .disabled
  | "takeover" => pure .takeover
  | "reset" => pure .reset
  | _ => throw (IO.userError "compression mode must be none, takeover, or reset")

private structure Options where
  port : UInt16 := 9001
  compression : CompressionMode := .takeover

private def optionsFromArgs (args : List String) : IO Options := do
  let port ← match args with
  | [] => pure 9001
  | value :: _ =>
      let some port := value.toNat?
        | throw (IO.userError s!"invalid port {value.quote}")
      if port == 0 || port > 65535 then
        throw (IO.userError "port must be between 1 and 65535")
      pure (UInt16.ofNat port)
  let mode ← match args.drop 1 with
  | [] => pure .takeover
  | value :: _ => compressionModeFromString value
  pure { port, compression := mode }

private def sendEcho (session : Server.Session) (message : Message.Message) : Async Unit := do
  match ← Connection.send session.connection message with
  | .ok _ => pure ()
  | .error error => throw (IO.userError s!"echo write failed: {error.message}")

private def echoApplication (session : Server.Session) : Async Unit := do
  let mut done := false
  while !done do
    match ← Connection.receive session.connection with
    | .ok (some (.message message)) =>
        sendEcho session message
    | .ok (some (.close _)) | .ok none => done := true
    | .ok (some (.ping _)) | .ok (some (.pong _)) => pure ()
    | .error error =>
        throw (IO.userError s!"echo receive failed: {error.message}")

private def policy (mode : CompressionMode) : Server.Policy := fun _ =>
  pure (.accept {
    compression := match mode with
    | .disabled => { enabled := false }
    | .takeover => { enabled := true }
    | .reset => {
        enabled := true
        serverNoContextTakeover := true
        clientNoContextTakeover := true
      }
  })

private def serverConfig : Server.Config := {
  connection := {
    limits := {
      maxFramePayloadBytes := 64 * 1024 * 1024
      maxMessagePayloadBytes := 64 * 1024 * 1024
      maxFragmentsPerMessage := 1024 * 1024
    }
    incomingCapacity := 64
    compressionThreshold := 0
    closeTimeoutMs := 3000
  }
  openingTimeoutMs := 10000
  openingWriteTimeoutMs := 5000
  retirementTimeoutMs := 500
}

private def serveOne (listener : TCP.Socket.Server) (options : Options) : Async Unit := do
  let client ← listener.accept
  let stream ← Transport.Plain.ofSocket client {
    readSize := 64 * 1024
    retireTimeoutMs := 500
  }
  match ← Server.handleHttp1 stream (policy options.compression)
      echoApplication serverConfig with
  | .ok _ => pure ()
  | .error error =>
      -- Invalid-wire cases intentionally end as protocol errors. Keep the
      -- listener available for the next independent test connection.
      if error.kind != .handshake && error.kind != .runtime && error.kind != .application then
        IO.eprintln s!"connection ended: {repr error.kind}: {error.message}"

private def serve (listener : TCP.Socket.Server) (options : Options) : IO Unit := do
  while true do
    Async.block (serveOne listener options)

end Ws.Conformance.EchoServer

def main (args : List String) : IO Unit := do
  let options ← Ws.Conformance.EchoServer.optionsFromArgs args
  let listener ← Std.Async.TCP.Socket.Server.mk
  listener.bind (Ws.Conformance.EchoServer.loopback options.port)
  listener.listen 128
  listener.noDelay
  IO.println s!"WebSocket conformance echo server listening on 127.0.0.1:{options.port}"
  (← IO.getStdout).flush
  Ws.Conformance.EchoServer.serve listener options
