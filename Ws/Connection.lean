module

public import Std.Async.Timer
public import Std.Sync.Channel
public import Std.Sync.Mutex
public import Ws.Message
public import Ws.PerMessageDeflate.Session
public import Ws.Transport.ByteStream

public section

namespace Ws

open Std.Async

namespace Connection

inductive SendErrorKind where
  | closed
  | invalidArgument
  | protocol
  | compression
  | transport
  | timeout
  | cancelled
  deriving Inhabited, Repr, BEq, DecidableEq

structure SendError where
  kind : SendErrorKind
  message : String
  deriving Inhabited, Repr, BEq, DecidableEq

inductive ReceiveErrorKind where
  | protocol
  | compression
  | transport
  | backpressure
  | timeout
  | cancelled
  deriving Inhabited, Repr, BEq, DecidableEq

structure ReceiveError where
  kind : ReceiveErrorKind
  message : String
  closeCode? : Option CloseCode := none
  deriving Inhabited, Repr, DecidableEq

inductive TerminationKind where
  | clean
  | endOfStream
  | protocolError
  | transportError
  | timeout
  | aborted
  deriving Inhabited, Repr, BEq, DecidableEq

structure Termination where
  kind : TerminationKind
  localClose? : Option Message.Close := none
  peerClose? : Option Message.Close := none
  detail? : Option String := none
  deriving Inhabited

structure Config where
  limits : Limits := {}
  fragmentSize : Nat := 64 * 1024
  incomingCapacity : Nat := 64
  compressionThreshold : Nat := 1024
  compressByDefault : Bool := true
  closeTimeoutMs : Nat := 5000
  retireTimeoutMs : Nat := 200
  deriving Inhabited, Repr

structure SendOptions where
  compress? : Option Bool := none
  deriving Inhabited, Repr, BEq, DecidableEq

private inductive Phase where
  | open
  | closeQueued
  | closeSent
  | terminal
  deriving Inhabited, BEq

private structure State where
  phase : Phase := .open
  localClose? : Option Message.Close := none
  peerClose? : Option Message.Close := none
  abortRequested : Bool := false
  closeTimedOut : Bool := false
  terminalReceiveError? : Option ReceiveError := none

private inductive WriteOperation where
  | message (message : Message.Message) (compress : Bool)
  | ping (payload : ByteArray)
  | pong (payload : ByteArray)
  | close (value : Message.Close)

private structure WriteRequest where
  operation : WriteOperation
  completion : IO.Promise (Except SendError Unit)

private structure Runtime where
  role : Role
  stream : Transport.ByteStream
  config : Config
  compression? : Option PerMessageDeflate.Session
  state : Std.Mutex State
  admission : Std.CloseableChannel Unit
  outbound : Std.CloseableChannel WriteRequest
  controlAdmission : Std.CloseableChannel Unit
  control : Std.CloseableChannel WriteRequest
  closeStarted : IO.Promise Unit
  closeFinished : IO.Promise Unit
  closeWritten : IO.Promise (Except SendError Unit)
  abortStarted : IO.Promise Unit
  terminal : IO.Promise Termination
  incoming : Std.CloseableChannel Message.Event

private inductive ReaderResult where
  | clean
  | endOfStream
  | failed (error : ReceiveError)
  | aborted

private inductive WriterResult where
  | stopped
  | failed (error : SendError)
  | aborted

structure Connection where
  private runtime : Runtime
  private deadline : AsyncTask Unit
  private abortSignal : AsyncTask Unit
  private reader : AsyncTask ReaderResult
  private writer : AsyncTask WriterResult
  private owner : AsyncTask Termination

def role (connection : Connection) : Role := connection.runtime.role

def version (connection : Connection) : Transport.Version :=
  connection.runtime.stream.version

private def sendErrorOfProtocol (error : Error) : SendError :=
  { kind := if error.kind == .invalidArgument then .invalidArgument else .protocol,
    message := error.message }

private def receiveErrorOfProtocol (error : Error) : ReceiveError :=
  { kind := .protocol, message := error.message, closeCode? := error.closeCode? }

private def receiveErrorOfCompression (error : PerMessageDeflate.Raw.Error) : ReceiveError :=
  match error with
  | .outputLimit =>
      { kind := .compression, message := toString error,
        closeCode? := some .messageTooBig }
  | .corruptData =>
      { kind := .compression, message := toString error,
        closeCode? := some .protocolError }
  | .invalidWindow | .outOfMemory | .closed | .backend =>
      { kind := ReceiveErrorKind.compression
        message := toString error
        closeCode? := some CloseCode.internalError }

private def sendErrorOfCompression (error : PerMessageDeflate.Raw.Error) : SendError :=
  { kind := .compression, message := toString error }

private def sendErrorOfTransport (error : Transport.Failure) : SendError :=
  { kind := .transport, message := error.message }

private def receiveErrorOfTransport (error : Transport.Failure) : ReceiveError :=
  { kind := if error.kind == .cancelled then .cancelled else .transport,
    message := error.message }

private def closeChannel (channel : Std.CloseableChannel α) : BaseIO Unit := do
  discard <| channel.close.toBaseIO

private def releaseAdmission (runtime : Runtime) : BaseIO Unit := do
  discard <| runtime.admission.trySend ()

private def releaseControlAdmission (runtime : Runtime) : BaseIO Unit := do
  discard <| runtime.controlAdmission.trySend ()

private inductive AdmissionResult where
  | acquired
  | closed
  | cancelled

private def submissionCancelled
    (cancellation? : Option Std.CancellationToken) : BaseIO Bool := do
  if ← IO.checkCanceled then return true
  if let some cancellation := cancellation? then
    if ← cancellation.isCancelled then return true
  pure false

private partial def acquireAdmissionIO (channel : Std.CloseableChannel Unit)
    (cancellation? : Option Std.CancellationToken := none) : IO AdmissionResult := do
  if ← submissionCancelled cancellation? then return .cancelled
  match ← channel.tryRecv with
  | some _ => pure .acquired
  | none =>
      if ← channel.isClosed then pure .closed
      else
        IO.sleep 1
        acquireAdmissionIO channel cancellation?

private def terminalSendError (termination : Termination) : SendError :=
  match termination.kind with
  | .timeout => {
      kind := .timeout,
      message := termination.detail?.getD "WebSocket operation timed out" }
  | .aborted => {
      kind := .cancelled,
      message := termination.detail?.getD "WebSocket connection was aborted" }
  | _ => {
      kind := .closed,
      message := termination.detail?.getD "WebSocket connection is closed" }

private partial def awaitCompletion (runtime : Runtime)
    (promise : IO.Promise (Except SendError Unit)) :
    Async (Except SendError Unit) := do
  if ← IO.hasFinished promise.result? then
    match ← Async.ofTask promise.result? with
    | some result => pure result
    | none => pure (.error {
        kind := .cancelled, message := "write completion was dropped" })
  else if ← IO.hasFinished runtime.terminal.result? then
    match ← Async.ofTask runtime.terminal.result? with
    | some termination => pure (.error (terminalSendError termination))
    | none => pure (.error {
        kind := .cancelled, message := "connection termination was dropped" })
  else
    -- At most the bounded admission set can poll here. Avoid registering a
    -- losing callback on the connection-long terminal promise for every send.
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 1)
    awaitCompletion runtime promise

private partial def awaitCompletionIO (runtime : Runtime)
    (promise : IO.Promise (Except SendError Unit)) :
    IO (Except SendError Unit) := do
  if ← IO.checkCanceled then
    return .error {
      kind := .cancelled, message := "WebSocket write observation was cancelled" }
  if ← IO.hasFinished promise.result? then
    match promise.result?.get with
    | some result => pure result
    | none => pure (.error {
        kind := .cancelled, message := "write completion was dropped" })
  else if ← IO.hasFinished runtime.terminal.result? then
    match runtime.terminal.result?.get with
    | some termination => pure (.error (terminalSendError termination))
    | none => pure (.error {
        kind := .cancelled, message := "connection termination was dropped" })
  else
    IO.sleep 1
    awaitCompletionIO runtime promise

private def submitClaimed (runtime : Runtime) (operation : WriteOperation) :
    Async (Except SendError Unit) := do
  let completion ← IO.Promise.new
  let request : WriteRequest := { operation, completion }
  if ← runtime.outbound.trySend request then
    awaitCompletion runtime completion
  else
    releaseAdmission runtime
    pure (.error { kind := .closed, message := "WebSocket writer is closed" })

private def submitControlClaimed (runtime : Runtime) (operation : WriteOperation) :
    Async (Except SendError Unit) := do
  let completion ← IO.Promise.new
  let request : WriteRequest := { operation, completion }
  if ← runtime.control.trySend request then
    awaitCompletion runtime completion
  else
    unless operation matches .close _ do releaseControlAdmission runtime
    pure (.error { kind := .closed, message := "WebSocket writer is closed" })

private def submitDataOpenIO (runtime : Runtime) (operation : WriteOperation)
    (cancellation? : Option Std.CancellationToken) : IO (Except SendError Unit) := do
  match ← acquireAdmissionIO runtime.admission cancellation? with
  | .cancelled => pure (.error {
      kind := .cancelled, message := "WebSocket data admission was cancelled" })
  | .closed =>
      pure (.error { kind := .closed, message := "WebSocket connection is closed" })
  | .acquired =>
      let transferred ← IO.mkRef false
      try
        if ← submissionCancelled cancellation? then
          releaseAdmission runtime
          return .error {
            kind := .cancelled, message := "WebSocket data admission was cancelled" }
        let allowed ← runtime.state.atomically do
          pure ((← get).phase == .open)
        if !allowed then
          releaseAdmission runtime
          pure (.error {
            kind := .closed, message := "WebSocket close handshake has started" })
        else if ← submissionCancelled cancellation? then
          releaseAdmission runtime
          pure (.error {
            kind := .cancelled, message := "WebSocket data admission was cancelled" })
        else
          let completion ← IO.Promise.new
          let request : WriteRequest := { operation, completion }
          if ← runtime.outbound.trySend request then
            -- The writer now owns permit release, request execution, and
            -- completion resolution. Forced caller cancellation retires only
            -- this exact polling observer; it cannot retract the request.
            transferred.set true
            awaitCompletionIO runtime completion
          else
            releaseAdmission runtime
            pure (.error { kind := .closed, message := "WebSocket writer is closed" })
      catch error =>
        unless ← transferred.get do releaseAdmission runtime
        throw error

private def submitControlOpenIO (runtime : Runtime) (operation : WriteOperation)
    (cancellation? : Option Std.CancellationToken) : IO (Except SendError Unit) := do
  match ← acquireAdmissionIO runtime.controlAdmission cancellation? with
  | .cancelled => pure (.error {
      kind := .cancelled, message := "WebSocket control admission was cancelled" })
  | .closed =>
      pure (.error { kind := .closed, message := "WebSocket connection is closed" })
  | .acquired =>
      let transferred ← IO.mkRef false
      try
        if ← submissionCancelled cancellation? then
          releaseControlAdmission runtime
          return .error {
            kind := .cancelled, message := "WebSocket control admission was cancelled" }
        let allowed ← runtime.state.atomically do pure ((← get).phase == .open)
        if !allowed then
          releaseControlAdmission runtime
          pure (.error {
            kind := .closed, message := "WebSocket close handshake has started" })
        else if ← submissionCancelled cancellation? then
          releaseControlAdmission runtime
          pure (.error {
            kind := .cancelled, message := "WebSocket control admission was cancelled" })
        else
          let completion ← IO.Promise.new
          let request : WriteRequest := { operation, completion }
          if ← runtime.control.trySend request then
            transferred.set true
            awaitCompletionIO runtime completion
          else
            releaseControlAdmission runtime
            pure (.error { kind := .closed, message := "WebSocket writer is closed" })
      catch error =>
        unless ← transferred.get do releaseControlAdmission runtime
        throw error

private def submitOpenIO (runtime : Runtime) (operation : WriteOperation)
    (cancellation? : Option Std.CancellationToken) : IO (Except SendError Unit) :=
  match operation with
  | .message .. => submitDataOpenIO runtime operation cancellation?
  | _ => submitControlOpenIO runtime operation cancellation?

/-- Spawn an IO polling action as the exact task exposed by an `Async` value.
This keeps forced cancellation attached to the worker that owns its polling
state; there is no dependent continuation or cancellation watcher to retire. -/
private def exactIOWorker (action : IO α) : Async α := do
  let task ← IO.asTask action
  Async.ofAsyncTask task

private def submitOpen (runtime : Runtime) (operation : WriteOperation)
    (cancellation? : Option Std.CancellationToken := none) :
    Async (Except SendError Unit) :=
  exactIOWorker (submitOpenIO runtime operation cancellation?)

private def signalCloseStarted (runtime : Runtime) : BaseIO Unit := do
  discard <| runtime.closeStarted.resolve ()

private def signalCloseWritten (runtime : Runtime) (result : Except SendError Unit) : BaseIO Unit := do
  discard <| runtime.closeWritten.resolve result

private def closeResult (runtime : Runtime) (result : Except SendError Unit) :
    BaseIO (Except SendError Unit) := do
  let timedOut ← runtime.state.atomically do pure (← get).closeTimedOut
  if timedOut then
    pure (.error { kind := .timeout, message := "WebSocket close handshake timed out" })
  else pure result

private inductive CloseSubmission where
  | send
  | awaitQueued
  | alreadySent

private def submitClose (runtime : Runtime) (value : Message.Close)
    (cancellation? : Option Std.CancellationToken := none) :
    Async (Except SendError Unit) := do
  if let some cancellation := cancellation? then
    if ← cancellation.isCancelled then
      return .error {
        kind := .cancelled, message := "WebSocket Close admission was cancelled" }
  let submission ← runtime.state.atomically do
    let state ← get
    if state.phase == .open then
      set { state with phase := .closeQueued, localClose? := some value }
      pure CloseSubmission.send
    else if state.phase == .closeQueued then
      pure CloseSubmission.awaitQueued
    else pure CloseSubmission.alreadySent
  match submission with
  | .alreadySent => pure (.ok ())
  | .awaitQueued =>
      match ← Async.ofTask runtime.closeWritten.result? with
      | some result => closeResult runtime result
      | none => pure (.error {
          kind := .cancelled, message := "queued Close completion was dropped" })
  | .send =>
    signalCloseStarted runtime
    closeResult runtime (← submitControlClaimed runtime (.close value))

private def submitForcedClose (runtime : Runtime) (value : Message.Close) :
    Async (Except SendError Unit) := do
  closeResult runtime (← submitControlClaimed runtime (.close value))

private def randomMaskKey : IO UInt32 := do
  let bytes ← IO.getRandomBytes 4
  pure <| bytes[0]!.toUInt32 <<< 24 ||| bytes[1]!.toUInt32 <<< 16 |||
    bytes[2]!.toUInt32 <<< 8 ||| bytes[3]!.toUInt32

private def sendFrame (runtime : Runtime) (frame : Frame.Frame) :
    Async (Except SendError Unit) := do
  let maskKey? ← if runtime.role.masksOutbound then some <$> randomMaskKey else pure none
  let encoded ← match Frame.encode runtime.role maskKey? frame with
    | .ok bytes => pure bytes
    | .error error => return .error (sendErrorOfProtocol error)
  match ← runtime.stream.send encoded with
  | .ok _ => pure (.ok ())
  | .error error => pure (.error (sendErrorOfTransport error))

private def resolveWrite (request : WriteRequest) (result : Except SendError Unit) :
    BaseIO Unit := do
  discard <| request.completion.resolve result

private def executeControlWrite (runtime : Runtime) (operation : WriteOperation) :
    Async (Except SendError Unit) :=
  match operation with
  | .ping payload => sendFrame runtime { opcode := .ping, payload }
  | .pong payload => sendFrame runtime { opcode := .pong, payload }
  | .close value =>
      match Message.Close.payload runtime.role value with
      | .error error => pure (.error (sendErrorOfProtocol error))
      | .ok payload => sendFrame runtime { opcode := .close, payload }
  | .message .. => pure (.error {
      kind := .protocol, message := "data request appeared on the control queue" })

private def markCloseSent (runtime : Runtime) : BaseIO Unit :=
  runtime.state.atomically do
    modify fun state => { state with phase := .closeSent }

private def bestEffortInternalClose (runtime : Runtime) : Async Unit := do
  let value := (Message.Close.create runtime.role (some CloseCode.internalError) "").toOption
  let some value := value | pure ()
  let shouldSend ← runtime.state.atomically do
    let state ← get
    if state.phase == .open then
      set { state with phase := .closeQueued, localClose? := some value }
      pure true
    else pure false
  if shouldSend then
    signalCloseStarted runtime
    if let .ok payload := Message.Close.payload runtime.role value then
      match ← sendFrame runtime { opcode := .close, payload } with
      | .ok _ => markCloseSent runtime
      | .error _ => pure ()

private partial def servicePendingControls (runtime : Runtime) :
    Async (Except SendError Bool) := do
  let some request ← runtime.control.tryRecv | pure (.ok false)
  unless request.operation matches .close _ do
    releaseControlAdmission runtime
    let allowed ← runtime.state.atomically do pure ((← get).phase == .open)
    if !allowed then
      resolveWrite request (.error {
        kind := .closed, message := "WebSocket close handshake has started" })
      return ← servicePendingControls runtime
  let result ← try executeControlWrite runtime request.operation catch error =>
    resolveWrite request (.error {
      kind := .cancelled, message := "WebSocket control write was cancelled" })
    throw error
  if result.isOk then
    match request.operation with
    | .close _ => markCloseSent runtime
    | _ => pure ()
  match request.operation with
  | .close _ => signalCloseWritten runtime result
  | _ => pure ()
  resolveWrite request result
  match result with
  | .error error => pure (.error error)
  | .ok _ =>
      match request.operation with
      | .close _ =>
          pure (.ok true)
      | _ => servicePendingControls runtime

private def sendAutomaticPong (runtime : Runtime) (payload : ByteArray) :
    Async (Except SendError Unit) := do
  let token? ← await (← runtime.controlAdmission.recv)
  if token?.isNone then
    pure (.error { kind := .closed, message := "WebSocket writer is closed" })
  else
    let allowed ← runtime.state.atomically do
      let state ← get
      pure (state.phase != .terminal && state.peerClose?.isNone)
    if !allowed then
      releaseControlAdmission runtime
      pure (.ok ())
    else
      submitControlClaimed runtime (.pong payload)

private inductive DataWriteResult where
  | sent
  | interruptedByClose
  | failed (error : SendError)

private def sendData (runtime : Runtime) (message : Message.Message) (compress : Bool) :
    Async DataWriteResult := do
  let (payload, compressed) ← if compress then
      match runtime.compression? with
      | none => return .failed {
          kind := .invalidArgument, message := "permessage-deflate was not negotiated" }
      | some session =>
          -- The native compressor is transactional: output-limit leaves its
          -- takeover dictionary untouched, so expansion can safely fall back
          -- to the original message.
          let fragmentBound := runtime.config.fragmentSize *
            runtime.config.limits.maxFragmentsPerMessage
          match ← session.compress message.data
              (min message.data.size (min fragmentBound
                runtime.config.limits.maxMessagePayloadBytes)).toUInt64 with
          | .ok payload => pure (payload, true)
          | .error .outputLimit => pure (message.data, false)
          | .error error => return .failed (sendErrorOfCompression error)
    else
      pure (message.data, false)
  let fragmentSize := runtime.config.fragmentSize
  let count := if payload.isEmpty then 1 else (payload.size + fragmentSize - 1) / fragmentSize
  if count > runtime.config.limits.maxFragmentsPerMessage then
    return .failed {
      kind := .invalidArgument, message := "message exceeds configured fragment limit" }
  for index in [0:count] do
    match ← servicePendingControls runtime with
    | .error error => return .failed error
    | .ok true => return .interruptedByClose
    | .ok false => pure ()
    let start := index * fragmentSize
    let stop := min payload.size (start + fragmentSize)
    let opcode := if index == 0 then
        match message.kind with
        | .text => Frame.Opcode.text
        | .binary => Frame.Opcode.binary
      else
        Frame.Opcode.continuation
    let frame : Frame.Frame := {
      fin := index + 1 == count
      rsv1 := compressed && index == 0
      opcode
      payload := payload.extract start stop
    }
    match ← sendFrame runtime frame with
    | .ok _ => pure ()
    | .error error => return .failed error
  pure .sent

private inductive NextWrite where
  | data (request? : Option WriteRequest)
  | control (request? : Option WriteRequest)

private def nextWrite (runtime : Runtime) : Async NextWrite := do
  match ← runtime.control.tryRecv with
  | some request => pure (.control (some request))
  | none =>
      Selectable.one #[
        Selectable.case runtime.control.recvSelector fun request => pure (.control request),
        Selectable.case runtime.outbound.recvSelector fun request => pure (.data request)
      ]

private partial def writerLoop (runtime : Runtime) : Async WriterResult := do
  match ← nextWrite runtime with
  | .data none | .control none =>
      if ← runtime.state.atomically do pure (← get).abortRequested then
        pure .aborted
      else
        pure .stopped
  | .control (some request) =>
      unless request.operation matches .close _ do
        releaseControlAdmission runtime
        let allowed ← runtime.state.atomically do pure ((← get).phase == .open)
        if !allowed then
          resolveWrite request (.error {
            kind := .closed, message := "WebSocket close handshake has started" })
          return ← writerLoop runtime
      let result ← try executeControlWrite runtime request.operation catch error =>
        resolveWrite request (.error {
          kind := .cancelled, message := "WebSocket control write was cancelled" })
        throw error
      if result.isOk then
        match request.operation with
        | .close _ => markCloseSent runtime
        | _ => pure ()
      match request.operation with
      | .close _ => signalCloseWritten runtime result
      | _ => pure ()
      resolveWrite request result
      match result with
      | .error error =>
          if error.kind == .invalidArgument then writerLoop runtime
          else pure (.failed error)
      | .ok _ =>
          match request.operation with
          | .close _ => writerLoop runtime
          | _ => writerLoop runtime
  | .data (some request) =>
      releaseAdmission runtime
      match request.operation with
      | .message message compress =>
          let isOpen ← runtime.state.atomically do pure ((← get).phase == .open)
          if !isOpen then
            resolveWrite request (.error {
              kind := .closed, message := "WebSocket close handshake has started" })
            return ← writerLoop runtime
          let dataResult ← try sendData runtime message compress catch error =>
            resolveWrite request (.error {
              kind := .cancelled, message := "WebSocket data write was cancelled" })
            throw error
          match dataResult with
          | .sent =>
              resolveWrite request (.ok ())
              writerLoop runtime
          | .interruptedByClose =>
              resolveWrite request (.error {
                kind := .closed, message := "message interrupted by WebSocket Close" })
              writerLoop runtime
          | .failed error =>
              if error.kind == .compression then
                try bestEffortInternalClose runtime catch exception =>
                  resolveWrite request (.error {
                    kind := .cancelled, message := "WebSocket failure Close was cancelled" })
                  throw exception
              resolveWrite request (.error error)
              if error.kind == .invalidArgument then writerLoop runtime
              else pure (.failed error)
      | _ =>
          let error : SendError := {
            kind := .protocol, message := "control request appeared on the data queue" }
          resolveWrite request (.error error)
          pure (.failed error)

private def deliver (runtime : Runtime) (event : Message.Event) :
    Async (Except ReceiveError Unit) := do
  if ← runtime.incoming.trySend event then
    pure (.ok ())
  else
    pure (.error {
      kind := .backpressure,
      message := "WebSocket incoming event capacity was exhausted",
      closeCode? := some .policyViolation })

private def inflateMessage (runtime : Runtime) (message : Message.Message) :
    IO (Except ReceiveError Message.Message) := do
  if !message.compressed then
    pure (.ok message)
  else
    let some session := runtime.compression?
      | pure (.error {
          kind := .protocol, message := "compressed message without negotiated extension",
          closeCode? := some .protocolError })
    match ← session.decompress message.data
        runtime.config.limits.maxMessagePayloadBytes.toUInt64 with
    | .error error => pure (.error (receiveErrorOfCompression error))
    | .ok data =>
        if message.kind == .text then
          match Utf8.validate data with
          | .error error => pure (.error (receiveErrorOfProtocol error))
          | .ok _ => pure (.ok { message with data, compressed := false })
        else
          pure (.ok { message with data, compressed := false })

private inductive PeerCloseAction where
  | reply
  | awaitQueued
  | none

private def notePeerClose (runtime : Runtime) (value replyValue : Message.Close) :
    BaseIO PeerCloseAction :=
  runtime.state.atomically do
    let state ← get
    let action := if state.localClose?.isNone && state.phase == .open then
        PeerCloseAction.reply
      else if state.phase == .closeQueued then
        PeerCloseAction.awaitQueued
      else
        PeerCloseAction.none
    set {
      state with
      peerClose? := some value
      phase := if action matches .reply then .closeQueued else state.phase
      localClose? := if action matches .reply then some replyValue else state.localClose?
    }
    pure action

private def processEvent (runtime : Runtime) (event : Message.Event) :
    Async (Except ReceiveError Bool) := do
  match event with
  | .message _ => pure (.ok true)
  | .ping payload =>
      match ← sendAutomaticPong runtime payload with
      | .error error => pure (.error {
          kind := if error.kind == .timeout then .timeout else .transport,
          message := s!"automatic Pong failed: {error.message}" })
      | .ok _ => pure (.ok true)
  | .pong _ => pure (.ok true)
  | .close value =>
      let replyValue := match Message.Close.create runtime.role value.code? value.reason with
        | .ok close => close
        | .error _ => (Message.Close.create runtime.role (some .normalClosure) "").toOption.get!
      let action ← notePeerClose runtime value replyValue
      match action with
      | .reply =>
        signalCloseStarted runtime
        match ← submitForcedClose runtime replyValue with
        | .error error => return .error {
            kind := if error.kind == .timeout then .timeout else .transport,
            message := s!"Close response failed: {error.message}" }
        | .ok _ => pure ()
      | .awaitQueued =>
        match ← Async.ofTask runtime.closeWritten.result? with
        | some (.ok _) => pure ()
        | some (.error error) => return .error {
            kind := if error.kind == .timeout then .timeout else .transport,
            message := s!"queued Close failed: {error.message}" }
        | none => return .error {
            kind := .cancelled, message := "queued Close completion was dropped" }
      | .none => pure ()
      pure (.ok false)

private def failReader (runtime : Runtime) (error : ReceiveError) : Async ReaderResult := do
  if let some code := error.closeCode? then
    if let .ok close := Message.Close.create runtime.role (some code) "" then
      -- `submitClose` resolves only after the sole writer has put the Close on
      -- the transport. Failure handling may then abort without dropping the
      -- protocol-mandated best-effort Close frame.
      discard <| submitClose runtime close
  pure (.failed error)

private def failProtocolAfterPublishedData (runtime : Runtime) (error : Error)
    (publishedData : Bool) : Async ReaderResult := do
  if publishedData then
    -- Preserve wire order across the application boundary as well as the
    -- parser boundary. Give an already-published message a bounded handoff
    -- before the failure Close takes ownership of the writer.
    Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat 5)
  failReader runtime (receiveErrorOfProtocol error)

private partial def readerLoop (runtime : Runtime) (frameDecoder : Frame.Decoder)
    (messageDecoder : Message.Decoder) (publishedData : Bool := false) : Async ReaderResult := do
  match ← runtime.stream.recv? with
  | .error error => pure (.failed (receiveErrorOfTransport error))
  | .ok none =>
      let peerClose? ← runtime.state.atomically do pure (← get).peerClose?
      if peerClose?.isSome then pure .clean else pure .endOfStream
  | .ok (some chunk) =>
      let batch := frameDecoder.feedBatch chunk
      let frameDecoder := batch.decoder
      let mut decoder := messageDecoder
      let mut publishedData := publishedData
      for frame in batch.frames do
        let (next, events) ← match decoder.feed frame with
          | .ok result => pure result
          | .error error =>
              return ← failProtocolAfterPublishedData runtime error publishedData
        decoder := next
        for event in events do
          match event with
          | .message message =>
              let observable ← match ← inflateMessage runtime message with
                | .error error => return ← failReader runtime error
                | .ok message => pure (.message message)
              match ← deliver runtime observable with
              | .ok _ => publishedData := true
              | .error error => return ← failReader runtime error
          | .ping payload =>
              -- Protocol control is serviced before application publication,
              -- so a full incoming queue cannot suppress the mandatory Pong.
              match ← sendAutomaticPong runtime payload with
              | .ok _ => pure ()
              | .error error => return ← failReader runtime {
                  kind := if error.kind == .timeout then .timeout else .transport,
                  message := s!"automatic Pong failed: {error.message}" }
              match ← deliver runtime event with
              | .ok _ => pure ()
              | .error error => return ← failReader runtime error
          | .pong _ =>
              match ← deliver runtime event with
              | .ok _ => pure ()
              | .error error => return ← failReader runtime error
          | .close _ =>
              -- Stop Message-level decoding at the peer Close. In particular,
              -- data following Close in the same transport chunk cannot
              -- replace the exact Close reply with a later protocol error.
              match ← processEvent runtime event with
              | .error error => return ← failReader runtime error
              | .ok _ => pure ()
              -- A peer Close is terminal protocol state. Publish it when room
              -- remains, but never let application backpressure prevent the
              -- reply or turn a completed handshake into another failure.
              discard <| runtime.incoming.trySend event
              return .clean
      if let some error := batch.error? then
        return ← failProtocolAfterPublishedData runtime error publishedData
      readerLoop runtime frameDecoder decoder publishedData

private def ownedReader (runtime : Runtime) : Async ReaderResult :=
  try
    readerLoop runtime
      (Frame.Decoder.new runtime.role runtime.config.limits runtime.compression?.isSome
        (validateTextPayload := true))
      (Message.Decoder.new runtime.role runtime.config.limits)
  catch error =>
    if ← runtime.state.atomically do pure (← get).abortRequested then
      pure .aborted
    else
      pure (.failed { kind := .transport, message := toString error })

private def ownedWriter (runtime : Runtime) : Async WriterResult :=
  try writerLoop runtime catch error =>
    if ← runtime.state.atomically do pure (← get).abortRequested then
      pure .aborted
    else
      pure (.failed { kind := .transport, message := toString error })

private def asyncTaskSelector (task : AsyncTask α) : Selector α := {
  tryFn := do
    if ← IO.hasFinished task then some <$> Async.ofAsyncTask task else pure none
  registerFn := fun waiter => do
    discard <| IO.mapTask (t := task) (sync := true) fun result =>
      waiter.race (pure ()) fun promise => promise.resolve result
  unregisterFn := pure ()
}

private inductive FirstResult where
  | reader (result : ReaderResult)
  | writer (result : WriterResult)
  | deadline
  | abort

private def sleepMs (milliseconds : Nat) : Async Unit :=
  Std.Async.sleep (Std.Time.Millisecond.Offset.ofNat milliseconds)

private partial def awaitTaskWithin (task : AsyncTask α) (remainingMs : Nat) : Async Bool := do
  if ← IO.hasFinished task then
    pure true
  else if remainingMs == 0 then
    pure false
  else
    let slice := min remainingMs 10
    sleepMs slice
    awaitTaskWithin task (remainingMs - slice)

private def retire (runtime : Runtime) : Async Unit := do
  let task ← Async.toIO runtime.stream.retire
  if ← awaitTaskWithin task runtime.config.retireTimeoutMs then
    try Async.ofAsyncTask task catch _ => pure ()
  else
    runtime.stream.abort
    -- The public pinned socket API cannot cancel an in-flight native write or
    -- guarantee descriptor release. Bound the Lean owner anyway: remove its
    -- cleanup continuation and let the native promise/OS settle independently.
    IO.cancel task

private def snapshotTermination (runtime : Runtime) (kind : TerminationKind)
    (detail? : Option String := none) : BaseIO Termination := do
  let termination ← runtime.state.atomically do
    let state ← get
    set { state with phase := .terminal }
    pure { kind, localClose? := state.localClose?, peerClose? := state.peerClose?, detail? }
  discard <| runtime.terminal.resolve termination
  pure termination

private def rememberReceiveError (runtime : Runtime) (error : ReceiveError) : BaseIO Unit :=
  runtime.state.atomically do
    modify fun state =>
      if state.terminalReceiveError?.isSome then state
      else { state with terminalReceiveError? := some error }

private partial def waitCloseDeadline (runtime : Runtime) (remainingMs : Nat) : Async Unit := do
  if ← IO.hasFinished runtime.closeFinished.result? then
    pure ()
  else if remainingMs == 0 then
    let shouldAbort ← runtime.state.atomically do
      let state ← get
      if state.phase == .terminal then pure false
      else
        set { state with closeTimedOut := true }
        pure true
    if shouldAbort then runtime.stream.abort
  else
    -- Pinned Std.Async cannot interrupt one raw timer wait. Short retained
    -- slices keep successful-close cancellation and exact joining bounded.
    let slice := min remainingMs 10
    sleepMs slice
    waitCloseDeadline runtime (remainingMs - slice)

private def closeDeadlineLoop (runtime : Runtime) : Async Unit := do
  match ← Async.ofTask runtime.closeStarted.result? with
  | none => pure ()
  | some _ => waitCloseDeadline runtime runtime.config.closeTimeoutMs

private def signalCloseFinished (runtime : Runtime) : BaseIO Unit := do
  discard <| runtime.closeFinished.resolve ()

private inductive FinishSendResult where
  | completed (result : Except Transport.Failure Unit)
  | deadline
  | abort
  deriving Repr

private inductive WriterStopResult where
  | completed (result : WriterResult)
  | deadline
  | abort

private def awaitWriterUntilLifecycle (writer : AsyncTask WriterResult)
    (deadline abortSignal : AsyncTask Unit) : Async WriterStopResult := do
  try
    Selectable.one #[
      Selectable.case (asyncTaskSelector writer) fun result => pure (.completed result),
      Selectable.case (asyncTaskSelector deadline) fun _ => pure .deadline,
      Selectable.case (asyncTaskSelector abortSignal) fun _ => pure .abort
    ]
  catch _ => pure (.completed .aborted)

private def finishSendUntilLifecycle (runtime : Runtime) (deadline abortSignal : AsyncTask Unit) :
    Async FinishSendResult := do
  let action ← Async.toIO runtime.stream.finishSend
  let attempted : Except IO.Error FinishSendResult ← try
      let winner : FinishSendResult ← Selectable.one #[
        Selectable.case (asyncTaskSelector action) fun result =>
          pure (FinishSendResult.completed result),
        Selectable.case (asyncTaskSelector deadline) fun _ =>
          pure FinishSendResult.deadline,
        Selectable.case (asyncTaskSelector abortSignal) fun _ =>
          pure FinishSendResult.abort
      ]
      pure (Except.ok winner)
    catch error => pure (Except.error error)
  match attempted with
  | .error error =>
      runtime.stream.abort
      IO.cancel action
      signalCloseFinished runtime
      try discard <| Async.ofAsyncTask deadline catch _ => pure ()
      pure (.completed (.error (Transport.Failure.io "finish WebSocket send side" error)))
  | .ok (.completed result) =>
      -- Join the exact retained deadline before reading closeTimedOut. If its
      -- wakeup raced this completion, its state update is now visible.
      signalCloseFinished runtime
      try discard <| Async.ofAsyncTask deadline catch _ => pure ()
      pure (.completed result)
  | .ok .deadline =>
      runtime.stream.abort
      IO.cancel action
      pure .deadline
  | .ok .abort =>
      runtime.stream.abort
      IO.cancel action
      pure .abort

private def abortSignalLoop (runtime : Runtime) : Async Unit := do
  discard <| Async.ofTask runtime.abortStarted.result?

private def finishRuntimeCore (runtime : Runtime) (deadline abortSignal : AsyncTask Unit)
    (kind : TerminationKind)
    (detail? : Option String := none) (closeCompression : Bool := true) : Async Termination := do
  closeChannel runtime.outbound
  closeChannel runtime.admission
  closeChannel runtime.control
  closeChannel runtime.controlAdmission
  closeChannel runtime.incoming
  signalCloseWritten runtime (.error {
    kind := .closed, message := "WebSocket connection terminated before Close was written" })
  -- Wake promise-backed signal tasks before joining them. Forced task
  -- cancellation cannot interrupt `Async.ofTask` waiting on a raw Promise.
  signalCloseStarted runtime
  signalCloseFinished runtime
  try Async.ofAsyncTask deadline catch _ => pure ()
  discard <| runtime.abortStarted.resolve ()
  try Async.ofAsyncTask abortSignal catch _ => pure ()
  if closeCompression then
    if let some compression := runtime.compression? then compression.close
  snapshotTermination runtime kind detail?

private def finishRuntime (runtime : Runtime) (deadline abortSignal : AsyncTask Unit)
    (kind : TerminationKind)
    (detail? : Option String := none) : Async Termination := do
  retire runtime
  finishRuntimeCore runtime deadline abortSignal kind detail?

private structure AbortWorkState where
  readerDone : Bool
  writerDone : Bool
  retirementDone : Bool

private partial def awaitAbortWork (reader : AsyncTask ReaderResult)
    (writer : AsyncTask WriterResult) (retirement : AsyncTask Unit)
    (remainingMs : Nat) : Async AbortWorkState := do
  let readerDone ← IO.hasFinished reader
  let writerDone ← IO.hasFinished writer
  let retirementDone ← IO.hasFinished retirement
  if readerDone && writerDone && retirementDone then
    pure { readerDone, writerDone, retirementDone }
  else if remainingMs == 0 then
    unless readerDone do IO.cancel reader
    unless writerDone do IO.cancel writer
    unless retirementDone do IO.cancel retirement
    pure { readerDone, writerDone, retirementDone }
  else
    let slice := min remainingMs 10
    sleepMs slice
    awaitAbortWork reader writer retirement (remainingMs - slice)

private def abortRuntime (runtime : Runtime) (reader : AsyncTask ReaderResult)
    (writer : AsyncTask WriterResult) (deadline abortSignal : AsyncTask Unit)
    (kind : TerminationKind) (detail? : Option String) :
    Async Termination := do
  runtime.state.atomically do modify fun state => { state with abortRequested := true }
  runtime.stream.abort
  signalCloseWritten runtime (.error {
    kind := if kind == .timeout then .timeout else .cancelled,
    message := detail?.getD "WebSocket connection was aborted" })
  closeChannel runtime.outbound
  closeChannel runtime.admission
  closeChannel runtime.control
  closeChannel runtime.controlAdmission
  -- Begin adapter retirement before waiting on children. It may wake a native
  -- send/ack waiter that prompt protocol abort alone cannot interrupt.
  let retirement ← Async.toIO runtime.stream.retire
  IO.cancel reader
  IO.cancel writer
  let completed ← awaitAbortWork reader writer retirement runtime.config.retireTimeoutMs
  if completed.readerDone then
    try discard <| Async.ofAsyncTask reader catch _ => pure ()
  if completed.writerDone then
    try discard <| Async.ofAsyncTask writer catch _ => pure ()
  if completed.retirementDone then
    try discard <| Async.ofAsyncTask retirement catch _ => pure ()
  -- An abandoned child still retains Runtime and may be synchronously inside
  -- zlib. Do not concurrently free its contexts; finalization occurs only
  -- after the native operation and retained task release them.
  finishRuntimeCore runtime deadline abortSignal kind detail?
    (closeCompression := completed.readerDone && completed.writerDone)

private def ownerLoop (runtime : Runtime) (reader : AsyncTask ReaderResult)
    (writer : AsyncTask WriterResult) (deadline abortSignal : AsyncTask Unit) : Async Termination := do
  let first : FirstResult ← Selectable.one #[
    Selectable.case (asyncTaskSelector reader) fun result => pure (.reader result),
    Selectable.case (asyncTaskSelector writer) fun result => pure (.writer result),
    Selectable.case (asyncTaskSelector deadline) fun _ => pure .deadline,
    Selectable.case (asyncTaskSelector abortSignal) fun _ => pure .abort
  ]
  match first with
  | .reader .clean =>
      closeChannel runtime.outbound
      closeChannel runtime.admission
      closeChannel runtime.control
      closeChannel runtime.controlAdmission
      -- Closed queues wake an idle writer naturally. Forced cancellation while
      -- it is suspended in channel selection does not complete promptly in the
      -- pinned runtime and can consume the entire close deadline.
      match ← awaitWriterUntilLifecycle writer deadline abortSignal with
      | .deadline =>
          return ← abortRuntime runtime reader writer deadline abortSignal .timeout
            (some "WebSocket close handshake timed out while stopping the writer")
      | .abort =>
          return ← abortRuntime runtime reader writer deadline abortSignal .aborted
            (some "WebSocket connection was aborted while stopping the writer")
      | .completed (.failed error) =>
          return ← abortRuntime runtime reader writer deadline abortSignal
            .transportError (some error.message)
      | .completed _ => pure ()
      let finishResult ← finishSendUntilLifecycle runtime deadline abortSignal
      let state ← runtime.state.atomically do pure (← get)
      if state.abortRequested || finishResult matches .abort then
        abortRuntime runtime reader writer deadline abortSignal .aborted
          (some "WebSocket connection was aborted")
      else if state.closeTimedOut || finishResult matches .deadline then
        abortRuntime runtime reader writer deadline abortSignal .timeout
          (some "WebSocket close handshake timed out")
      else
        let detail? := match finishResult with
          | .completed (.ok _) => none
          | .completed (.error error) => some error.message
          | .deadline | .abort => none
        finishRuntime runtime deadline abortSignal .clean detail?
  | .reader .endOfStream =>
      let timedOut ← runtime.state.atomically do pure (← get).closeTimedOut
      if timedOut then
        abortRuntime runtime reader writer deadline abortSignal .timeout
          (some "WebSocket close handshake timed out")
      else
        abortRuntime runtime reader writer deadline abortSignal .endOfStream
          (some "transport ended before a Close frame")
  | .reader (.failed error) =>
      let state ← runtime.state.atomically do pure (← get)
      let preservedError := if state.closeTimedOut then {
          kind := ReceiveErrorKind.timeout
          message := "WebSocket close handshake timed out"
        } else error
      rememberReceiveError runtime preservedError
      let kind := if state.abortRequested then TerminationKind.aborted
        else if state.closeTimedOut || error.kind == .timeout then TerminationKind.timeout
        else if error.kind == .protocol || error.kind == .compression ||
            error.kind == .backpressure then
          TerminationKind.protocolError
        else TerminationKind.transportError
      abortRuntime runtime reader writer deadline abortSignal kind (some error.message)
  | .reader .aborted =>
      let timedOut ← runtime.state.atomically do pure (← get).closeTimedOut
      abortRuntime runtime reader writer deadline abortSignal
        (if timedOut then .timeout else .aborted) none
  | .writer (.failed error) =>
      let state ← runtime.state.atomically do pure (← get)
      let kind := if state.abortRequested then TerminationKind.aborted
        else if state.closeTimedOut || error.kind == .timeout then TerminationKind.timeout
        else if error.kind == .protocol || error.kind == .compression then
          TerminationKind.protocolError
        else TerminationKind.transportError
      abortRuntime runtime reader writer deadline abortSignal kind (some error.message)
  | .writer .stopped =>
      abortRuntime runtime reader writer deadline abortSignal .aborted (some "WebSocket writer stopped")
  | .writer .aborted => abortRuntime runtime reader writer deadline abortSignal .aborted none
  | .deadline =>
      abortRuntime runtime reader writer deadline abortSignal .timeout
        (some "WebSocket close handshake timed out")
  | .abort =>
      abortRuntime runtime reader writer deadline abortSignal .aborted
        (some "WebSocket connection was aborted")

/-- Start protocol ownership over an already-upgraded byte stream. -/
def start (role : Role) (stream : Transport.ByteStream) (config : Config := {})
    (compression? : Option PerMessageDeflate.Parameters := none) :
    IO (Except SendError Connection) := do
  if config.limits.maxFramePayloadBytes == 0 then
    return .error {
      kind := .invalidArgument, message := "maxFramePayloadBytes must be positive" }
  if config.limits.maxMessagePayloadBytes == 0 then
    return .error {
      kind := .invalidArgument, message := "maxMessagePayloadBytes must be positive" }
  if config.limits.maxFragmentsPerMessage == 0 then
    return .error {
      kind := .invalidArgument, message := "maxFragmentsPerMessage must be positive" }
  if config.fragmentSize == 0 || config.fragmentSize > config.limits.maxFramePayloadBytes then
    return .error {
      kind := .invalidArgument,
      message := "fragmentSize must be between 1 and maxFramePayloadBytes" }
  if config.closeTimeoutMs == 0 || config.retireTimeoutMs == 0 then
    return .error {
      kind := .invalidArgument, message := "close and retire timeouts must be positive" }
  if config.incomingCapacity == 0 then
    return .error {
      kind := .invalidArgument, message := "incomingCapacity must be positive" }
  let mut compressionSession? : Option PerMessageDeflate.Session := none
  match compression? with
  | none => pure ()
  | some parameters =>
      match ← PerMessageDeflate.Session.create role parameters with
      | .ok session => compressionSession? := some session
      | .error error => return .error (sendErrorOfCompression error)
  let state ← Std.Mutex.new {}
  let admission ← Std.CloseableChannel.new (some 1)
  discard <| admission.trySend ()
  let outbound ← Std.CloseableChannel.new (some 1)
  let controlAdmission ← Std.CloseableChannel.new (some 1)
  discard <| controlAdmission.trySend ()
  -- Application controls are admission-limited; Close bypasses admission and
  -- is irrevocably queued, so the control queue itself is unbounded.
  let control ← Std.CloseableChannel.new none
  let closeStarted ← IO.Promise.new
  let closeFinished ← IO.Promise.new
  let closeWritten ← IO.Promise.new
  let abortStarted ← IO.Promise.new
  let terminal ← IO.Promise.new
  let incoming ← Std.CloseableChannel.new (some config.incomingCapacity)
  let runtime : Runtime := {
    role, stream, config, compression? := compressionSession?, state,
    admission, outbound, controlAdmission, control, closeStarted, closeFinished, closeWritten,
    abortStarted, terminal, incoming
  }
  let deadline ← Async.toIO (closeDeadlineLoop runtime)
  let abortSignal ← Async.toIO (abortSignalLoop runtime)
  let reader ← Async.toIO (ownedReader runtime)
  let writer ← Async.toIO (ownedWriter runtime)
  let owner ← Async.toIO (ownerLoop runtime reader writer deadline abortSignal)
  pure (.ok { runtime, deadline, abortSignal, reader, writer, owner })

private def chooseCompression (connection : Connection) (message : Message.Message)
    (options : SendOptions) : Bool :=
  let requested := options.compress?.getD connection.runtime.config.compressByDefault
  requested && connection.runtime.compression?.isSome &&
    message.data.size >= connection.runtime.config.compressionThreshold

private def sendWithToken (connection : Connection) (message : Message.Message)
    (options : SendOptions) (cancellation? : Option Std.CancellationToken) :
    Async (Except SendError Unit) := do
  if message.compressed then
    pure (.error {
      kind := .invalidArgument, message := "outbound messages must contain uncompressed data" })
  else if message.data.size > connection.runtime.config.limits.maxMessagePayloadBytes then
    pure (.error { kind := .invalidArgument, message := "message exceeds configured limit" })
  else if message.kind == .text then
    match Utf8.validate message.data with
    | .error _ => pure (.error {
        kind := .invalidArgument, message := "outbound text message is not valid UTF-8" })
    | .ok _ =>
        let compress := chooseCompression connection message options
        let count := if message.data.isEmpty then 1 else
          (message.data.size + connection.runtime.config.fragmentSize - 1) /
            connection.runtime.config.fragmentSize
        if !compress && count > connection.runtime.config.limits.maxFragmentsPerMessage then
          pure (.error {
            kind := .invalidArgument, message := "message exceeds configured fragment limit" })
        else
          submitOpen connection.runtime (.message message compress) cancellation?
  else
    let compress := chooseCompression connection message options
    let count := if message.data.isEmpty then 1 else
      (message.data.size + connection.runtime.config.fragmentSize - 1) /
        connection.runtime.config.fragmentSize
    if !compress && count > connection.runtime.config.limits.maxFragmentsPerMessage then
      pure (.error {
        kind := .invalidArgument, message := "message exceeds configured fragment limit" })
    else
        submitOpen connection.runtime (.message message compress) cancellation?

/-- Send with cooperative pre-admission cancellation. Cancellation can prevent
queue admission; after admission it cannot retract the connection-owned
request. A concurrent Close may still reject queued data or interrupt a
fragmented message, and this action reports that eventual outcome. -/
def sendWithCancellation (connection : Connection) (message : Message.Message)
    (cancellation : Std.CancellationToken) (options : SendOptions := {}) :
    Async (Except SendError Unit) :=
  sendWithToken connection message options (some cancellation)

def sendWith (connection : Connection) (message : Message.Message)
    (options : SendOptions := {}) : Async (Except SendError Unit) :=
  sendWithToken connection message options none

def send (connection : Connection) (message : Message.Message) :
    Async (Except SendError Unit) :=
  sendWith connection message

def sendText (connection : Connection) (text : String) (options : SendOptions := {}) :
    Async (Except SendError Unit) :=
  sendWith connection { kind := .text, data := text.toUTF8 } options

def sendBinary (connection : Connection) (data : ByteArray) (options : SendOptions := {}) :
    Async (Except SendError Unit) :=
  sendWith connection { kind := .binary, data } options

def ping (connection : Connection) (payload : ByteArray := ByteArray.empty) :
    Async (Except SendError Unit) :=
  if payload.size > 125 then
    pure (.error { kind := .invalidArgument, message := "Ping payload exceeds 125 bytes" })
  else
    submitOpen connection.runtime (.ping payload)

def pingWithCancellation (connection : Connection) (cancellation : Std.CancellationToken)
    (payload : ByteArray := ByteArray.empty) : Async (Except SendError Unit) :=
  if payload.size > 125 then
    pure (.error { kind := .invalidArgument, message := "Ping payload exceeds 125 bytes" })
  else
    submitOpen connection.runtime (.ping payload) (some cancellation)

def pong (connection : Connection) (payload : ByteArray := ByteArray.empty) :
    Async (Except SendError Unit) :=
  if payload.size > 125 then
    pure (.error { kind := .invalidArgument, message := "Pong payload exceeds 125 bytes" })
  else
    submitOpen connection.runtime (.pong payload)

def pongWithCancellation (connection : Connection) (cancellation : Std.CancellationToken)
    (payload : ByteArray := ByteArray.empty) : Async (Except SendError Unit) :=
  if payload.size > 125 then
    pure (.error { kind := .invalidArgument, message := "Pong payload exceeds 125 bytes" })
  else
    submitOpen connection.runtime (.pong payload) (some cancellation)

private inductive IncomingResult where
  | event (value : Message.Event)
  | closed
  | cancelled

private partial def nextIncomingIO (runtime : Runtime)
    (cancellation? : Option Std.CancellationToken) : IO IncomingResult := do
  if ← submissionCancelled cancellation? then return .cancelled
  match ← runtime.incoming.tryRecv with
  | some event => pure (.event event)
  | none =>
      if ← runtime.incoming.isClosed then pure .closed
      else
        IO.sleep 1
        nextIncomingIO runtime cancellation?

private def receiveResultAfterTermination (connection : Connection)
    (termination : Termination) : BaseIO (Except ReceiveError (Option Message.Event)) := do
  let terminalError? ← connection.runtime.state.atomically do
    pure (← get).terminalReceiveError?
  if let some error := terminalError? then return .error error
  match termination.kind with
  | .clean => pure (.ok none)
  | .protocolError => pure (.error {
      kind := .protocol, message := termination.detail?.getD "WebSocket protocol error" })
  | .timeout => pure (.error {
      kind := .timeout, message := termination.detail?.getD "WebSocket operation timed out" })
  | .aborted => pure (.error {
      kind := .cancelled, message := termination.detail?.getD "WebSocket aborted" })
  | _ => pure (.error {
      kind := .transport, message := termination.detail?.getD "WebSocket transport ended" })

private partial def receiveClosedIO (connection : Connection)
    (cancellation? : Option Std.CancellationToken) :
    IO (Except ReceiveError (Option Message.Event)) := do
  if ← submissionCancelled cancellation? then
    return .error {
      kind := .cancelled, message := "WebSocket receive was cancelled" }
  if ← IO.hasFinished connection.runtime.terminal.result? then
    match connection.runtime.terminal.result?.get with
    | some termination => receiveResultAfterTermination connection termination
    | none => pure (.error {
        kind := .cancelled, message := "connection termination was dropped" })
  else
    IO.sleep 1
    receiveClosedIO connection cancellation?

private partial def receiveIO (connection : Connection)
    (cancellation? : Option Std.CancellationToken) :
    IO (Except ReceiveError (Option Message.Event)) := do
  match ← nextIncomingIO connection.runtime cancellation? with
  | .event event => pure (.ok (some event))
  | .closed => receiveClosedIO connection cancellation?
  | .cancelled => pure (.error {
      kind := .cancelled, message := "WebSocket receive was cancelled" })

private def receiveWithToken (connection : Connection)
    (cancellation? : Option Std.CancellationToken) :
    Async (Except ReceiveError (Option Message.Event)) :=
  exactIOWorker (receiveIO connection cancellation?)

/-- Receive one event with cooperative cancellation. A cancelled wait never
leaves a hidden channel consumer behind, so a later receive observes the next
event exactly once. -/
def receiveWithCancellation (connection : Connection)
    (cancellation : Std.CancellationToken) :
    Async (Except ReceiveError (Option Message.Event)) :=
  receiveWithToken connection (some cancellation)

def receive (connection : Connection) :
    Async (Except ReceiveError (Option Message.Event)) :=
  receiveWithToken connection none

def wait (connection : Connection) : Async Termination :=
  Async.ofAsyncTask connection.owner

private def closeWithToken (connection : Connection) (code? : Option CloseCode)
    (reason : String) (cancellation? : Option Std.CancellationToken) :
    Async (Except SendError Termination) := do
  let value ← match Message.Close.create connection.runtime.role code? reason with
    | .ok value => pure value
    | .error error => return .error (sendErrorOfProtocol error)
  match ← submitClose connection.runtime value cancellation? with
  | .error error =>
      if ← IO.hasFinished connection.runtime.terminal.result? then
        match ← Async.ofTask connection.runtime.terminal.result? with
        | some termination =>
            if termination.kind == .clean then pure (.ok termination) else pure (.error error)
        | none => pure (.error error)
      else pure (.error error)
  | .ok _ => pure (.ok (← wait connection))

/-- Start Close with cooperative cancellation before its atomic phase
transition. After transition, exactly one Close is connection-owned and
irrevocable even if the caller stops observing this action. -/
def closeWithCancellation (connection : Connection) (cancellation : Std.CancellationToken)
    (code? : Option CloseCode := some .normalClosure) (reason : String := "") :
    Async (Except SendError Termination) :=
  closeWithToken connection code? reason (some cancellation)

def close (connection : Connection) (code? : Option CloseCode := some .normalClosure)
    (reason : String := "") : Async (Except SendError Termination) :=
  closeWithToken connection code? reason none

/-- Prompt, idempotent abort.  Child tasks are exact retained handles; the
owner observes their cancellation and performs bounded transport retirement. -/
def requestAbort (connection : Connection) : IO Unit := do
  connection.runtime.state.atomically do
    modify fun state => { state with abortRequested := true }
  -- The transport's prompt abort wakes the reader. The retained owner then
  -- observes that normal task completion and exclusively owns forced child
  -- cancellation, joining, and transport retirement. Cancelling children here
  -- would skip their catches and could make the owner's selector fail.
  connection.runtime.stream.abort
  discard <| connection.runtime.abortStarted.resolve ()

end Connection

end Ws
