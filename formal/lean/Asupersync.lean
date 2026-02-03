import Std

namespace Asupersync

/-!
Small-step operational semantics skeleton.
Source of truth: asupersync_v4_formal_semantics.md

This file intentionally starts minimal. The goal is to mechanize the operational
rules and proofs incrementally while keeping the model faithful to the doc.
-/-

abbrev RegionId := Nat
abbrev TaskId := Nat
abbrev ObligationId := Nat
abbrev Time := Nat

/-- Outcome with four severity-ordered cases. -/
inductive Outcome (Value Error Cancel Panic : Type) where
  | ok (v : Value)
  | err (e : Error)
  | cancelled (c : Cancel)
  | panicked (p : Panic)

/-- Cancellation kinds. -/
inductive CancelKind where
  | user
  | timeout
  | failFast
  | parentCancelled
  | shutdown
  deriving DecidableEq, Repr

/-- Cancellation reason. -/
structure CancelReason where
  kind : CancelKind
  message : Option String

/-- Budget semiring (min-plus with priority max). -/
structure Budget where
  deadline : Option Time
  pollQuota : Nat
  costQuota : Option Nat
  priority : Nat

/-- min on optional values -/
def minOpt (a b : Option Nat) : Option Nat :=
  match a, b with
  | none, x => x
  | x, none => x
  | some x, some y => some (Nat.min x y)

/-- Combine budgets (componentwise min, except priority max). -/
def Budget.combine (b1 b2 : Budget) : Budget :=
  { deadline := minOpt b1.deadline b2.deadline
  , pollQuota := Nat.min b1.pollQuota b2.pollQuota
  , costQuota := minOpt b1.costQuota b2.costQuota
  , priority := Nat.max b1.priority b2.priority
  }

/-- Task states. -/
inductive TaskState (Value Error Panic : Type) where
  | created
  | running
  | cancelRequested (reason : CancelReason) (cleanup : Budget)
  | cancelling (cleanup : Budget)
  | finalizing (cleanup : Budget)
  | completed (outcome : Outcome Value Error CancelReason Panic)

/-- Region states. -/
inductive RegionState (Value Error Panic : Type) where
  | open
  | closing
  | draining
  | finalizing
  | closed (outcome : Outcome Value Error CancelReason Panic)

/-- Obligation states. -/
inductive ObligationState where
  | reserved
  | committed
  | aborted
  | leaked
  deriving DecidableEq, Repr

/-- Obligation kinds. -/
inductive ObligationKind where
  | sendPermit
  | ack
  | lease
  | ioOp
  deriving DecidableEq, Repr

/-- Task record (minimal, extend as needed). -/
structure Task (Value Error Panic : Type) where
  region : RegionId
  state : TaskState Value Error Panic
  mask : Nat
  waiters : List TaskId

/-- Region record (minimal, extend as needed). -/
structure Region (Value Error Panic : Type) where
  state : RegionState Value Error Panic
  children : List TaskId
  subregions : List RegionId
  ledger : List ObligationId
  deadline : Option Time

/-- Obligation record (minimal, extend as needed). -/
structure ObligationRecord where
  kind : ObligationKind
  holder : TaskId
  region : RegionId
  state : ObligationState

/-- Scheduler lane (Cancel > Timed > Ready). -/
inductive Lane where
  | cancel
  | timed
  | ready
  deriving DecidableEq, Repr

/-- Scheduler state (queues abstracted as lists). -/
structure SchedulerState where
  cancelLane : List TaskId
  timedLane : List TaskId
  readyLane : List TaskId

/-- Global kernel state Sigma = (R, T, O, Now). -/
structure State (Value Error Panic : Type) where
  regions : RegionId -> Option (Region Value Error Panic)
  tasks : TaskId -> Option (Task Value Error Panic)
  obligations : ObligationId -> Option ObligationRecord
  scheduler : SchedulerState
  now : Time

def getTask (s : State Value Error Panic) (t : TaskId) : Option (Task Value Error Panic) :=
  s.tasks t

def getRegion (s : State Value Error Panic) (r : RegionId) : Option (Region Value Error Panic) :=
  s.regions r

def getObligation (s : State Value Error Panic) (o : ObligationId) : Option ObligationRecord :=
  s.obligations o

def setTask (s : State Value Error Panic) (t : TaskId) (task : Task Value Error Panic) :
    State Value Error Panic :=
  { s with tasks := fun t' => if t' = t then some task else s.tasks t' }

def setRegion (s : State Value Error Panic) (r : RegionId) (region : Region Value Error Panic) :
    State Value Error Panic :=
  { s with regions := fun r' => if r' = r then some region else s.regions r' }

def setObligation (s : State Value Error Panic) (o : ObligationId) (ob : ObligationRecord) :
    State Value Error Panic :=
  { s with obligations := fun o' => if o' = o then some ob else s.obligations o' }

def runnable {Value Error Panic : Type} (st : TaskState Value Error Panic) : Prop :=
  match st with
  | TaskState.created => True
  | TaskState.running => True
  | TaskState.cancelRequested _ _ => True
  | TaskState.cancelling _ => True
  | TaskState.finalizing _ => True
  | TaskState.completed _ => False

def laneOf {Value Error Panic : Type} (task : Task Value Error Panic) (region : Region Value Error Panic) :
    Lane :=
  match task.state with
  | TaskState.cancelRequested _ _ => Lane.cancel
  | TaskState.cancelling _ => Lane.cancel
  | TaskState.finalizing _ => Lane.cancel
  | _ =>
      match region.deadline with
      | some _ => Lane.timed
      | none => Lane.ready

def pushLane (sched : SchedulerState) (lane : Lane) (t : TaskId) : SchedulerState :=
  match lane with
  | Lane.cancel => { sched with cancelLane := sched.cancelLane ++ [t] }
  | Lane.timed => { sched with timedLane := sched.timedLane ++ [t] }
  | Lane.ready => { sched with readyLane := sched.readyLane ++ [t] }

def popLane (lane : List TaskId) : Option (TaskId × List TaskId) :=
  match lane with
  | [] => none
  | t :: rest => some (t, rest)

def popNext (sched : SchedulerState) : Option (TaskId × SchedulerState) :=
  match popLane sched.cancelLane with
  | some (t, rest) => some (t, { sched with cancelLane := rest })
  | none =>
      match popLane sched.timedLane with
      | some (t, rest) => some (t, { sched with timedLane := rest })
      | none =>
          match popLane sched.readyLane with
          | some (t, rest) => some (t, { sched with readyLane := rest })
          | none => none

def schedulerNonempty (sched : SchedulerState) : Prop :=
  sched.cancelLane ≠ [] ∨ sched.timedLane ≠ [] ∨ sched.readyLane ≠ []

opaque IsReady {Value Error Panic : Type} : State Value Error Panic -> TaskId -> Prop

def Resolved (st : ObligationState) : Prop :=
  st = ObligationState.committed ∨ st = ObligationState.aborted

def taskCompleted (t : Task Value Error Panic) : Prop :=
  match t.state with
  | TaskState.completed _ => True
  | _ => False

def regionClosed (r : Region Value Error Panic) : Prop :=
  match r.state with
  | RegionState.closed _ => True
  | _ => False

def allTasksCompleted (s : State Value Error Panic) (ts : List TaskId) : Prop :=
  List.All (fun t =>
    match getTask s t with
    | some task => taskCompleted task
    | none => False) ts

def allRegionsClosed (s : State Value Error Panic) (rs : List RegionId) : Prop :=
  List.All (fun r =>
    match getRegion s r with
    | some region => regionClosed region
    | none => False) rs

def Quiescent (s : State Value Error Panic) (r : Region Value Error Panic) : Prop :=
  allTasksCompleted s r.children ∧ allRegionsClosed s r.subregions ∧ r.ledger = []

def LoserDrained (s : State Value Error Panic) (t1 t2 : TaskId) : Prop :=
  match getTask s t1, getTask s t2 with
  | some a, some b => taskCompleted a ∧ taskCompleted b
  | _, _ => False

/-- Observable labels (extend as rules are added). -/
inductive Label (Value Error Panic : Type) where
  | tau
  | spawn (r : RegionId) (t : TaskId)
  | complete (t : TaskId) (outcome : Outcome Value Error CancelReason Panic)
  | cancel (r : RegionId) (reason : CancelReason)
  | reserve (o : ObligationId)
  | commit (o : ObligationId)
  | abort (o : ObligationId)
  | leak (o : ObligationId)
  | defer (r : RegionId) (f : TaskId)
  | finalize (r : RegionId) (f : TaskId)
  | close (r : RegionId) (outcome : Outcome Value Error CancelReason Panic)
  | tick
  deriving DecidableEq, Repr

/-- Small-step operational relation. -/
inductive Step (Value Error Panic : Type) :
  State Value Error Panic -> Label Value Error Panic -> State Value Error Panic -> Prop where
  /-- ENQUEUE: put a runnable task into the appropriate lane. -/
  | enqueue {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      {region : Region Value Error Panic}
      (hReady : IsReady s t)
      (hTask : getTask s t = some task)
      (hRegion : getRegion s task.region = some region)
      (hRunnable : runnable task.state)
      (hUpdate :
        s' =
          { s with scheduler := pushLane s.scheduler (laneOf task region) t }) :
      Step s (Label.tau) s'

  /-- SCHEDULE-STEP: pick next runnable task (poll abstracted). -/
  | scheduleStep {s s' : State Value Error Panic} {t : TaskId} {sched' : SchedulerState}
      (hPick : popNext s.scheduler = some (t, sched'))
      (hUpdate : s' = { s with scheduler := sched' }) :
      Step s (Label.tau) s'

  /-- SPAWN: create a task in an open region. -/
  | spawn {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
      {region : Region Value Error Panic}
      (hRegion : getRegion s r = some region)
      (hOpen : region.state = RegionState.open)
      (hAbsent : getTask s t = none)
      (hUpdate :
        s' =
          setRegion
            (setTask s t { region := r, state := TaskState.created, mask := 0, waiters := [] })
            r
            { region with children := region.children ++ [t] }) :
      Step s (Label.spawn r t) s'

  /-- SCHEDULE: transition a created task to running. -/
  | schedule {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      {region : Region Value Error Panic}
      (hTask : getTask s t = some task)
      (hRegion : getRegion s task.region = some region)
      (hTaskState : task.state = TaskState.created)
      (hRegionState :
        region.state = RegionState.open ∨
        region.state = RegionState.closing ∨
        region.state = RegionState.draining)
      (hUpdate :
        s' = setTask s t { task with state := TaskState.running }) :
      Step s (Label.tau) s'

  /-- COMPLETE: a running task completes with an outcome. -/
  | complete {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      (outcome : Outcome Value Error CancelReason Panic)
      (hTask : getTask s t = some task)
      (hTaskState : task.state = TaskState.running)
      (hUpdate :
        s' = setTask s t { task with state := TaskState.completed outcome }) :
      Step s (Label.complete t outcome) s'

  -- Rules to be added here (complete, cancel, join, obligations, close, ...)

end Asupersync
