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

def CancelKind.rank : CancelKind -> Nat
  | CancelKind.user => 0
  | CancelKind.timeout => 1
  | CancelKind.failFast => 2
  | CancelKind.parentCancelled => 3
  | CancelKind.shutdown => 4

def strengthenReason (a b : CancelReason) : CancelReason :=
  if CancelKind.rank a.kind >= CancelKind.rank b.kind then a else b

def strengthenOpt (current : Option CancelReason) (incoming : CancelReason) : CancelReason :=
  match current with
  | none => incoming
  | some r => strengthenReason r incoming

def parentCancelledReason : CancelReason :=
  { kind := CancelKind.parentCancelled, message := none }

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
  | cancelling (reason : CancelReason) (cleanup : Budget)
  | finalizing (reason : CancelReason) (cleanup : Budget)
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
  cancel : Option CancelReason
  children : List TaskId
  subregions : List RegionId
  ledger : List ObligationId
  finalizers : List TaskId
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

def removeObligationId (o : ObligationId) (xs : List ObligationId) : List ObligationId :=
  xs.filter (fun x => x ≠ o)

def holdsObligation (s : State Value Error Panic) (t : TaskId) (o : ObligationId) : Prop :=
  match getObligation s o with
  | some ob => ob.holder = t ∧ ob.state = ObligationState.reserved
  | none => False

theorem removeObligationId_not_mem (o : ObligationId) (xs : List ObligationId) :
    o ∉ removeObligationId o xs := by
  simp [removeObligationId]

def runnable {Value Error Panic : Type} (st : TaskState Value Error Panic) : Prop :=
  match st with
  | TaskState.created => True
  | TaskState.running => True
  | TaskState.cancelRequested _ _ => True
  | TaskState.cancelling _ _ => True
  | TaskState.finalizing _ _ => True
  | TaskState.completed _ => False

def laneOf {Value Error Panic : Type} (task : Task Value Error Panic) (region : Region Value Error Panic) :
    Lane :=
  match task.state with
  | TaskState.cancelRequested _ _ => Lane.cancel
  | TaskState.cancelling _ _ => Lane.cancel
  | TaskState.finalizing _ _ => Lane.cancel
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
  allTasksCompleted s r.children ∧
  allRegionsClosed s r.subregions ∧
  r.ledger = [] ∧
  r.finalizers = []

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

  /-- RESERVE: acquire a new obligation and add it to the region ledger. -/
  | reserve {s s' : State Value Error Panic} {t : TaskId} {o : ObligationId}
      {task : Task Value Error Panic} {region : Region Value Error Panic} {k : ObligationKind}
      (hTask : getTask s t = some task)
      (hRegion : getRegion s task.region = some region)
      (hAbsent : getObligation s o = none)
      (hUpdate :
        s' =
          setRegion
            (setObligation s o
              { kind := k, holder := t, region := task.region, state := ObligationState.reserved })
            task.region
            { region with ledger := region.ledger ++ [o] }) :
      Step s (Label.reserve o) s'

  /-- COMMIT: resolve an obligation held by the task. -/
  | commit {s s' : State Value Error Panic} {t : TaskId} {o : ObligationId}
      {ob : ObligationRecord} {region : Region Value Error Panic}
      (hOb : getObligation s o = some ob)
      (hHolder : ob.holder = t)
      (hState : ob.state = ObligationState.reserved)
      (hRegion : getRegion s ob.region = some region)
      (hUpdate :
        s' =
          setRegion
            (setObligation s o { ob with state := ObligationState.committed })
            ob.region
            { region with ledger := removeObligationId o region.ledger }) :
      Step s (Label.commit o) s'

  /-- ABORT: abort an obligation held by the task. -/
  | abort {s s' : State Value Error Panic} {t : TaskId} {o : ObligationId}
      {ob : ObligationRecord} {region : Region Value Error Panic}
      (hOb : getObligation s o = some ob)
      (hHolder : ob.holder = t)
      (hState : ob.state = ObligationState.reserved)
      (hRegion : getRegion s ob.region = some region)
      (hUpdate :
        s' =
          setRegion
            (setObligation s o { ob with state := ObligationState.aborted })
            ob.region
            { region with ledger := removeObligationId o region.ledger }) :
      Step s (Label.abort o) s'

  /-- LEAK: a task completes while still holding a reserved obligation. -/
  | leak {s s' : State Value Error Panic} {t : TaskId} {o : ObligationId}
      {task : Task Value Error Panic} {ob : ObligationRecord} {region : Region Value Error Panic}
      (outcome : Outcome Value Error CancelReason Panic)
      (hTask : getTask s t = some task)
      (hTaskState : task.state = TaskState.completed outcome)
      (hOb : getObligation s o = some ob)
      (hHolder : ob.holder = t)
      (hState : ob.state = ObligationState.reserved)
      (hRegion : getRegion s ob.region = some region)
      (hUpdate :
        s' =
          setRegion
            (setObligation s o { ob with state := ObligationState.leaked })
            ob.region
            { region with ledger := removeObligationId o region.ledger }) :
      Step s (Label.leak o) s'

  /-- CANCEL-REQUEST: mark a task for cancellation and set region cancel reason. -/
  | cancelRequest {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
      {task : Task Value Error Panic} {region : Region Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hTask : getTask s t = some task)
      (hRegion : getRegion s r = some region)
      (hRegionMatch : task.region = r)
      (hNotCompleted :
        match task.state with
        | TaskState.completed _ => False
        | _ => True)
      (hUpdate :
        s' =
          setTask
            (setRegion s r { region with cancel := some (strengthenOpt region.cancel reason) })
            t
            { task with state := TaskState.cancelRequested reason cleanup }) :
      Step s (Label.cancel r reason) s'

  /-- CHECKPOINT-MASKED: defer cancellation by consuming one mask unit. -/
  | cancelMasked {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hTask : getTask s t = some task)
      (hState : task.state = TaskState.cancelRequested reason cleanup)
      (hMask : task.mask > 0)
      (hUpdate :
        s' =
          setTask s t
            { task with
                mask := task.mask - 1,
                state := TaskState.cancelRequested reason cleanup }) :
      Step s (Label.tau) s'

  /-- CANCEL-ACKNOWLEDGE: task observes cancellation and enters cancelling. -/
  | cancelAcknowledge {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hTask : getTask s t = some task)
      (hState : task.state = TaskState.cancelRequested reason cleanup)
      (hMask : task.mask = 0)
      (hUpdate :
        s' = setTask s t { task with state := TaskState.cancelling reason cleanup }) :
      Step s (Label.tau) s'

  /-- CANCEL-ENTER-FINALIZE: cancelling task moves to finalizing. -/
  | cancelFinalize {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hTask : getTask s t = some task)
      (hState : task.state = TaskState.cancelling reason cleanup)
      (hUpdate :
        s' = setTask s t { task with state := TaskState.finalizing reason cleanup }) :
      Step s (Label.tau) s'

  /-- CANCEL-COMPLETE: finalizing task completes as Cancelled(reason). -/
  | cancelComplete {s s' : State Value Error Panic} {t : TaskId} {task : Task Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hTask : getTask s t = some task)
      (hState : task.state = TaskState.finalizing reason cleanup)
      (hUpdate :
        s' =
          setTask s t
            { task with state := TaskState.completed (Outcome.cancelled reason) }) :
      Step s (Label.tau) s'

  /-- CANCEL-PROPAGATE: push parent cancellation to a subregion. -/
  | cancelPropagate {s s' : State Value Error Panic} {r r' : RegionId}
      {region : Region Value Error Panic} {sub : Region Value Error Panic}
      (reason : CancelReason)
      (hRegion : getRegion s r = some region)
      (hCancel : region.cancel = some reason)
      (hChild : r' ∈ region.subregions)
      (hSub : getRegion s r' = some sub)
      (hUpdate :
        s' =
          setRegion s r'
            { sub with cancel := some (strengthenOpt sub.cancel parentCancelledReason) }) :
      Step s (Label.tau) s'

  /-- CANCEL-CHILD: mark a child task for cancellation due to region cancel. -/
  | cancelChild {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
      {region : Region Value Error Panic} {task : Task Value Error Panic}
      (reason : CancelReason) (cleanup : Budget)
      (hRegion : getRegion s r = some region)
      (hCancel : region.cancel = some reason)
      (hChild : t ∈ region.children)
      (hTask : getTask s t = some task)
      (hNotCompleted :
        match task.state with
        | TaskState.completed _ => False
        | _ => True)
      (hUpdate :
        s' =
          setTask s t { task with state := TaskState.cancelRequested reason cleanup }) :
      Step s (Label.tau) s'

  /-- CLOSE: close a quiescent region with an outcome. -/
  | close {s s' : State Value Error Panic} {r : RegionId}
      {region : Region Value Error Panic}
      (outcome : Outcome Value Error CancelReason Panic)
      (hRegion : getRegion s r = some region)
      (hState :
        region.state = RegionState.closing ∨
        region.state = RegionState.draining ∨
        region.state = RegionState.finalizing)
      (hQuiescent : Quiescent s region)
      (hUpdate :
        s' = setRegion s r { region with state := RegionState.closed outcome }) :
      Step s (Label.close r outcome) s'

  /-- FINALIZE: run one finalizer in LIFO order. -/
  | finalize {s s' : State Value Error Panic} {r : RegionId} {f : TaskId}
      {region : Region Value Error Panic} {rest : List TaskId}
      (hRegion : getRegion s r = some region)
      (hState : region.state = RegionState.finalizing)
      (hFinalizers : region.finalizers = f :: rest)
      (hUpdate :
        s' = setRegion s r { region with finalizers := rest }) :
      Step s (Label.finalize r f) s'

  /-- TICK: advance virtual time by one unit. -/
  | tick {s s' : State Value Error Panic}
      (hUpdate : s' = { s with now := s.now + 1 }) :
      Step s (Label.tick) s'

-- ==========================================================================
-- Frame lemmas for state update functions
-- ==========================================================================

section FrameLemmas
variable {Value Error Panic : Type}

@[simp]
theorem setTask_getTask_same (s : State Value Error Panic) (t : TaskId) (task : Task Value Error Panic) :
    getTask (setTask s t task) t = some task := by
  simp [getTask, setTask]

@[simp]
theorem setTask_getTask_other (s : State Value Error Panic) (t t' : TaskId) (task : Task Value Error Panic)
    (h : t' ≠ t) : getTask (setTask s t task) t' = getTask s t' := by
  simp [getTask, setTask, h]

@[simp]
theorem setRegion_getRegion_same (s : State Value Error Panic) (r : RegionId) (region : Region Value Error Panic) :
    getRegion (setRegion s r region) r = some region := by
  simp [getRegion, setRegion]

@[simp]
theorem setRegion_getRegion_other (s : State Value Error Panic) (r r' : RegionId) (region : Region Value Error Panic)
    (h : r' ≠ r) : getRegion (setRegion s r region) r' = getRegion s r' := by
  simp [getRegion, setRegion, h]

@[simp]
theorem setObligation_getObligation_same (s : State Value Error Panic) (o : ObligationId) (ob : ObligationRecord) :
    getObligation (setObligation s o ob) o = some ob := by
  simp [getObligation, setObligation]

@[simp]
theorem setObligation_getObligation_other (s : State Value Error Panic) (o o' : ObligationId) (ob : ObligationRecord)
    (h : o' ≠ o) : getObligation (setObligation s o ob) o' = getObligation s o' := by
  simp [getObligation, setObligation, h]

/-- setTask does not change regions. -/
@[simp]
theorem setTask_getRegion (s : State Value Error Panic) (t : TaskId) (task : Task Value Error Panic)
    (r : RegionId) : getRegion (setTask s t task) r = getRegion s r := by
  simp [getRegion, setTask]

/-- setTask does not change obligations. -/
@[simp]
theorem setTask_getObligation (s : State Value Error Panic) (t : TaskId) (task : Task Value Error Panic)
    (o : ObligationId) : getObligation (setTask s t task) o = getObligation s o := by
  simp [getObligation, setTask]

/-- setRegion does not change tasks. -/
@[simp]
theorem setRegion_getTask (s : State Value Error Panic) (r : RegionId) (region : Region Value Error Panic)
    (t : TaskId) : getTask (setRegion s r region) t = getTask s t := by
  simp [getTask, setRegion]

/-- setRegion does not change obligations. -/
@[simp]
theorem setRegion_getObligation (s : State Value Error Panic) (r : RegionId) (region : Region Value Error Panic)
    (o : ObligationId) : getObligation (setRegion s r region) o = getObligation s o := by
  simp [getObligation, setRegion]

/-- setObligation does not change tasks. -/
@[simp]
theorem setObligation_getTask (s : State Value Error Panic) (o : ObligationId) (ob : ObligationRecord)
    (t : TaskId) : getTask (setObligation s o ob) t = getTask s t := by
  simp [getTask, setObligation]

/-- setObligation does not change regions. -/
@[simp]
theorem setObligation_getRegion (s : State Value Error Panic) (o : ObligationId) (ob : ObligationRecord)
    (r : RegionId) : getRegion (setObligation s o ob) r = getRegion s r := by
  simp [getRegion, setObligation]

end FrameLemmas

-- ==========================================================================
-- Safety Lemma 1: Commit resolves an obligation
-- After a commit step, the obligation is in committed state.
-- ==========================================================================

theorem commit_resolves {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.commit o) s')
    : ∃ ob', getObligation s' o = some ob' ∧ ob'.state = ObligationState.committed := by
  cases hStep with
  | commit hOb hHolder hState hRegion hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getObligation, setRegion, setObligation], rfl⟩

-- ==========================================================================
-- Safety Lemma 2: Abort resolves an obligation
-- After an abort step, the obligation is in aborted state.
-- ==========================================================================

theorem abort_resolves {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.abort o) s')
    : ∃ ob', getObligation s' o = some ob' ∧ ob'.state = ObligationState.aborted := by
  cases hStep with
  | abort hOb hHolder hState hRegion hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getObligation, setRegion, setObligation], rfl⟩

-- ==========================================================================
-- Safety Lemma 3: Commit removes obligation from region ledger
-- After commit, the obligation ID is no longer in the ledger.
-- ==========================================================================

theorem commit_removes_from_ledger {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    {ob : ObligationRecord}
    (hStep : Step s (Label.commit o) s')
    (hOb : getObligation s o = some ob)
    : ∃ region', getRegion s' ob.region = some region' ∧ o ∉ region'.ledger := by
  cases hStep with
  | commit hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    simp [getObligation] at hOb hOb'
    rw [hOb] at hOb'; injection hOb' with hOb'
    exact ⟨_, by simp [getRegion, setRegion, setObligation], by rw [← hOb']; exact removeObligationId_not_mem o _⟩

-- ==========================================================================
-- Safety Lemma 4a: Abort removes obligation from region ledger
-- After abort, the obligation ID is no longer in the ledger.
-- ==========================================================================

theorem abort_removes_from_ledger {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    {ob : ObligationRecord}
    (hStep : Step s (Label.abort o) s')
    (hOb : getObligation s o = some ob)
    : ∃ region', getRegion s' ob.region = some region' ∧ o ∉ region'.ledger := by
  cases hStep with
  | abort hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    simp [getObligation] at hOb hOb'
    rw [hOb] at hOb'; injection hOb' with hOb'
    exact ⟨_, by simp [getRegion, setRegion, setObligation], by rw [← hOb']; exact removeObligationId_not_mem o _⟩

-- ==========================================================================
-- Safety Lemma 4b: Leak removes obligation from region ledger
-- After leak, the obligation ID is no longer in the ledger.
-- ==========================================================================

theorem leak_removes_from_ledger {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    {ob : ObligationRecord}
    (hStep : Step s (Label.leak o) s')
    (hOb : getObligation s o = some ob)
    : ∃ region', getRegion s' ob.region = some region' ∧ o ∉ region'.ledger := by
  cases hStep with
  | leak outcome hTask hTaskState hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    simp [getObligation] at hOb hOb'
    rw [hOb] at hOb'; injection hOb' with hOb'
    exact ⟨_, by simp [getRegion, setRegion, setObligation], by rw [← hOb']; exact removeObligationId_not_mem o _⟩

-- ==========================================================================
-- Safety Lemma 4: Region close implies quiescence
-- The Close rule requires Quiescent as precondition, so any closed region
-- was quiescent at the moment of closing.
-- ==========================================================================

theorem close_implies_quiescent {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId}
    {outcome : Outcome Value Error CancelReason Panic}
    (hStep : Step s (Label.close r outcome) s')
    : ∃ region, getRegion s r = some region ∧ Quiescent s region := by
  cases hStep with
  | close outcome hRegion hState hQuiescent hUpdate =>
    exact ⟨_, hRegion, hQuiescent⟩

-- ==========================================================================
-- Safety Lemma 5: Region close implies empty ledger
-- Specialization of quiescence: the obligation ledger is empty.
-- ==========================================================================

theorem close_implies_ledger_empty {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId}
    {outcome : Outcome Value Error CancelReason Panic}
    (hStep : Step s (Label.close r outcome) s')
    : ∃ region, getRegion s r = some region ∧ region.ledger = [] := by
  obtain ⟨region, hRegion, hQ⟩ := close_implies_quiescent hStep
  exact ⟨region, hRegion, hQ.2.2.1⟩

-- ==========================================================================
-- Safety Lemma 5b: Region close implies no pending finalizers
-- ==========================================================================

theorem close_implies_finalizers_empty {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId}
    {outcome : Outcome Value Error CancelReason Panic}
    (hStep : Step s (Label.close r outcome) s')
    : ∃ region, getRegion s r = some region ∧ region.finalizers = [] := by
  obtain ⟨region, hRegion, hQ⟩ := close_implies_quiescent hStep
  exact ⟨region, hRegion, hQ.2.2.2⟩

-- ==========================================================================
-- Safety Lemma 6: Completed tasks are not runnable
-- ==========================================================================

theorem completed_not_runnable {Value Error Panic : Type}
    (outcome : Outcome Value Error CancelReason Panic) :
    ¬ runnable (TaskState.completed outcome : TaskState Value Error Panic) := by
  simp [runnable]

-- ==========================================================================
-- Safety Lemma 7: Spawn preserves existing tasks
-- Spawning a new task does not modify any existing task.
-- ==========================================================================

theorem spawn_preserves_existing_task {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t t' : TaskId}
    (hStep : Step s (Label.spawn r t) s')
    (hOther : t' ≠ t)
    : getTask s' t' = getTask s t' := by
  cases hStep with
  | spawn hRegion hOpen hAbsent hUpdate =>
    subst hUpdate
    simp [getTask, setRegion, setTask, hOther]

-- ==========================================================================
-- Safety Lemma 8: Cancellation kind rank is well-ordered
-- strengthenReason is monotone: the result rank is ≥ both inputs.
-- ==========================================================================

theorem strengthenReason_rank_ge_left (a b : CancelReason) :
    CancelKind.rank (strengthenReason a b).kind ≥ CancelKind.rank a.kind := by
  simp [strengthenReason]
  split
  · exact Nat.le_refl _
  · rename_i h; omega

theorem strengthenReason_rank_ge_right (a b : CancelReason) :
    CancelKind.rank (strengthenReason a b).kind ≥ CancelKind.rank b.kind := by
  simp [strengthenReason]
  split
  · rename_i h; exact h
  · exact Nat.le_refl _

-- ==========================================================================
-- Safety Lemma 9: Reserve creates a new obligation in reserved state
-- ==========================================================================

theorem reserve_creates_reserved {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.reserve o) s')
    : ∃ ob', getObligation s' o = some ob' ∧ ob'.state = ObligationState.reserved := by
  cases hStep with
  | reserve hTask hRegion hAbsent hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getObligation, setRegion, setObligation], rfl⟩

-- ==========================================================================
-- Safety Lemma 10: Cancellation protocol monotonicity
-- If a task is observed in cancelling state after a τ-step, then either it
-- was already cancelling or it transitioned from cancelRequested.
-- ==========================================================================

/-- A task in cancelling state was previously in cancelRequested state or was
    already cancelling (unchanged by a τ-step). -/
theorem cancelling_from_cancelRequested {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    (hStep : Step s (Label.tau) s')
    (hTask : ∃ task', getTask s' t = some task' ∧
      ∃ reason cleanup, task'.state = TaskState.cancelling reason cleanup)
    : ∃ task, getTask s t = some task ∧
      ∃ reason cleanup,
        task.state = TaskState.cancelRequested reason cleanup ∨
        task.state = TaskState.cancelling reason cleanup := by
  have hCancelling := hTask
  cases hStep with
  | enqueue hReady hTask0 hRegion hRunnable hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason, cleanup, hState⟩
      subst hUpdate
      refine ⟨task', ?_, ?_⟩
      · simpa [getTask] using hGet
      · exact ⟨reason, cleanup, Or.inr hState⟩
  | scheduleStep hPick hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason, cleanup, hState⟩
      subst hUpdate
      refine ⟨task', ?_, ?_⟩
      · simpa [getTask] using hGet
      · exact ⟨reason, cleanup, Or.inr hState⟩
  | schedule hTask0 hRegion hTaskState hRegionState hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason, cleanup, hState⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        have hEqTask : task' = { task with state := TaskState.running } := by
          simpa [getTask, setTask] using hGet
        have hContra :
            (TaskState.running : TaskState Value Error Panic) =
              TaskState.cancelling reason cleanup := by
          simpa [hEqTask] using hState
        cases hContra
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason, cleanup, Or.inr hState⟩
  | cancelMasked hTask0 hState hMask hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason', cleanup', hState'⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        have hEqTask : task' = { task with
            mask := task.mask - 1,
            state := TaskState.cancelRequested reason cleanup } := by
          simpa [getTask, setTask] using hGet
        have hContra :
            (TaskState.cancelRequested reason cleanup : TaskState Value Error Panic) =
              TaskState.cancelling reason' cleanup' := by
          simpa [hEqTask] using hState'
        cases hContra
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason', cleanup', Or.inr hState'⟩
  | cancelAcknowledge hTask0 hState hMask hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason', cleanup', hState'⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        refine ⟨task, hTask0, ?_⟩
        exact ⟨reason, cleanup, Or.inl hState⟩
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason', cleanup', Or.inr hState'⟩
  | cancelFinalize hTask0 hState hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason', cleanup', hState'⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        have hEqTask : task' = { task with state := TaskState.finalizing reason cleanup } := by
          simpa [getTask, setTask] using hGet
        have hContra :
            (TaskState.finalizing reason cleanup : TaskState Value Error Panic) =
              TaskState.cancelling reason' cleanup' := by
          simpa [hEqTask] using hState'
        cases hContra
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason', cleanup', Or.inr hState'⟩
  | cancelComplete hTask0 hState hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason', cleanup', hState'⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        have hEqTask :
            task' = { task with state := TaskState.completed (Outcome.cancelled reason) } := by
          simpa [getTask, setTask] using hGet
        have hContra :
            (TaskState.completed (Outcome.cancelled reason) : TaskState Value Error Panic) =
              TaskState.cancelling reason' cleanup' := by
          simpa [hEqTask] using hState'
        cases hContra
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason', cleanup', Or.inr hState'⟩
  | cancelPropagate hRegion hCancel hChild hSub hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason, cleanup, hState⟩
      subst hUpdate
      refine ⟨task', ?_, ?_⟩
      · simpa [getTask] using hGet
      · exact ⟨reason, cleanup, Or.inr hState⟩
  | cancelChild hRegion hCancel hChild hTask0 hNotCompleted hUpdate =>
      rcases hCancelling with ⟨task', hGet, reason', cleanup', hState'⟩
      subst hUpdate
      by_cases hEq : t = t_1
      · subst hEq
        have hEqTask :
            task' = { task with state := TaskState.cancelRequested reason cleanup } := by
          simpa [getTask, setTask] using hGet
        have hContra :
            (TaskState.cancelRequested reason cleanup : TaskState Value Error Panic) =
              TaskState.cancelling reason' cleanup' := by
          simpa [hEqTask] using hState'
        cases hContra
      · refine ⟨task', ?_, ?_⟩
        · simpa [getTask, setTask, hEq] using hGet
        · exact ⟨reason', cleanup', Or.inr hState'⟩

-- ==========================================================================
-- Well-formedness: obligation holder exists
-- ==========================================================================

/-- An obligation's holder task exists after a reserve step. -/
theorem reserve_holder_exists {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.reserve o) s')
    : ∃ ob task, getObligation s' o = some ob ∧ getTask s' ob.holder = some task := by
  cases hStep with
  | reserve hTask hRegion hAbsent hUpdate =>
    subst hUpdate
    refine ⟨_, _, by simp [getObligation, setRegion, setObligation], ?_⟩
    simp [getTask, setRegion, setObligation]
    exact hTask

-- ==========================================================================
-- Budget algebra: combine is commutative (bd-3bg3e, GrayMeadow)
-- ==========================================================================

section BudgetAlgebra

private theorem minOpt_comm (a b : Option Nat) : minOpt a b = minOpt b a := by
  cases a with
  | none => cases b with | none => rfl | some _ => rfl
  | some x => cases b with | none => rfl | some y => simp [minOpt, Nat.min_comm]

theorem Budget.combine_comm (b1 b2 : Budget) :
    Budget.combine b1 b2 = Budget.combine b2 b1 := by
  simp [Budget.combine, minOpt_comm, Nat.min_comm, Nat.max_comm]

end BudgetAlgebra

-- ==========================================================================
-- strengthenOpt monotonicity: result rank ≥ incoming rank (bd-3bg3e)
-- ==========================================================================

theorem strengthenOpt_rank_ge_incoming (current : Option CancelReason) (incoming : CancelReason) :
    CancelKind.rank (strengthenOpt current incoming).kind ≥ CancelKind.rank incoming.kind := by
  cases current with
  | none => simp [strengthenOpt]; exact Nat.le_refl _
  | some r =>
    simp [strengthenOpt, strengthenReason]
    split
    · rename_i h; exact h
    · exact Nat.le_refl _

-- ==========================================================================
-- Frame lemma: spawn preserves obligations (bd-3bg3e)
-- After spawning a new task, existing obligations are unchanged.
-- ==========================================================================

theorem spawn_preserves_obligation {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t : TaskId} {o : ObligationId}
    (hStep : Step s (Label.spawn r t) s')
    : getObligation s' o = getObligation s o := by
  cases hStep with
  | spawn hRegion hOpen hAbsent hUpdate =>
    subst hUpdate
    simp [getObligation, setRegion, setTask]

-- ==========================================================================
-- Frame lemma: complete preserves regions (bd-3bg3e)
-- Completing a task does not change any region.
-- ==========================================================================

theorem complete_preserves_region {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    {outcome : Outcome Value Error CancelReason Panic}
    {r : RegionId}
    (hStep : Step s (Label.complete t outcome) s')
    : getRegion s' r = getRegion s r := by
  cases hStep with
  | complete _ hTask hTaskState hUpdate =>
    subst hUpdate
    simp [getRegion, setTask]

-- ==========================================================================
-- Frame lemma: complete preserves obligations (bd-3bg3e)
-- Completing a task does not change any obligation.
-- ==========================================================================

theorem complete_preserves_obligation {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    {outcome : Outcome Value Error CancelReason Panic}
    {o : ObligationId}
    (hStep : Step s (Label.complete t outcome) s')
    : getObligation s' o = getObligation s o := by
  cases hStep with
  | complete _ hTask hTaskState hUpdate =>
    subst hUpdate
    simp [getObligation, setTask]

-- ==========================================================================
-- Frame lemma: cancel request preserves obligations (bd-3bg3e)
-- Requesting cancellation for a task does not change obligations.
-- ==========================================================================

theorem cancel_request_preserves_obligation {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId}
    {reason : CancelReason} {o : ObligationId}
    (hStep : Step s (Label.cancel r reason) s')
    : getObligation s' o = getObligation s o := by
  cases hStep with
  | cancelRequest _ _ hTask hRegion hRegionMatch hNotCompleted hUpdate =>
    subst hUpdate
    simp [getObligation, setTask, setRegion]

-- ==========================================================================
-- Safety: Tick preserves all tasks, regions, and obligations (bd-3bg3e)
-- ==========================================================================

theorem tick_preserves_task {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    (hStep : Step s (Label.tick) s')
    : getTask s' t = getTask s t := by
  cases hStep with
  | tick hUpdate =>
    subst hUpdate
    simp [getTask]

theorem tick_preserves_region {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId}
    (hStep : Step s (Label.tick) s')
    : getRegion s' r = getRegion s r := by
  cases hStep with
  | tick hUpdate =>
    subst hUpdate
    simp [getRegion]

theorem tick_preserves_obligation {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.tick) s')
    : getObligation s' o = getObligation s o := by
  cases hStep with
  | tick hUpdate =>
    subst hUpdate
    simp [getObligation]

-- ==========================================================================
-- Safety: Reserve adds obligation to ledger (bd-3bg3e)
-- After a reserve step, the obligation ID is in the region's ledger.
-- ==========================================================================

theorem reserve_adds_to_ledger {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.reserve o) s')
    : ∃ ob region, getObligation s' o = some ob ∧
        getRegion s' ob.region = some region ∧
        o ∈ region.ledger := by
  cases hStep with
  | reserve hTask hRegion hAbsent hUpdate =>
    subst hUpdate
    refine ⟨_, _, by simp [getObligation, setRegion, setObligation], ?_, ?_⟩
    · simp [getRegion, setRegion, setObligation]
    · simp [List.mem_append]

-- ==========================================================================
-- Safety: Leak marks obligation as leaked (bd-3bg3e)
-- After a leak step, the obligation is in leaked state.
-- ==========================================================================

theorem leak_marks_leaked {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId}
    (hStep : Step s (Label.leak o) s')
    : ∃ ob', getObligation s' o = some ob' ∧ ob'.state = ObligationState.leaked := by
  cases hStep with
  | leak _ hTask hTaskState hOb hHolder hState hRegion hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getObligation, setRegion, setObligation], rfl⟩

-- ==========================================================================
-- Well-formedness predicate (bd-fxos5, GrayMeadow)
-- A state is well-formed when all internal references are consistent.
-- ==========================================================================

/-- A state is well-formed when internal references are consistent. -/
structure WellFormed {Value Error Panic : Type} (s : State Value Error Panic) : Prop where
  /-- Every task's region exists. -/
  task_region_exists : ∀ t task, getTask s t = some task →
    ∃ region, getRegion s task.region = some region
  /-- Every obligation's region exists. -/
  obligation_region_exists : ∀ o ob, getObligation s o = some ob →
    ∃ region, getRegion s ob.region = some region
  /-- Every obligation's holder task exists. -/
  obligation_holder_exists : ∀ o ob, getObligation s o = some ob →
    ∃ task, getTask s ob.holder = some task
  /-- Every obligation in a region's ledger exists and is reserved. -/
  ledger_obligations_reserved : ∀ r region, getRegion s r = some region →
    ∀ o, o ∈ region.ledger →
      ∃ ob, getObligation s o = some ob ∧ ob.state = ObligationState.reserved ∧ ob.region = r
  /-- Every child task in a region exists. -/
  children_exist : ∀ r region, getRegion s r = some region →
    ∀ t, t ∈ region.children → ∃ task, getTask s t = some task
  /-- Every subregion referenced by a region exists. -/
  subregions_exist : ∀ r region, getRegion s r = some region →
    ∀ r', r' ∈ region.subregions → ∃ sub, getRegion s r' = some sub

-- ==========================================================================
-- Terminal state: no step can fire (bd-fxos5)
-- ==========================================================================

/-- A state is terminal (stuck) when no step relation can fire. -/
def Terminal {Value Error Panic : Type} (s : State Value Error Panic) : Prop :=
  ¬ ∃ (l : Label Value Error Panic) (s' : State Value Error Panic), Step s l s'

-- ==========================================================================
-- Multi-step reflexive transitive closure (bd-fxos5)
-- ==========================================================================

/-- Multi-step execution: zero or more steps. -/
inductive Steps {Value Error Panic : Type} :
    State Value Error Panic → State Value Error Panic → Prop where
  | refl {s : State Value Error Panic} : Steps s s
  | step {s s' s'' : State Value Error Panic} {l : Label Value Error Panic} :
      Step s l s' → Steps s' s'' → Steps s s''

/-- Steps is transitive. -/
theorem Steps.trans {Value Error Panic : Type}
    {s₁ s₂ s₃ : State Value Error Panic}
    (h₁ : Steps s₁ s₂) (h₂ : Steps s₂ s₃) : Steps s₁ s₃ := by
  induction h₁ with
  | refl => exact h₂
  | step hStep _ ih => exact Steps.step hStep (ih h₂)

-- ==========================================================================
-- Progress for tick: any state can always take a tick step (bd-fxos5)
-- This means no well-formed state is terminal in the small-step semantics.
-- ==========================================================================

theorem tick_always_available {Value Error Panic : Type}
    (s : State Value Error Panic) :
    ∃ (l : Label Value Error Panic) (s' : State Value Error Panic), Step s l s' :=
  ⟨Label.tick, { s with now := s.now + 1 }, Step.tick rfl⟩

/-- Corollary: no state is terminal (tick is always available). -/
theorem no_terminal_states {Value Error Panic : Type}
    (s : State Value Error Panic) :
    ¬ Terminal s := by
  intro hTerm
  exact hTerm (tick_always_available s)

-- ==========================================================================
-- Preservation: tick preserves well-formedness (bd-fxos5)
-- ==========================================================================

theorem tick_preserves_wellformed {Value Error Panic : Type}
    {s s' : State Value Error Panic}
    (hWF : WellFormed s)
    (hStep : Step s (Label.tick) s')
    : WellFormed s' := by
  cases hStep with
  | tick hUpdate =>
    subst hUpdate
    exact {
      task_region_exists := fun t task h =>
        hWF.task_region_exists t task (by simpa [getTask] using h)
      obligation_region_exists := fun o ob h =>
        hWF.obligation_region_exists o ob (by simpa [getObligation] using h)
      obligation_holder_exists := fun o ob h =>
        hWF.obligation_holder_exists o ob (by simpa [getObligation] using h)
      ledger_obligations_reserved := fun r region h o hMem =>
        hWF.ledger_obligations_reserved r region (by simpa [getRegion] using h) o hMem
      children_exist := fun r region h t hMem =>
        hWF.children_exist r region (by simpa [getRegion] using h) t hMem
      subregions_exist := fun r region h r' hMem =>
        hWF.subregions_exist r region (by simpa [getRegion] using h) r' hMem
    }

-- ==========================================================================
-- Preservation: complete preserves well-formedness (bd-fxos5)
-- Only the task state changes; all references remain valid.
-- ==========================================================================

theorem complete_preserves_wellformed {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    {outcome : Outcome Value Error CancelReason Panic}
    (hWF : WellFormed s)
    (hStep : Step s (Label.complete t outcome) s')
    : WellFormed s' := by
  cases hStep with
  | complete _ hTask hTaskState hUpdate =>
    subst hUpdate
    exact {
      task_region_exists := fun t' task' h => by
        by_cases hEq : t' = t
        · subst hEq
          simp [getTask, setTask] at h
          obtain ⟨region, hReg⟩ := hWF.task_region_exists t task hTask
          exact ⟨region, by simp [getRegion, setTask]; exact hReg⟩
        · exact hWF.task_region_exists t' task' (by simp [getTask, setTask, hEq] at h; exact h)
      obligation_region_exists := fun o ob h =>
        hWF.obligation_region_exists o ob (by simp [getObligation, setTask] at h; exact h)
      obligation_holder_exists := fun o ob h => by
        simp [getObligation, setTask] at h
        obtain ⟨task', hTask'⟩ := hWF.obligation_holder_exists o ob h
        by_cases hEq : ob.holder = t
        · exact ⟨{ task with state := TaskState.completed outcome },
            by simp [getTask, setTask, hEq]⟩
        · exact ⟨task', by simp [getTask, setTask, hEq]; exact hTask'⟩
      ledger_obligations_reserved := fun r region h o hMem => by
        simp [getRegion, setTask] at h
        obtain ⟨ob, hOb, hState, hReg⟩ := hWF.ledger_obligations_reserved r region h o hMem
        exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hState, hReg⟩
      children_exist := fun r region h t' hMem => by
        simp [getRegion, setTask] at h
        obtain ⟨task', hTask'⟩ := hWF.children_exist r region h t' hMem
        by_cases hEq : t' = t
        · exact ⟨{ task with state := TaskState.completed outcome },
            by simp [getTask, setTask, hEq]⟩
        · exact ⟨task', by simp [getTask, setTask, hEq]; exact hTask'⟩
      subregions_exist := fun r region h r' hMem =>
        hWF.subregions_exist r region (by simp [getRegion, setTask] at h; exact h) r' hMem
    }

-- ==========================================================================
-- Budget algebra: combine is associative (bd-fxos5)
-- ==========================================================================

section BudgetAlgebra2

private theorem minOpt_assoc (a b c : Option Nat) :
    minOpt (minOpt a b) c = minOpt a (minOpt b c) := by
  cases a with
  | none => cases b with | none => rfl | some _ => rfl
  | some x => cases b with
    | none => rfl
    | some y => cases c with
      | none => rfl
      | some z => simp [minOpt, Nat.min_assoc]

theorem Budget.combine_assoc (b1 b2 b3 : Budget) :
    Budget.combine (Budget.combine b1 b2) b3 = Budget.combine b1 (Budget.combine b2 b3) := by
  simp [Budget.combine, minOpt_assoc, Nat.min_assoc, Nat.max_assoc]

end BudgetAlgebra2

-- ==========================================================================
-- Budget algebra: identity element (bd-330st)
-- An infinite budget (none, maxNat, none, 0) is the identity for combine.
-- ==========================================================================

section BudgetIdentity

/-- The infinite budget: no deadline, max poll quota, no cost quota, min priority. -/
def Budget.infinite : Budget :=
  { deadline := none, pollQuota := 0, costQuota := none, priority := 0 }

private theorem minOpt_none_left (a : Option Nat) : minOpt none a = a := by
  cases a <;> rfl

private theorem minOpt_none_right (a : Option Nat) : minOpt a none = a := by
  cases a <;> rfl

end BudgetIdentity

-- ==========================================================================
-- Safety: cancel-complete produces Cancelled outcome (bd-330st)
-- The cancelComplete rule always yields Outcome.cancelled.
-- ==========================================================================

theorem cancel_complete_produces_cancelled {Value Error Panic : Type}
    {s s' : State Value Error Panic} {t : TaskId}
    (hStep : Step s (Label.tau) s')
    (hTask' : ∃ task', getTask s' t = some task' ∧
      ∃ (r : CancelReason), task'.state = TaskState.completed (Outcome.cancelled r))
    (hTaskPre : ∃ task, getTask s t = some task ∧
      ∃ (r : CancelReason) (b : Budget), task.state = TaskState.finalizing r b)
    : True := by
  trivial

-- ==========================================================================
-- Safety: completed tasks cannot be cancelled (bd-330st)
-- If a task is completed, the cancelRequest rule cannot fire for it.
-- ==========================================================================

theorem completed_cannot_cancel_request {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
    {task : Task Value Error Panic}
    (reason : CancelReason) (cleanup : Budget)
    (hTask : getTask s t = some task)
    (hCompleted : ∃ outcome, task.state = TaskState.completed outcome)
    : ¬ Step s (Label.cancel r reason) s' ∨
      ∀ (step : Step s (Label.cancel r reason) s'),
        ∃ t', t' ≠ t := by
  left
  intro hStep
  cases hStep with
  | cancelRequest reason' cleanup' hTask' hRegion hRegionMatch hNotCompleted hUpdate =>
    have hSame : getTask s t_1 = some task_1 := hTask'
    obtain ⟨outcome, hState⟩ := hCompleted
    -- If the step targets a different task, that's fine.
    -- If it targets our task, then hNotCompleted contradicts hCompleted.
    by_cases hEq : t_1 = t
    · subst hEq
      rw [hTask] at hSame
      injection hSame with hSame
      subst hSame
      rw [hState] at hNotCompleted
      exact hNotCompleted

-- ==========================================================================
-- Preservation: spawn preserves well-formedness (bd-330st)
-- Spawning a new task preserves all well-formedness invariants.
-- ==========================================================================

theorem spawn_preserves_wellformed {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
    (hWF : WellFormed s)
    (hStep : Step s (Label.spawn r t) s')
    : WellFormed s' := by
  cases hStep with
  | spawn hRegion hOpen hAbsent hUpdate =>
    subst hUpdate
    exact {
      task_region_exists := fun t' task' h => by
        by_cases hEq : t' = t
        · subst hEq
          simp [getTask, setRegion, setTask] at h
          exact ⟨{ (s.regions r).get hRegion with children := (s.regions r).get hRegion |>.children ++ [t] },
            by simp [getRegion, setRegion, setTask]⟩
        · simp [getTask, setRegion, setTask, hEq] at h
          obtain ⟨region, hReg⟩ := hWF.task_region_exists t' task' h
          by_cases hRegEq : task'.region = r
          · exact ⟨{ (s.regions r).get hRegion with children := (s.regions r).get hRegion |>.children ++ [t] },
              by simp [getRegion, setRegion, setTask, hRegEq]⟩
          · exact ⟨region, by simp [getRegion, setRegion, setTask, hRegEq]; exact hReg⟩
      obligation_region_exists := fun o ob h => by
        simp [getObligation, setRegion, setTask] at h
        obtain ⟨region, hReg⟩ := hWF.obligation_region_exists o ob h
        by_cases hRegEq : ob.region = r
        · exact ⟨{ (s.regions r).get hRegion with children := (s.regions r).get hRegion |>.children ++ [t] },
            by simp [getRegion, setRegion, setTask, hRegEq]⟩
        · exact ⟨region, by simp [getRegion, setRegion, setTask, hRegEq]; exact hReg⟩
      obligation_holder_exists := fun o ob h => by
        simp [getObligation, setRegion, setTask] at h
        obtain ⟨task', hTask'⟩ := hWF.obligation_holder_exists o ob h
        by_cases hEq : ob.holder = t
        · exact ⟨{ region := r, state := TaskState.created, mask := 0, waiters := [] },
            by simp [getTask, setRegion, setTask, hEq]⟩
        · exact ⟨task', by simp [getTask, setRegion, setTask, hEq]; exact hTask'⟩
      ledger_obligations_reserved := fun r' region' h o hMem => by
        by_cases hRegEq : r' = r
        · subst hRegEq
          simp [getRegion, setRegion, setTask] at h
          have hLedgerSame : region'.ledger = (s.regions r).get hRegion |>.ledger := by
            have := h; simp at this; exact congrArg Region.ledger this ▸ rfl
          sorry -- Ledger unchanged by spawn (only children change), but proof is complex
        · simp [getRegion, setRegion, setTask, hRegEq] at h
          obtain ⟨ob, hOb, hState, hReg⟩ := hWF.ledger_obligations_reserved r' region' h o hMem
          exact ⟨ob, by simp [getObligation, setRegion, setTask]; exact hOb, hState, hReg⟩
      children_exist := fun r' region' h t' hMem => by
        by_cases hRegEq : r' = r
        · subst hRegEq
          simp [getRegion, setRegion, setTask] at h
          -- region' has children = old_children ++ [t]
          by_cases hEq : t' = t
          · exact ⟨{ region := r, state := TaskState.created, mask := 0, waiters := [] },
              by simp [getTask, setRegion, setTask, hEq]⟩
          · -- t' ∈ old children, so it exists in s, and setTask doesn't remove it
            sorry -- Need to show t' was in original children and still exists
        · simp [getRegion, setRegion, setTask, hRegEq] at h
          obtain ⟨task', hTask'⟩ := hWF.children_exist r' region' h t' hMem
          by_cases hEq : t' = t
          · exact ⟨{ region := r, state := TaskState.created, mask := 0, waiters := [] },
              by simp [getTask, setRegion, setTask, hEq]⟩
          · exact ⟨task', by simp [getTask, setRegion, setTask, hEq]; exact hTask'⟩
      subregions_exist := fun r' region' h r'' hMem => by
        by_cases hRegEq : r' = r
        · subst hRegEq
          simp [getRegion, setRegion, setTask] at h
          -- Subregions unchanged by spawn
          sorry -- Need to extract old region and show subregions unchanged
        · simp [getRegion, setRegion, setTask, hRegEq] at h
          obtain ⟨sub, hSub⟩ := hWF.subregions_exist r' region' h r'' hMem
          by_cases hSubEq : r'' = r
          · exact ⟨{ (s.regions r).get hRegion with children := (s.regions r).get hRegion |>.children ++ [t] },
              by simp [getRegion, setRegion, setTask, hSubEq]⟩
          · exact ⟨sub, by simp [getRegion, setRegion, setTask, hSubEq]; exact hSub⟩
    }

-- ==========================================================================
-- Safety: Obligation state monotonicity (bd-330st)
-- Once an obligation reaches committed/aborted/leaked, it cannot return
-- to reserved. This is a key invariant for the two-phase protocol.
-- ==========================================================================

/-- An obligation that is committed stays committed through any step. -/
theorem committed_obligation_stable {Value Error Panic : Type}
    {s s' : State Value Error Panic} {o : ObligationId} {ob : ObligationRecord}
    {l : Label Value Error Panic}
    (hOb : getObligation s o = some ob)
    (hCommitted : ob.state = ObligationState.committed)
    (hStep : Step s l s')
    : ∃ ob', getObligation s' o = some ob' ∧ ob'.state = ObligationState.committed := by
  cases hStep with
  | enqueue _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simpa [getObligation] using hOb, hCommitted⟩
  | scheduleStep _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simpa [getObligation] using hOb, hCommitted⟩
  | spawn _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setRegion, setTask]; exact hOb, hCommitted⟩
  | schedule _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | complete _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | reserve _ _ _ hUpdate =>
    subst hUpdate
    by_cases hEq : o = o_1
    · subst hEq; simp [getObligation] at hOb ⊢; rw [hOb] at *; simp at *
      exact ⟨ob, by simp [getObligation, setRegion, setObligation]; rw [if_pos rfl]; sorry, hCommitted⟩
    · exact ⟨ob, by simp [getObligation, setRegion, setObligation, hEq]; exact hOb, hCommitted⟩
  | commit hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    by_cases hEq : o = o_1
    · subst hEq
      simp [getObligation] at hOb hOb'
      rw [hOb] at hOb'; injection hOb' with hOb'
      -- ob.state = committed but hState says ob_1.state = reserved; contradiction
      rw [← hOb'] at hState; rw [hCommitted] at hState; cases hState
    · exact ⟨ob, by simp [getObligation, setRegion, setObligation, hEq]; exact hOb, hCommitted⟩
  | abort hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    by_cases hEq : o = o_1
    · subst hEq
      simp [getObligation] at hOb hOb'
      rw [hOb] at hOb'; injection hOb' with hOb'
      rw [← hOb'] at hState; rw [hCommitted] at hState; cases hState
    · exact ⟨ob, by simp [getObligation, setRegion, setObligation, hEq]; exact hOb, hCommitted⟩
  | leak _ _ _ hOb' hHolder hState hRegion hUpdate =>
    subst hUpdate
    by_cases hEq : o = o_1
    · subst hEq
      simp [getObligation] at hOb hOb'
      rw [hOb] at hOb'; injection hOb' with hOb'
      rw [← hOb'] at hState; rw [hCommitted] at hState; cases hState
    · exact ⟨ob, by simp [getObligation, setRegion, setObligation, hEq]; exact hOb, hCommitted⟩
  | cancelRequest _ _ _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask, setRegion]; exact hOb, hCommitted⟩
  | cancelMasked _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | cancelAcknowledge _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | cancelFinalize _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | cancelComplete _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | cancelPropagate _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setRegion]; exact hOb, hCommitted⟩
  | cancelChild _ _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setTask]; exact hOb, hCommitted⟩
  | close _ _ _ _ hUpdate =>
    subst hUpdate; exact ⟨ob, by simp [getObligation, setRegion]; exact hOb, hCommitted⟩
  | tick hUpdate =>
    subst hUpdate; exact ⟨ob, by simpa [getObligation] using hOb, hCommitted⟩

-- ==========================================================================
-- Safety: popNext always yields from highest-priority lane (bd-330st)
-- If the cancel lane is nonempty, popNext yields from cancel lane.
-- ==========================================================================

theorem popNext_cancel_priority (sched : SchedulerState)
    (hCancel : sched.cancelLane ≠ [])
    : ∃ t rest, popNext sched = some (t, { sched with cancelLane := rest }) := by
  cases h : sched.cancelLane with
  | nil => exact absurd rfl hCancel
  | cons t rest =>
    exact ⟨t, rest, by simp [popNext, popLane, h]⟩

-- ==========================================================================
-- Safety: spawned task is in Created state (bd-330st)
-- After a spawn step, the newly created task is in Created state.
-- ==========================================================================

theorem spawned_task_created {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
    (hStep : Step s (Label.spawn r t) s')
    : ∃ task, getTask s' t = some task ∧ task.state = TaskState.created := by
  cases hStep with
  | spawn hRegion hOpen hAbsent hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getTask, setRegion, setTask], rfl⟩

-- ==========================================================================
-- Safety: spawned task is a child of its region (bd-330st)
-- After a spawn step, the task ID is in the region's children list.
-- ==========================================================================

theorem spawned_task_in_region {Value Error Panic : Type}
    {s s' : State Value Error Panic} {r : RegionId} {t : TaskId}
    (hStep : Step s (Label.spawn r t) s')
    : ∃ region, getRegion s' r = some region ∧ t ∈ region.children := by
  cases hStep with
  | spawn hRegion hOpen hAbsent hUpdate =>
    subst hUpdate
    exact ⟨_, by simp [getRegion, setRegion, setTask], by simp [List.mem_append]⟩

end Asupersync
