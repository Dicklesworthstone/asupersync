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
  exact ⟨region, hRegion, hQ.2.2⟩

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

end Asupersync
