    use super::*;
    use crate::atp::object::ContentId;
    use std::future::Future;

    /// Drive a future that completes without yielding (the actor's message
    /// handlers contain no await points).
    fn poll_ready<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("future was not immediately ready"),
        }
    }

    fn insert_active_session(actor: &mut TransferActor, counter: u64) -> SessionId {
        let object_id = ObjectId::content(ContentId::from_bytes(b"pressure-object"));
        let session_id = SessionId::new(object_id.clone(), counter);
        let mut session = TransferSession::new(
            session_id.clone(),
            object_id,
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(2, 0),
            TransferBrainConfig::default(),
            TraceId::from_raw(3),
        );
        session.transition_to(SessionState::Active);
        actor.sessions.insert(session_id.clone(), session);
        session_id
    }

    #[test]
    fn pressure_auto_pause_then_auto_resume() {
        let (mut actor, _handle) = TransferActor::new(TransferActorConfig::default());
        let session_id = insert_active_session(&mut actor, 1);

        let high = SystemPressure {
            cpu_utilization: 0.99,
            ..SystemPressure::default()
        };
        poll_ready(actor.update_pressure(high));
        assert_eq!(actor.sessions[&session_id].state, SessionState::Paused);
        assert!(actor.sessions[&session_id].auto_paused);

        // Recovery below the hysteresis band must resume the session;
        // previously a pressure-pause was permanent (no auto-resume path).
        let low = SystemPressure {
            cpu_utilization: 0.1,
            ..SystemPressure::default()
        };
        poll_ready(actor.update_pressure(low));
        assert_eq!(actor.sessions[&session_id].state, SessionState::Active);
        assert!(!actor.sessions[&session_id].auto_paused);
    }

    #[test]
    fn explicit_pause_survives_pressure_recovery() {
        let (mut actor, _handle) = TransferActor::new(TransferActorConfig::default());
        let session_id = insert_active_session(&mut actor, 2);

        poll_ready(actor.pause_session(session_id.clone())).expect("pause session");
        assert_eq!(actor.sessions[&session_id].state, SessionState::Paused);

        let low = SystemPressure {
            cpu_utilization: 0.1,
            ..SystemPressure::default()
        };
        poll_ready(actor.update_pressure(low));
        assert_eq!(
            actor.sessions[&session_id].state,
            SessionState::Paused,
            "explicitly paused sessions must not auto-resume"
        );
    }

    #[test]
    fn test_transfer_actor_creation() {
        let config = TransferActorConfig::default();
        let (actor, _handle) = TransferActor::new(config);

        assert_eq!(actor.session_counter, 0);
        assert!(actor.sessions.is_empty());
    }

    #[test]
    fn completed_response_survives_actor_context_cancellation() {
        let (mut actor, _handle) = TransferActor::new(TransferActorConfig::default());
        let cx: Cx = Cx::for_testing();
        cx.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel before terminal response publication"),
        );
        let (response_tx, mut response_rx) = oneshot::channel();

        poll_ready(actor.handle_message(&cx, TransferMessage::GetAllSessions { response_tx }))
            .expect("message handling itself must complete");

        let sessions = response_rx
            .try_recv()
            .expect("the completed response must be published independently of actor cancellation")
            .expect("an empty actor must return a valid session list");
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_session_state_transition() {
        let object_id = ObjectId::content(ContentId::from_bytes(b"test-object"));
        let session_id = SessionId::new(object_id.clone(), 1);
        let mut session = TransferSession::new(
            session_id,
            object_id,
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(2, 0),
            TransferBrainConfig::default(),
            TraceId::from_raw(3),
        );

        assert_eq!(session.state, SessionState::Initializing);
        session.transition_to(SessionState::Active);
        assert_eq!(session.state, SessionState::Active);
    }
