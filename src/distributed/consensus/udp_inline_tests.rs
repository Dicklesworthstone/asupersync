    use super::*;
    use crate::cx::Cx;
    use crate::distributed::consensus::authenticated::{
        AuthenticatedPbftNode, PbftIngressOutcome, PbftMembership,
    };
    use crate::distributed::consensus::pbft::{PbftConfig, PbftMessage, PbftStateMachine};
    use crate::distributed::consensus::types::{
        ConsensusRequest, ConsensusResponse, MessageDigest, SequenceNumber, ViewNumber,
    };
    use crate::runtime::RuntimeBuilder;
    use crate::types::{CancelKind, Outcome, Time};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::future::{Future, poll_fn};
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    fn auth(local: usize, limit: usize) -> Arc<PbftAuthenticator> {
        let key = |index: usize| {
            let seed: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..4).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([8; 32], 11, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), limit,
        ).unwrap())
    }

    fn sockets() -> (Vec<StdUdpSocket>, Vec<SocketAddr>) {
        let sockets: Vec<_> = (0..4).map(|_| StdUdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        let routes = sockets.iter().map(|socket| socket.local_addr().unwrap()).collect();
        (sockets, routes)
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("native-client".into(), Time::from_millis(41), b"native-bytes".to_vec())
    }

    #[derive(Clone, Default)]
    struct Application(Arc<StdMutex<Vec<Vec<u8>>>>);

    struct RelayWake {
        parent: Waker,
        count: Arc<AtomicUsize>,
    }

    impl Wake for RelayWake {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.parent.wake_by_ref();
        }
    }

    impl PbftStateMachine for Application {
        fn apply(&mut self, request: &ConsensusRequest) -> Outcome<Vec<u8>, String> {
            self.0.lock().unwrap().push(request.operation.clone());
            let mut result = b"native-result:".to_vec();
            result.extend_from_slice(&request.operation);
            Outcome::Ok(result)
        }
    }

    #[test]
    fn native_signed_quorum_executes_on_both_runtime_models_with_a_silent_backup() {
        for workers in [false, true] {
            for live in [4, 3] {
                let runtime = if workers {
                    RuntimeBuilder::new().worker_threads(2).build().unwrap()
                } else {
                    RuntimeBuilder::current_thread().build().unwrap()
                };
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (sockets, routes) = sockets();
                    let mut inactive = Vec::new();
                    let applications: Vec<_> = (0..live).map(|_| Application::default()).collect();
                    let mut nodes = Vec::new();
                    for (local, socket) in sockets.into_iter().enumerate() {
                        if local >= live {
                            inactive.push(socket); // Bound but deliberately never responds.
                            continue;
                        }
                        let auth = auth(local, 4096);
                        let wire = UdpPbftTransport::new(
                            UdpSocket::from_std(socket).unwrap(), &auth, routes.clone(),
                        ).unwrap();
                        nodes.push(AuthenticatedPbftNode::new(
                            PbftConfig::new(4, 1).unwrap(), wire, auth, applications[local].clone(),
                        ).unwrap());
                    }
                    let request = request();
                    nodes[0].submit_request(&cx, request.clone()).await.unwrap();
                    let responses = {
                        // Drive each node in the same owned root future. Keep
                        // pending node futures alive, never cancel another
                        // node's partially processed packet merely because a
                        // peer made progress. No spawned protocol tasks.
                        let mut pumps: Vec<_> = nodes.iter_mut().map(|node| {
                            let cx = &cx;
                            let request = &request;
                            Box::pin(async move {
                                loop {
                                    if let Some(response) = node.committed_response(request)? {
                                        return Ok::<_, Error>(response);
                                    }
                                    node.receive_one(cx).await?;
                                    crate::runtime::yield_now().await;
                                }
                            })
                        }).collect();
                        let mut outputs: Vec<Option<ConsensusResponse>> = (0..live).map(|_| None).collect();
                        let join = poll_fn(|task| {
                            for (index, pump) in pumps.iter_mut().enumerate() {
                                if outputs[index].is_some() { continue; }
                                match pump.as_mut().poll(task) {
                                    Poll::Ready(Ok(response)) => outputs[index] = Some(response),
                                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                    Poll::Pending => {}
                                }
                            }
                            if outputs.iter().all(Option::is_some) {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        });
                        crate::time::timeout(cx.now(), Duration::from_secs(5), join)
                            .await.expect("native quorum deadline").expect("native quorum result");
                        outputs
                    };
                    for (index, response) in responses.into_iter().enumerate() {
                        let response = response.unwrap();
                        assert_eq!(response.sequence, SequenceNumber::new(1));
                        assert_eq!(response.result, Outcome::Ok(b"native-result:native-bytes".to_vec()));
                        assert_eq!(applications[index].0.lock().unwrap().as_slice(), &[b"native-bytes".to_vec()]);
                        let replay = nodes[index].submit_and_wait(&cx, request.clone()).await.unwrap();
                        assert_eq!(replay.sequence, response.sequence);
                        assert_eq!(replay.result, response.result);
                        assert_eq!(applications[index].0.lock().unwrap().len(), 1);
                    }
                    drop(inactive);
                });
                assert!(runtime.is_quiescent());
            }
        }
    }

    #[test]
    fn native_receive_lease_returns_after_witnessed_pending_drop_or_cancellation() {
        for cancel in [false, true] {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            runtime.block_on(async {
                let (mut sockets, routes) = sockets();
                let receiver = sockets.remove(1);
                let authority = auth(1, 4096);
                let wire = UdpPbftTransport::new(UdpSocket::from_std(receiver).unwrap(), &authority, routes.clone()).unwrap();
                let mut node = AuthenticatedPbftNode::new(
                    PbftConfig::new(4, 1).unwrap(), wire, authority, Application::default(),
                ).unwrap();
                // `receive_one` uses this context only as a cancel token
                // (`until_stopped`); the socket recv parks on the ambient
                // reactor, not on `cx`. A full-cap testing context supplies the
                // independent cancel node this branch needs while satisfying
                // `receive_one(&Cx)`, mirroring driver.rs
                // `parked_receive_is_woken_by_cancellation_and_its_future_is_dropped`.
                // `Cx::detached_cancel_context()` is `Cx<cap::None>` and does
                // not type-check against the full-cap `&Cx` parameter.
                let stop = Cx::for_testing();
                {
                    let mut receive = Box::pin(node.receive_one(&stop));
                    let wakes = Arc::new(AtomicUsize::new(0));
                    poll_fn(|task| {
                        let relay = Waker::from(Arc::new(RelayWake {
                            parent: task.waker().clone(),
                            count: Arc::clone(&wakes),
                        }));
                        assert!(receive.as_mut().poll(&mut Context::from_waker(&relay)).is_pending(), "must register native receive first");
                        Poll::Ready(())
                    }).await;
                    if cancel {
                        let before = wakes.load(Ordering::SeqCst);
                        stop.cancel_fast(CancelKind::User);
                        assert!(wakes.load(Ordering::SeqCst) > before, "native wait must be woken before repoll");
                        assert!(receive.await.unwrap_err().is_cancelled());
                    } else {
                        drop(receive);
                    }
                }
                // A complete signed vote after retirement proves the socket
                // was returned and remains usable, not merely that we exited.
                let primary = auth(0, 4096);
                let vote = PbftMessage::Prepare {
                    view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
                    digest: MessageDigest::from_bytes([4; 32]), replica_id: ReplicaId::new("0".into()),
                };
                let packet = primary.seal(None, &vote).unwrap();
                sockets[0].send_to(&packet, routes[1]).unwrap();
                let cx = Cx::current().unwrap();
                let result = crate::time::timeout(cx.now(), Duration::from_secs(2), node.receive_one(&cx)).await.unwrap().unwrap();
                assert_eq!(result, PbftIngressOutcome::Processed);
                assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
            });
            assert!(runtime.is_quiescent());
        }
    }

    #[test]
    fn native_receive_rejects_truncated_signed_prefix_and_foreign_source() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let (mut sockets, routes) = sockets();
            let receiver = sockets.remove(1);
            let authority = auth(1, 4096);
            let limit = authority.max_packet_bytes();
            let wire = UdpPbftTransport::new(UdpSocket::from_std(receiver).unwrap(), &authority, routes.clone()).unwrap();
            let primary = auth(0, 4096);
            let packet = primary.seal(None, &PbftMessage::Request(request())).unwrap();
            let outsider = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            let mut foreign_request = request();
            foreign_request.operation = b"different-foreign-source".to_vec();
            let foreign = primary.seal(None, &PbftMessage::Request(foreign_request)).unwrap();
            outsider.send_to(&foreign, routes[1]).unwrap();

            // Construct a VALID signed packet exactly the size of the receive
            // allocation. Appending any suffix then produces a dangerous
            // truncated prefix: an implementation that only verifies retained
            // bytes would accept a packet whose full transcript was not signed.
            let mut full = request();
            full.operation = Vec::new();
            let base = serde_json::to_vec(&PbftMessage::Request(full.clone())).unwrap().len();
            full.operation = vec![0; (4096 - base).div_ceil(2)];
            let encoded = serde_json::to_vec(&PbftMessage::Request(full.clone())).unwrap().len();
            full.client_id.push_str(&"x".repeat(4096 - encoded));
            let exact_fit = primary.seal(None, &PbftMessage::Request(full)).unwrap();
            assert_eq!(exact_fit.len(), limit);
            assert!(authority.open(&exact_fit).is_ok(), "negative-control prefix is authentic");
            let mut oversized = exact_fit.clone();
            oversized.extend_from_slice(&[7; 20]);
            sockets[0].send_to(&oversized, routes[1]).unwrap();
            sockets[0].send_to(&exact_fit, routes[1]).unwrap();
            sockets[0].send_to(&packet, routes[1]).unwrap();
            let cx = Cx::current().unwrap();
            let received = crate::time::timeout(cx.now(), Duration::from_secs(2), wire.receive_packet(limit))
                .await.unwrap().unwrap();
            assert_eq!(received, packet);
            assert!(authority.open(&received).is_ok());
            assert!(received.len() <= wire.max_datagram_bytes());
        });
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn native_transport_refuses_competing_operations_and_restores_ownership_on_drop() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let (mut sockets, routes) = sockets();
            let socket = sockets.remove(0);
            let authority = auth(0, 4096);
            let wire = UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).unwrap();
            let mut pending = Box::pin(wire.receive_packet(authority.max_packet_bytes()));
            poll_fn(|task| {
                assert!(pending.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            assert!(wire.send_packet(&ReplicaId::new("1".into()), vec![1]).await.is_err());
            drop(pending);
            wire.send_packet(&ReplicaId::new("1".into()), vec![1]).await.unwrap();
            assert!(wire.socket.lock().is_some());
        });
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn native_constructor_and_send_bounds_fail_before_datagram_delivery() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            for case in 0..5 {
                let (mut sockets, mut routes) = sockets();
                let socket = sockets.remove(0);
                let authority = auth(0, if case == 0 { 65_507 } else { 4096 });
                match case {
                    1 => routes[1] = routes[0],
                    2 => routes[1].set_port(0),
                    3 => routes[1] = "224.0.0.1:3000".parse().unwrap(),
                    4 => { socket.connect(routes[1]).unwrap(); }
                    _ => {}
                }
                assert!(UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).is_err());
            }
            let (mut sockets, routes) = sockets();
            let socket = sockets.remove(0);
            let authority = auth(0, 4096);
            let wire = UdpPbftTransport::new(UdpSocket::from_std(socket).unwrap(), &authority, routes).unwrap();
            let recipient = ReplicaId::new("1".into());
            assert!(wire.send_packet(&recipient, vec![0; authority.max_packet_bytes()]).await.is_err());
            assert!(wire.send_packet(&ReplicaId::new("01".into()), vec![1]).await.is_err());
            assert!(wire.send_packet(&ReplicaId::new("0".into()), vec![1]).await.is_err());
            assert!(wire.receive_packet(1).await.is_err());
            sockets[0].set_nonblocking(true).unwrap();
            assert_eq!(sockets[0].recv_from(&mut [0; 8]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert!(wire.socket.lock().is_some());
        });
        assert!(runtime.is_quiescent());
    }
