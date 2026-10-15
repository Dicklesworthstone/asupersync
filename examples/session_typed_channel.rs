//! End-to-end examples for the public obligation session facade.

use asupersync::Cx;
use asupersync::record::ObligationKind;
use asupersync::runtime::RuntimeBuilder;
use asupersync::session::obligation::{
    Branch, Selected, lease, new_transport_pair, send_permit, two_phase,
};

fn send_permit_commit() {
    let (sender, receiver) = send_permit::new_session::<u64>(1);

    let sender = sender.send(send_permit::ReserveMsg);
    let sender = sender.select_left();
    let sender = sender.send(42);
    let sender_proof = sender.close();

    let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
    let receiver_proof = match receiver.offer(Branch::Left) {
        Selected::Left(channel) => {
            let (value, channel) = channel.recv(42);
            assert_eq!(value, 42);
            channel.close()
        }
        Selected::Right(_) => panic!("send_permit_commit expected Send branch"),
    };

    assert_eq!(sender_proof.channel_id, receiver_proof.channel_id);
    assert_eq!(sender_proof.obligation_kind, ObligationKind::SendPermit);
}

fn lease_release() {
    let (holder, resource) = lease::new_session(2);

    let holder = holder.send(lease::AcquireMsg);
    let holder = holder.select_right();
    let holder = holder.send(lease::ReleaseMsg);
    let holder_proof = holder.close();

    let (_, resource) = resource.recv(lease::AcquireMsg);
    let resource_proof = match resource.offer(Branch::Right) {
        Selected::Right(channel) => {
            let (_, channel) = channel.recv(lease::ReleaseMsg);
            channel.close()
        }
        Selected::Left(_) => panic!("lease_release expected Release branch"),
    };

    assert_eq!(holder_proof.channel_id, resource_proof.channel_id);
    assert_eq!(holder_proof.obligation_kind, ObligationKind::Lease);
}

fn two_phase_commit_over_mpsc() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;

    runtime.block_on(async {
        let cx = Cx::for_testing();
        let kind = ObligationKind::IoOp;
        let (initiator, executor) = new_transport_pair::<
            two_phase::InitiatorSession,
            two_phase::ResponderSession,
        >(3, kind, 2);
        let reserve = two_phase::ReserveMsg { kind };

        let initiator = initiator.send_async(&cx, reserve.clone()).await?;
        let (received, executor) = executor.recv_async(&cx).await?;
        assert_eq!(received.kind, kind);

        let initiator = initiator.select_left_async(&cx).await?;
        let executor = match executor.offer_async(&cx).await? {
            Selected::Left(channel) => channel,
            Selected::Right(_) => panic!("two_phase_commit_over_mpsc expected Commit branch"),
        };

        let initiator = initiator.send_async(&cx, two_phase::CommitMsg).await?;
        let (_, executor) = executor.recv_async(&cx).await?;

        let initiator_proof = initiator.close();
        let executor_proof = executor.close();

        assert_eq!(initiator_proof.channel_id, executor_proof.channel_id);
        assert_eq!(initiator_proof.obligation_kind, kind);

        Ok::<(), asupersync::session::obligation::SessionError>(())
    })?;

    Ok(())
}

fn two_phase_commit_pure_typestate() {
    let kind = ObligationKind::IoOp;
    let (initiator, executor) = two_phase::new_session(3, kind);
    let reserve = two_phase::ReserveMsg { kind };

    let initiator = initiator.send(reserve.clone());
    let initiator = initiator.select_left();
    let initiator = initiator.send(two_phase::CommitMsg);
    let initiator_proof = initiator.close();

    let (received, executor) = executor.recv(reserve);
    assert_eq!(received.kind, kind);
    let executor_proof = match executor.offer(Branch::Left) {
        Selected::Left(channel) => {
            let (_, channel) = channel.recv(two_phase::CommitMsg);
            channel.close()
        }
        Selected::Right(_) => panic!("two_phase_commit expected Commit branch"),
    };

    assert_eq!(initiator_proof.channel_id, executor_proof.channel_id);
    assert_eq!(initiator_proof.obligation_kind, kind);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    send_permit_commit();
    lease_release();
    two_phase_commit_pure_typestate();
    two_phase_commit_over_mpsc()?;

    Ok(())
}
