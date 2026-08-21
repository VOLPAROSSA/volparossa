#![no_main]

use libfuzzer_sys::fuzz_target;
use volparossa_protocol::{
    ClientSessionCapability, ExitCapacityHold, ExitCapacityHoldRequest, ExitConfirmationReceipt,
    ExitReservation, ExitReservationConfirmation, ExitReservationFinalizeRequest,
    NodeAdvertisement, OpenTcp, RelayAuthorization, RelayProbePermit, RelayProbePermitRequest,
    RelayProbeResult, RelayReservation, RelayReservationRequest, ReplayCache, TimePolicy,
    UdpFlowAuthorization, verify_control_message,
};

fn verify<T: volparossa_protocol::ControlPayload>(data: &[u8]) {
    let mut replay = ReplayCache::new(64).expect("fixed replay-cache capacity is valid");
    let _ =
        verify_control_message::<T>(data, 1_750_000_000_000, TimePolicy::default(), &mut replay);
}

fuzz_target!(|data: &[u8]| {
    verify::<NodeAdvertisement>(data);
    verify::<ExitReservation>(data);
    verify::<RelayAuthorization>(data);
    verify::<RelayReservation>(data);
    verify::<OpenTcp>(data);
    verify::<UdpFlowAuthorization>(data);
    verify::<ExitCapacityHoldRequest>(data);
    verify::<RelayReservationRequest>(data);
    verify::<ExitReservationConfirmation>(data);
    verify::<ClientSessionCapability>(data);
    verify::<ExitCapacityHold>(data);
    verify::<RelayProbePermitRequest>(data);
    verify::<RelayProbePermit>(data);
    verify::<RelayProbeResult>(data);
    verify::<ExitReservationFinalizeRequest>(data);
    verify::<ExitConfirmationReceipt>(data);
});
