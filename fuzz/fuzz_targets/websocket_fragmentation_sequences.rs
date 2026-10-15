#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, Role, WsError};
use libfuzzer_sys::fuzz_target;

/// WebSocket fragmentation sequence fuzzer targeting RFC 6455 §5.4 compliance.
///
/// Tests complex multi-frame fragmentation scenarios including:
/// - Continuation frame sequences with opcode transitions
/// - Control frame interleaving during fragmentation
/// - Fragment boundary edge cases and payload accumulation
/// - State machine validation for invalid sequences
#[derive(Arbitrary, Debug)]
struct FragmentationSequenceInput {
    role: TestRole,
    sequences: Vec<FragmentSequence>,
}

#[derive(Arbitrary, Debug)]
struct FragmentSequence {
    /// Initial frame type for the sequence
    initial_opcode: DataOpcode,
    /// Fragment the initial message across this many frames
    fragment_count: u8, // 1-8 to prevent timeouts
    /// Payload chunks for each fragment
    payload_chunks: Vec<Vec<u8>>,
    /// Control frames to interleave (RFC 6455 §5.5 allows this)
    interleaved_control: Vec<InterleavedControl>,
    /// Test invalid continuation sequences
    invalid_sequence: InvalidSequenceType,
}

#[derive(Arbitrary, Debug)]
struct InterleavedControl {
    /// Insert after which fragment index
    after_fragment: u8,
    /// Control frame type
    control_opcode: ControlOpcode,
    /// Control frame payload
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TestRole {
    Client,
    Server,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DataOpcode {
    Text,
    Binary,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ControlOpcode {
    Close,
    Ping,
    Pong,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum InvalidSequenceType {
    None,
    /// Continuation without preceding data frame
    OrphanedContinuation,
    /// Switch between Text/Binary mid-sequence
    OpcodeSwitch,
    /// Multiple FIN=1 frames in sequence
    MultipleFin,
    /// Control frame with FIN=0 (invalid per §5.5)
    FragmentedControl,
}

const MAX_SEQUENCES: usize = 10;
const MAX_FRAGMENTS: usize = 8;
const MAX_CHUNK_SIZE: usize = 1024;
const MAX_CONTROL_PAYLOAD: usize = 125; // RFC 6455 §5.5
const MAX_INTERLEAVED: usize = 3;

fuzz_target!(|input: FragmentationSequenceInput| {
    // Bound execution to prevent timeouts
    if input.sequences.len() > MAX_SEQUENCES {
        return;
    }

    let role = match input.role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    for sequence in input.sequences {
        test_fragmentation_sequence(role, sequence);
    }
});

fn test_fragmentation_sequence(role: Role, mut sequence: FragmentSequence) {
    // Bound fragment count and payload sizes
    let fragment_count = (sequence.fragment_count as usize).max(1).min(MAX_FRAGMENTS);

    sequence.payload_chunks.truncate(fragment_count);
    sequence
        .payload_chunks
        .resize_with(fragment_count, Vec::new);

    for chunk in &mut sequence.payload_chunks {
        chunk.truncate(MAX_CHUNK_SIZE);
    }

    sequence.interleaved_control.truncate(MAX_INTERLEAVED);
    for ctrl in &mut sequence.interleaved_control {
        ctrl.payload.truncate(MAX_CONTROL_PAYLOAD);
    }

    let mut codec = FrameCodec::new(role);
    let mut buf = BytesMut::new();

    // Track fragmentation state for validation
    let mut fragmentation_state = FragmentationState::new();

    // Generate frame sequence
    let frames = generate_frame_sequence(&sequence, role);

    // Encode all frames into buffer
    for frame_bytes in frames {
        buf.extend_from_slice(&frame_bytes);
    }

    // Decode and validate sequence
    let mut decoded_frames = Vec::new();
    while !buf.is_empty() {
        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                let validation_result = fragmentation_state.process_frame(&frame);

                // Assert sequence validity based on invalid_sequence type
                match sequence.invalid_sequence {
                    InvalidSequenceType::OrphanedContinuation => {
                        if matches!(frame.opcode, Opcode::Continuation)
                            && !fragmentation_state.in_fragment
                        {
                            assert!(
                                validation_result.is_err(),
                                "Orphaned continuation frame should be rejected"
                            );
                        }
                    }
                    InvalidSequenceType::OpcodeSwitch => {
                        // This would be caught by codec validation
                    }
                    InvalidSequenceType::FragmentedControl => {
                        if frame.opcode.is_control() && !frame.fin {
                            // Should be rejected during decode
                            panic!("Fragmented control frame should be rejected during decode");
                        }
                    }
                    InvalidSequenceType::None => {
                        // Valid sequence - assert no errors
                        if validation_result.is_err() && buf.is_empty() {
                            panic!(
                                "Valid fragmentation sequence incorrectly rejected: {:?}",
                                validation_result
                            );
                        }
                    }
                    _ => {}
                }

                decoded_frames.push(frame);
            }
            Ok(None) => {
                // Need more data
                break;
            }
            Err(_) => {
                // Expected for invalid sequences
                break;
            }
        }
    }

    // Additional invariant checks for valid sequences
    if matches!(sequence.invalid_sequence, InvalidSequenceType::None) {
        validate_fragment_invariants(&decoded_frames);
    }
}

fn generate_frame_sequence(sequence: &FragmentSequence, role: Role) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let initial_opcode = match sequence.initial_opcode {
        DataOpcode::Text => Opcode::Text,
        DataOpcode::Binary => Opcode::Binary,
    };

    let fragment_count = sequence.payload_chunks.len();
    let mut control_index = 0;

    for (i, chunk) in sequence.payload_chunks.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == fragment_count - 1;

        // Determine frame opcode and FIN bit
        let (opcode, fin) = match sequence.invalid_sequence {
            InvalidSequenceType::OpcodeSwitch if i == 1 => {
                // Switch opcode on second frame (invalid)
                let switched_opcode = match sequence.initial_opcode {
                    DataOpcode::Text => Opcode::Binary,
                    DataOpcode::Binary => Opcode::Text,
                };
                (switched_opcode, false)
            }
            InvalidSequenceType::MultipleFin if i == fragment_count - 2 => {
                // Set FIN=1 on second-to-last frame (invalid)
                (
                    if is_first {
                        initial_opcode
                    } else {
                        Opcode::Continuation
                    },
                    true,
                )
            }
            _ => {
                let opcode = if is_first {
                    initial_opcode
                } else {
                    Opcode::Continuation
                };
                let fin = is_last;
                (opcode, fin)
            }
        };

        // Generate data frame
        frames.push(construct_data_frame(chunk, opcode, fin, role));

        // Insert interleaved control frames
        while control_index < sequence.interleaved_control.len()
            && sequence.interleaved_control[control_index].after_fragment as usize == i
        {
            let control = &sequence.interleaved_control[control_index];
            let control_opcode = match control.control_opcode {
                ControlOpcode::Close => Opcode::Close,
                ControlOpcode::Ping => Opcode::Ping,
                ControlOpcode::Pong => Opcode::Pong,
            };

            let control_fin = !matches!(
                sequence.invalid_sequence,
                InvalidSequenceType::FragmentedControl
            );
            frames.push(construct_control_frame(
                &control.payload,
                control_opcode,
                control_fin,
                role,
            ));
            control_index += 1;
        }
    }

    // Handle orphaned continuation
    if matches!(
        sequence.invalid_sequence,
        InvalidSequenceType::OrphanedContinuation
    ) {
        let orphaned = construct_data_frame(&[0x42], Opcode::Continuation, true, role);
        frames.insert(0, orphaned); // Insert at beginning
    }

    frames
}

fn construct_data_frame(payload: &[u8], opcode: Opcode, fin: bool, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN + opcode
    let first_byte = (if fin { 0x80 } else { 0x00 }) | (opcode as u8);
    frame.push(first_byte);

    // Masking based on role (server receives masked frames from client)
    let masked = match role {
        Role::Server => true,  // Server expects masked client frames
        Role::Client => false, // Client expects unmasked server frames
    };

    // Encode length and masking bit
    let mask_bit = if masked { 0x80 } else { 0x00 };

    if payload.len() <= 125 {
        frame.push(mask_bit | (payload.len() as u8));
    } else if payload.len() <= 65535 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    // Mask key and payload
    let mask_key = [0x12, 0x34, 0x56, 0x78];
    if masked {
        frame.extend_from_slice(&mask_key);
        let mut masked_payload = payload.to_vec();
        asupersync::net::websocket::apply_mask(&mut masked_payload, mask_key);
        frame.extend_from_slice(&masked_payload);
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

fn construct_control_frame(payload: &[u8], opcode: Opcode, fin: bool, role: Role) -> Vec<u8> {
    let payload = &payload[..payload.len().min(125)]; // Control frames limited to 125 bytes
    construct_data_frame(payload, opcode, fin, role)
}

// Fragmentation state machine for validation
#[derive(Debug)]
struct FragmentationState {
    in_fragment: bool,
    fragment_opcode: Option<Opcode>,
}

impl FragmentationState {
    fn new() -> Self {
        Self {
            in_fragment: false,
            fragment_opcode: None,
        }
    }

    fn process_frame(&mut self, frame: &Frame) -> Result<(), &'static str> {
        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                if self.in_fragment {
                    return Err("Data frame during fragmentation");
                }

                if frame.fin {
                    // Complete message
                    self.in_fragment = false;
                    self.fragment_opcode = None;
                } else {
                    // Start fragmentation
                    self.in_fragment = true;
                    self.fragment_opcode = Some(frame.opcode);
                }
            }

            Opcode::Continuation => {
                if !self.in_fragment {
                    return Err("Continuation without data frame");
                }

                if frame.fin {
                    // End fragmentation
                    self.in_fragment = false;
                    self.fragment_opcode = None;
                }
            }

            Opcode::Close | Opcode::Ping | Opcode::Pong => {
                // Control frames don't affect fragmentation state
                // but must have FIN=1
                if !frame.fin {
                    return Err("Control frame without FIN=1");
                }
            }
        }

        Ok(())
    }
}

fn validate_fragment_invariants(frames: &[Frame]) {
    let mut in_fragment = false;
    let mut fragment_opcode = None;

    for frame in frames {
        match frame.opcode {
            Opcode::Text | Opcode::Binary => {
                assert!(!in_fragment, "Data frame during fragmentation");

                if !frame.fin {
                    in_fragment = true;
                    fragment_opcode = Some(frame.opcode);
                }
            }

            Opcode::Continuation => {
                assert!(
                    in_fragment,
                    "Continuation frame without preceding data frame"
                );

                if frame.fin {
                    in_fragment = false;
                    fragment_opcode = None;
                }
            }

            Opcode::Close | Opcode::Ping | Opcode::Pong => {
                assert!(frame.fin, "Control frame must have FIN=1");
                // Control frames can be interleaved during fragmentation (RFC 6455 §5.5)
            }
        }
    }

    // Fragmentation should be complete by end of sequence
    assert!(!in_fragment, "Incomplete fragmentation at end of sequence");
}
