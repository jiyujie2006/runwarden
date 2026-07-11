mod common;

use std::sync::{Arc, Barrier};

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::story::{EventId, ObservationId, SecurityStory};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use runwarden_state::{NewStoryEvent, StateStore};

const WRITERS: usize = 8;
const EVENTS_PER_WRITER: usize = 50;

fn event_input(story: &SecurityStory, writer: usize, item: usize) -> NewStoryEvent {
    NewStoryEvent {
        obs_id: ObservationId::new(),
        event_id: EventId::new(),
        story_id: story.story_id,
        session_id: story.authority.session_id,
        operation_id: None,
        provider: None,
        payload: StoryEventPayload::InputConsumed {
            asset_id: EventCode::try_from(format!("asset-{writer}-{item}")).unwrap(),
            content_hash: Sha256Digest::from_bytes(format!("{writer}:{item}").as_bytes()),
        },
        recorded_at: mutation_time(story, 1),
    }
}

#[test]
fn eight_writers_append_four_hundred_gapless_events_and_frames() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let mut handles = Vec::with_capacity(WRITERS);
    for writer in 0..WRITERS {
        let barrier = Arc::clone(&barrier);
        let state_dir = fixture.state_dir.clone();
        let story = fixture.story.clone();
        handles.push(std::thread::spawn(move || {
            let store = StateStore::open(state_dir).unwrap();
            barrier.wait();
            for item in 0..EVENTS_PER_WRITER {
                let committed = store
                    .append_event(event_input(&story, writer, item))
                    .unwrap();
                assert_eq!(committed.event.sequence, committed.frame.sequence);
                assert_eq!(committed.story_version, committed.frame.story_version);
                committed.event.verify().unwrap();
                committed.frame.verify().unwrap();
            }
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }

    let expected = WRITERS * EVENTS_PER_WRITER;
    let events = fixture
        .store
        .events_after(fixture.story.story_id, 0, 1_000)
        .unwrap();
    let frames = fixture
        .store
        .replay_frames(fixture.story.story_id, 0, 1_000)
        .unwrap();
    assert_eq!(events.len(), expected);
    assert_eq!(frames.len(), expected);
    for (index, (event, frame)) in events.iter().zip(&frames).enumerate() {
        let expected_sequence = u64::try_from(index + 1).unwrap();
        assert_eq!(event.sequence, expected_sequence);
        assert_eq!(frame.sequence, expected_sequence);
        assert_eq!(frame.story_version, expected_sequence);
        assert_eq!(frame.event_hash, event.event_hash());
        assert_eq!(frame.story.event_count, expected_sequence);
        assert_eq!(
            frame.story.final_event_hash.as_deref(),
            Some(event.event_hash())
        );
        event.verify().unwrap();
        frame.verify().unwrap();
        if index == 0 {
            assert!(event.previous_hash.is_none());
            assert!(frame.previous_frame_hash.is_none());
        } else {
            assert_eq!(
                event.previous_hash.as_ref().map(Sha256Digest::as_str),
                Some(events[index - 1].event_hash())
            );
            assert_eq!(
                frame.previous_frame_hash.as_deref(),
                Some(frames[index - 1].frame_hash.as_str())
            );
        }
        let snapshot = serde_json::to_value(&frame.story).unwrap();
        assert!(snapshot.get("events").is_none());
    }

    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.story.event_count, u64::try_from(expected).unwrap());
    assert_eq!(evidence.events, events);
    assert_eq!(evidence.replay_frames, frames);
    assert!(
        !serde_json::to_string(&frames)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}
