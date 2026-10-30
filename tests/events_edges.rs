//! Event-stream framing: the corners `events.rs` does not reach.

// The event API is deprecated; its behaviour stays tested until it is removed.
#![allow(deprecated)]

use activeledger::{Event, EventParser};

fn parse(body: &str) -> Vec<Event> {
    let mut parser = EventParser::new();
    let mut events = parser.push(body);
    events.extend(parser.finish());
    events
}

#[test]
fn an_event_with_an_empty_name_keeps_the_empty_name() {
    let events = parse("event:\ndata: x\n\n");
    assert_eq!(1, events.len());
    assert_eq!(Some(String::new()), events[0].name);
}

#[test]
fn a_repeated_field_in_one_event_keeps_the_last_value() {
    let events = parse("event: first\nevent: second\nid: 1\nid: 2\ndata: x\n\n");
    assert_eq!(1, events.len());
    assert_eq!(Some("second".to_owned()), events[0].name);
    assert_eq!(Some("2".to_owned()), events[0].id);
}

#[test]
fn leading_blank_lines_before_the_first_event_are_harmless() {
    let events = parse("\n\n\ndata: late\n\n");
    assert_eq!(1, events.len());
    assert_eq!("late", events[0].data);
}

/// A CRLF pair can be cut between the CR and the LF by the network.
#[test]
fn a_crlf_split_between_chunks_still_ends_the_line() {
    let mut parser = EventParser::new();
    let mut events = Vec::new();
    for chunk in ["data: a\r", "\n\r", "\n"] {
        events.extend(parser.push(chunk));
    }
    events.extend(parser.finish());

    assert_eq!(1, events.len());
    assert_eq!("a", events[0].data);
}

#[test]
fn a_chunk_that_ends_mid_line_delivers_nothing_until_the_line_completes() {
    let mut parser = EventParser::new();

    assert!(parser.push("data: part").is_empty());
    assert!(parser.push("ial\n").is_empty());
    let events = parser.push("\n");
    assert_eq!(1, events.len());
    assert_eq!("partial", events[0].data);
}

/// finish() hands over the pending event once; a second call has nothing.
#[test]
fn finishing_twice_yields_the_event_only_once() {
    let mut parser = EventParser::new();
    assert!(parser.push("data: once\n").is_empty());

    assert_eq!("once", parser.finish().expect("pending event").data);
    assert_eq!(None, parser.finish());
}

#[test]
fn finishing_after_a_completed_event_yields_nothing() {
    let mut parser = EventParser::new();
    assert_eq!(1, parser.push("data: done\n\n").len());
    assert_eq!(None, parser.finish());
}

#[test]
fn a_trailing_comment_with_no_newline_is_not_an_event() {
    assert_eq!(1, parse("data: a\n\n: bye").len());
    assert!(parse(": only a comment").is_empty());
}

/// A parser keeps working across events: state from one never colours the
/// next, even when the first ended through finish().
#[test]
fn a_parser_can_be_reused_after_finish() {
    let mut parser = EventParser::new();
    parser.push("event: one\ndata: 1\n");
    assert_eq!(Some("one".to_owned()), parser.finish().unwrap().name);

    let events = parser.push("data: 2\n\n");
    assert_eq!(1, events.len());
    assert_eq!("2", events[0].data);
    assert_eq!(None, events[0].name);
}

#[test]
fn multi_line_data_keeps_blank_data_lines() {
    let events = parse("data: a\ndata:\ndata: c\n\n");
    assert_eq!("a\n\nc", events[0].data);
}

#[test]
fn non_ascii_payloads_survive_unchanged() {
    let events = parse("data: héllo \u{1F980}\n\n");
    assert_eq!("héllo \u{1F980}", events[0].data);
}

#[test]
fn events_compare_by_value_and_default_to_empty() {
    let event = Event {
        name: Some("n".into()),
        data: "d".into(),
        id: None,
    };
    assert_eq!(event, event.clone());
    assert_ne!(
        event,
        Event {
            id: Some("1".into()),
            ..event.clone()
        }
    );
    assert_eq!(
        Event {
            name: None,
            data: String::new(),
            id: None
        },
        Event::default()
    );
}
