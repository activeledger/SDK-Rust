//! The event-stream framing rules.
//!
//! Driven through the parser directly rather than over a socket, so each
//! rule is checked on its own -- including the ones that only show up when
//! the network splits a line across two chunks.

use activeledger::EventParser;

fn parse(body: &str) -> Vec<activeledger::Event> {
    let mut parser = EventParser::new();
    let mut events = parser.push(body);
    events.extend(parser.finish());
    events
}

#[test]
fn parses_a_simple_event() {
    let events = parse("data: hello\n\n");
    assert_eq!(1, events.len());
    assert_eq!("hello", events[0].data);
    assert_eq!(None, events[0].name);
    assert_eq!(None, events[0].id);
}

#[test]
fn parses_named_events_and_ids() {
    let events =
        parse("event: tx\nid: 1\ndata: {\"a\":1}\n\nevent: tx\nid: 2\ndata: {\"a\":2}\n\n");

    assert_eq!(2, events.len());
    assert_eq!(Some("tx".to_owned()), events[0].name);
    assert_eq!(Some("1".to_owned()), events[0].id);
    assert_eq!("{\"a\":1}", events[0].data);
    assert_eq!(Some("2".to_owned()), events[1].id);
}

#[test]
fn multiple_data_lines_join_with_newlines() {
    let events = parse("data: one\ndata: two\n\n");
    assert_eq!(1, events.len());
    assert_eq!("one\ntwo", events[0].data);
}

/// Heartbeats keep the connection alive and are not events. Delivering them
/// would hand the caller a stream of empty payloads to filter.
#[test]
fn comment_heartbeats_are_not_delivered() {
    let events = parse(": keep-alive\n\n: another\n\ndata: real\n\n");
    assert_eq!(1, events.len());
    assert_eq!("real", events[0].data);
}

/// event:/id: are per-event fields. Leaking them into the next event
/// mislabels it, and the mislabel looks like a server bug.
#[test]
fn fields_do_not_leak_into_the_following_event() {
    let events = parse("event: named\nid: 7\ndata: first\n\ndata: second\n\n");

    assert_eq!(2, events.len());
    assert_eq!(Some("named".to_owned()), events[0].name);
    assert_eq!(None, events[1].name);
    assert_eq!(None, events[1].id);
}

/// A block carrying fields but no data is not an event -- and must not leave
/// those fields attached to whatever comes next.
#[test]
fn field_only_blocks_produce_no_event_and_do_not_carry_over() {
    let events = parse("event: empty\n\nid: 9\n\ndata: real\n\n");

    assert_eq!(1, events.len());
    assert_eq!("real", events[0].data);
    assert_eq!(None, events[0].name);
    assert_eq!(None, events[0].id);
}

#[test]
fn carriage_returns_are_stripped() {
    let events = parse("event: tx\r\ndata: payload\r\n\r\n");

    assert_eq!(1, events.len());
    assert_eq!(Some("tx".to_owned()), events[0].name);
    assert_eq!("payload", events[0].data);
}

/// Exactly one space after the colon is framing; every other byte is
/// payload. Trimming would quietly corrupt a data field.
#[test]
fn only_one_space_after_the_colon_is_framing() {
    let events = parse("data:  leading\n\ndata:tight\n\ndata: trailing \n\n");

    assert_eq!(3, events.len());
    assert_eq!(" leading", events[0].data);
    assert_eq!("tight", events[1].data);
    assert_eq!("trailing ", events[2].data);
}

/// A stream that ends without its trailing blank line still has a complete
/// event in hand.
#[test]
fn an_event_without_its_trailing_blank_line_is_still_delivered() {
    let events = parse("data: truncated\n");
    assert_eq!(1, events.len());
    assert_eq!("truncated", events[0].data);
}

#[test]
fn a_final_line_with_no_newline_at_all_is_still_delivered() {
    let events = parse("data: no newline");
    assert_eq!(1, events.len());
    assert_eq!("no newline", events[0].data);
}

#[test]
fn an_empty_stream_produces_nothing() {
    assert!(parse("").is_empty());
    assert!(parse("\n\n").is_empty());
    assert!(parse(": just a heartbeat\n\n").is_empty());
}

/// Chunk boundaries fall wherever the network puts them, including the
/// middle of a field name. Anything that assumes a chunk is a whole line
/// works locally and fails against a real server.
#[test]
fn an_event_split_across_chunks_is_reassembled() {
    let mut parser = EventParser::new();
    let mut events = Vec::new();

    for chunk in ["eve", "nt: t", "x\nda", "ta: hel", "lo\n", "\n"] {
        events.extend(parser.push(chunk));
    }

    assert_eq!(1, events.len());
    assert_eq!(Some("tx".to_owned()), events[0].name);
    assert_eq!("hello", events[0].data);
}

#[test]
fn several_events_in_one_chunk_all_arrive() {
    let events = parse("data: a\n\ndata: b\n\ndata: c\n\n");
    assert_eq!(
        vec!["a", "b", "c"],
        events.iter().map(|e| e.data.as_str()).collect::<Vec<_>>()
    );
}

/// Data payloads are JSON, and a colon inside one must not be mistaken for
/// field framing.
#[test]
fn colons_inside_a_payload_are_left_alone() {
    let events = parse("data: {\"time\":\"12:30:00\",\"url\":\"http://x\"}\n\n");
    assert_eq!(1, events.len());
    assert_eq!(
        "{\"time\":\"12:30:00\",\"url\":\"http://x\"}",
        events[0].data
    );
}

/// An unknown field is ignored rather than treated as data.
#[test]
fn unknown_fields_are_ignored() {
    let events = parse("retry: 5000\nfoo: bar\ndata: real\n\n");
    assert_eq!(1, events.len());
    assert_eq!("real", events[0].data);
}

/// An empty data field is a real event with an empty payload, not nothing.
#[test]
fn an_empty_data_field_still_makes_an_event() {
    let events = parse("data:\n\n");
    assert_eq!(1, events.len());
    assert_eq!("", events[0].data);
}
