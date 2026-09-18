//! Server-sent events.

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event {
    /// The `event:` field, if the server sent one.
    pub name: Option<String>,
    /// The `data:` payload. Multiple data lines join with newlines.
    pub data: String,
    /// The `id:` field, if the server sent one.
    pub id: Option<String>,
}

/// Incremental parser for the event-stream format.
///
/// Kept separate from the transport so the framing rules can be tested
/// directly. They matter more than they look: a `:` comment line is a
/// heartbeat and must not surface as an empty event, `event:` and `id:`
/// belong to one event and must not leak into the next, and exactly one
/// space after the colon is framing while every other byte is payload.
#[derive(Debug, Default)]
pub struct EventParser {
    buffer: String,
    name: Option<String>,
    id: Option<String>,
    data: Vec<String>,
}

impl EventParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a chunk of the stream, returning any events it completed.
    ///
    /// Chunk boundaries fall wherever the network puts them, so a line can
    /// arrive in pieces. Anything incomplete stays buffered.
    pub fn push(&mut self, chunk: &str) -> Vec<Event> {
        self.buffer.push_str(chunk);
        let mut events = Vec::new();

        while let Some(index) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=index).collect();
            let line = line.trim_end_matches('\n').trim_end_matches('\r');
            if let Some(event) = self.line(line) {
                events.push(event);
            }
        }

        events
    }

    /// Ends the stream, returning a final event if one was pending.
    ///
    /// A stream that stops without a trailing blank line still has a
    /// complete event in hand.
    pub fn finish(&mut self) -> Option<Event> {
        let leftover = std::mem::take(&mut self.buffer);
        let mut event = None;
        if !leftover.is_empty() {
            event = self.line(leftover.trim_end_matches('\r'));
        }
        event.or_else(|| self.take())
    }

    fn line(&mut self, line: &str) -> Option<Event> {
        if line.is_empty() {
            return self.take();
        }

        if line.starts_with(':') {
            // Comment or heartbeat. Ignored deliberately.
        } else if let Some(rest) = line.strip_prefix("event:") {
            self.name = Some(strip_one_space(rest).to_owned());
        } else if let Some(rest) = line.strip_prefix("id:") {
            self.id = Some(strip_one_space(rest).to_owned());
        } else if let Some(rest) = line.strip_prefix("data:") {
            self.data.push(strip_one_space(rest).to_owned());
        }

        None
    }

    fn take(&mut self) -> Option<Event> {
        if self.data.is_empty() {
            // Fields with no data do not make an event, but they also do not
            // carry over: the next event would otherwise be mislabelled.
            self.name = None;
            self.id = None;
            return None;
        }

        Some(Event {
            name: self.name.take(),
            id: self.id.take(),
            data: std::mem::take(&mut self.data).join("\n"),
        })
    }
}

/// Removes the single optional space after a field's colon.
///
/// One space, not a trim. The event-stream format defines exactly one
/// optional space as framing; every other byte is payload. Trimming would
/// quietly alter a data field with meaningful leading or trailing
/// whitespace, and the damage would only show up in whatever consumed it.
fn strip_one_space(value: &str) -> &str {
    value.strip_prefix(' ').unwrap_or(value)
}
