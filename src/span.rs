//! Knus produces only a very simple span during parsing:
//! [`Span`] which only tracks byte offset from the start of the source code
//!
//! Line and column numbers are computed afterwards, from the source text, by
//! building a [`LineIndex`] once and then converting spans into [`LineSpan`]s
//! as needed.
//!
//! On the other hand, on the decode stage you can convert your span types into
//! more elaborate thing that includes file name or can refer to the defaults
//! as a separate kind of span. See [`DecodeSpan`].
use crate::decode::Context;
#[cfg(feature = "line-numbers")]
use crate::grammar::is_newline_char;
use crate::traits::DecodeSpan;

use chumsky::span::SimpleSpan;
/// Reexport of [miette::SourceSpan] trait that we use for parsing
pub use miette::SourceSpan as ErrorSpan;

/// Wraps the structure to keep source code span, but also dereference to T
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "minicbor", derive(minicbor::Encode, minicbor::Decode))]
pub struct Spanned<T> {
    #[cfg_attr(feature = "minicbor", n(0))]
    pub(crate) span: Span,
    #[cfg_attr(feature = "minicbor", n(1))]
    pub(crate) value: T,
}

/// A span based on byte offsets.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[cfg_attr(feature = "minicbor", derive(minicbor::Encode, minicbor::Decode))]
pub struct Span(
    #[cfg_attr(feature = "minicbor", n(0))] pub usize,
    #[cfg_attr(feature = "minicbor", n(1))] pub usize,
);

impl From<Span> for ErrorSpan {
    fn from(val: Span) -> Self {
        (val.0, val.1.saturating_sub(val.0)).into()
    }
}

/// Line and column position of the datum in the source code
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[cfg_attr(feature = "minicbor", derive(minicbor::Encode, minicbor::Decode))]
pub struct LinePos {
    /// Zero-based byte offset
    #[cfg_attr(feature = "minicbor", n(0))]
    pub offset: usize,
    /// Zero-based line number
    #[cfg_attr(feature = "minicbor", n(1))]
    pub line: usize,
    /// Zero-based column number
    #[cfg_attr(feature = "minicbor", n(2))]
    pub column: usize,
}

/// A span with line and column numbers, as produced by [`LineIndex`]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[cfg_attr(feature = "minicbor", derive(minicbor::Encode, minicbor::Decode))]
pub struct LineSpan(
    #[cfg_attr(feature = "minicbor", n(0))] pub LinePos,
    #[cfg_attr(feature = "minicbor", n(1))] pub LinePos,
);

impl From<LineSpan> for ErrorSpan {
    fn from(val: LineSpan) -> Self {
        (val.0.offset, val.1.offset.saturating_sub(val.0.offset)).into()
    }
}

impl chumsky::span::Span for Span {
    type Context = ();
    type Offset = usize;
    fn new(_context: (), range: std::ops::Range<usize>) -> Self {
        Span(range.start, range.end)
    }
    fn context(&self) {}
    fn start(&self) -> usize {
        self.0
    }
    fn end(&self) -> usize {
        self.1
    }
}

impl From<SimpleSpan> for Span {
    fn from(value: SimpleSpan) -> Self {
        Span(value.start, value.end)
    }
}

impl Span {
    /// Return a span of the given length at the start of this one.
    pub fn at_start(&self, chars: usize) -> Self {
        Span(self.0, self.0 + chars)
    }

    /// Return empty span at the end of this one.
    pub fn at_end(&self) -> Self {
        Span(self.1, self.1)
    }

    /// Return a span of the given length before the start of this one.
    pub fn before_start(&self, chars: usize) -> Self {
        Span(self.0.saturating_sub(chars), self.0)
    }

    /// Length of the span
    pub fn length(&self) -> usize {
        self.1.saturating_sub(self.0)
    }
}

/// An index of the line starts of a source text
///
/// Building the index takes a single pass over the text, after which any
/// number of [`Span`]s can be converted into line and column numbers in
/// logarithmic time (plus the length of the line the position is on).
///
/// ```
/// use knus::span::{LineIndex, Span};
///
/// let index = LineIndex::new("node1\nnode2\n");
/// let line_span = index.line_span(Span(6, 11));
/// assert_eq!((line_span.0.line, line_span.0.column), (1, 0));
/// assert_eq!((line_span.1.line, line_span.1.column), (1, 5));
/// ```
#[cfg(feature = "line-numbers")]
#[derive(Clone, Debug)]
pub struct LineIndex<'a> {
    text: &'a str,
    /// Byte offset of the start of each line; the first entry is always zero.
    line_starts: Vec<usize>,
}

#[cfg(feature = "line-numbers")]
impl<'a> LineIndex<'a> {
    /// Indexes the line starts of the given source text
    pub fn new(text: &'a str) -> Self {
        let mut line_starts = vec![0];
        let mut caret_return = false;
        for (offset, c) in text.char_indices() {
            match c {
                // `CRLF` counts as a single newline. The line then starts at
                // the `\n` itself, which is zero-width, so columns still come
                // out right.
                '\n' if caret_return => {}
                // Shared with the parser so that the two cannot disagree about
                // what a line break is.
                c if is_newline_char(c) => line_starts.push(offset + c.len_utf8()),
                _ => {}
            }
            caret_return = c == '\r';
        }
        LineIndex { text, line_starts }
    }

    /// Converts a byte offset into a zero-based line and column number
    ///
    /// Columns are counted in display width: a tab is eight columns wide and
    /// control characters are zero columns wide.
    ///
    /// An offset past the end of the text is clamped to the end.
    ///
    /// # Panics
    ///
    /// Panics if the offset is not on a `char` boundary of the indexed text.
    pub fn line_pos(&self, offset: usize) -> LinePos {
        let offset = offset.min(self.text.len());
        // `line_starts` always starts with a zero, so there is at least one
        // entry that is not greater than the offset.
        let line = self.line_starts.partition_point(|&start| start <= offset) - 1;
        let column = self.text[self.line_starts[line]..offset]
            .chars()
            .map(|c| match c {
                '\t' => 8,
                // Control characters are treated as zero-width.
                c => unicode_width::UnicodeWidthChar::width(c).unwrap_or(0),
            })
            .sum();
        LinePos {
            offset,
            line,
            column,
        }
    }

    /// Converts the byte offsets of a span into line and column numbers
    pub fn line_span(&self, span: Span) -> LineSpan {
        LineSpan(self.line_pos(span.0), self.line_pos(span.1))
    }

    /// The number of lines in the indexed text
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }
}

impl DecodeSpan for Span {
    fn decode_span(span: &Span, _: &mut Context) -> Self {
        *span
    }
}

impl<T> Spanned<T> {
    /// Converts value but keeps the same span attached
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> Spanned<R> {
        Spanned {
            span: self.span,
            value: f(self.value),
        }
    }
    pub(crate) fn clone_as(&self, ctx: &mut Context) -> Spanned<T>
    where
        T: Clone,
    {
        Spanned {
            span: DecodeSpan::decode_span(&self.span, ctx),
            value: self.value.clone(),
        }
    }
}

impl<U: ?Sized, T: AsRef<U>> AsRef<U> for Spanned<T> {
    fn as_ref(&self) -> &U {
        self.value.as_ref()
    }
}

impl<U: ?Sized, T: AsMut<U>> AsMut<U> for Spanned<T> {
    fn as_mut(&mut self) -> &mut U {
        self.value.as_mut()
    }
}

impl<T> std::ops::Deref for Spanned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> std::ops::DerefMut for Spanned<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T> std::borrow::Borrow<T> for Spanned<T> {
    fn borrow(&self) -> &T {
        self.value.borrow()
    }
}

impl<T: ?Sized> std::borrow::Borrow<T> for Spanned<Box<T>> {
    fn borrow(&self) -> &T {
        self.value.borrow()
    }
}

impl<T> Spanned<T> {
    /// Returns the span of the value
    pub fn span(&self) -> &Span {
        &self.span
    }
}

impl<T: PartialEq<T>> PartialEq for Spanned<T> {
    fn eq(&self, other: &Spanned<T>) -> bool {
        self.value == other.value
    }
}

impl<T: PartialOrd<T>> PartialOrd for Spanned<T> {
    fn partial_cmp(&self, other: &Spanned<T>) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T: Ord> Ord for Spanned<T> {
    fn cmp(&self, other: &Spanned<T>) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T: Eq> Eq for Spanned<T> {}

impl<T: std::hash::Hash> std::hash::Hash for Spanned<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.value.hash(state)
    }
}

#[cfg(all(test, feature = "line-numbers"))]
mod tests {
    use super::*;

    fn line_column(index: &LineIndex, span: Span) -> ((usize, usize), (usize, usize)) {
        let LineSpan(start, end) = index.line_span(span);
        ((start.line, start.column), (end.line, end.column))
    }

    #[test]
    fn test_line_column() {
        let text = "Hello\nWorld!\nThis is a test.\n";
        let index = LineIndex::new(text);
        assert_eq!(index.line_count(), 4);
        // The same index answers every span; "World!", "Hello" and " is a te".
        assert_eq!(line_column(&index, Span(6, 12)), ((1, 0), (1, 6)));
        assert_eq!(line_column(&index, Span(0, 5)), ((0, 0), (0, 5)));
        assert_eq!(line_column(&index, Span(17, 25)), ((2, 4), (2, 12)));
        // A span across lines gets each end measured from its own line start.
        assert_eq!(line_column(&index, Span(3, 8)), ((0, 3), (1, 2)));
    }

    #[test]
    fn test_line_column_carriage_return() {
        let text = "Line1\rLine2\r\nLine3\nLine4";
        let index = LineIndex::new(text);
        // `CRLF` is a single line break, so there are four lines, not five.
        assert_eq!(index.line_count(), 4);
        let span = Span(6, 11); // "Line2"
        assert_eq!(line_column(&index, span), ((1, 0), (1, 5)));
        let span = Span(13, 18); // "Line3"
        assert_eq!(line_column(&index, span), ((2, 0), (2, 5)));
    }

    #[test]
    fn test_line_column_unicode_newlines() {
        // The KDL spec's Newline table is wider than `\r` and `\n`: all of
        // these terminate a node, so they have to advance the line here too.
        for sep in ['\x0B', '\x0C', '\u{0085}', '\u{2028}', '\u{2029}'] {
            let text = format!("a{sep}b");
            let index = LineIndex::new(&text);
            let start = 1 + sep.len_utf8();
            let span = Span(start, start + 1); // "b"
            assert_eq!(
                line_column(&index, span),
                ((1, 0), (1, 1)),
                "wrong position after {sep:?}"
            );
        }
    }

    #[test]
    fn test_line_column_multi_byte() {
        let text = "Hellö\n, Flöße";
        let index = LineIndex::new(text);
        let span = Span(9, 16); // "Flöße"
        assert_eq!(line_column(&index, span), ((1, 2), (1, 7)));
    }

    #[test]
    fn test_line_column_tab() {
        // A tab is eight columns wide.
        let index = LineIndex::new("a\tb");
        assert_eq!(line_column(&index, Span(2, 3)), ((0, 9), (0, 10)));
    }

    #[test]
    fn test_line_column_edges() {
        let index = LineIndex::new("");
        assert_eq!(index.line_count(), 1);
        assert_eq!(line_column(&index, Span(0, 0)), ((0, 0), (0, 0)));
        // Offsets past the end are clamped to the end of the text.
        assert_eq!(index.line_pos(10).offset, 0);

        let text = "ab\ncd\n";
        let index = LineIndex::new(text);
        // The empty last line exists, and the end of the text is on it.
        assert_eq!(index.line_count(), 3);
        assert_eq!(
            line_column(&index, Span(text.len(), text.len())),
            ((2, 0), (2, 0))
        );
        // A newline itself belongs to the line it terminates.
        assert_eq!(line_column(&index, Span(2, 3)), ((0, 2), (1, 0)));
    }
}
