//! Knus produces only a very simple span during parsing:
//! [`Span`] which only tracks byte offset from the start of the source code
//!
//! On the other hand, on the decode stage you can convert your span types into
//! more elaborate thing that includes file name or can refer to the defaults
//! as a separate kind of span. See [`traits::DecodeSpan`].
use crate::decode::Context;
use crate::traits::DecodeSpan;

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

impl chumsky::Span for Span {
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

impl Span {
    /// Note assuming ascii, single-width, non-newline chars here
    pub fn at_start(&self, chars: usize) -> Self {
        Span(self.0, self.0 + chars)
    }

    /// Return empty span at the end of this one.
    pub fn at_end(&self) -> Self {
        Span(self.1, self.1)
    }

    /// Note assuming ascii, single-width, non-newline chars here
    pub fn before_start(&self, chars: usize) -> Self {
        Span(self.0.saturating_sub(chars), self.0)
    }

    /// Length of the span
    pub fn length(&self) -> usize {
        self.1.saturating_sub(self.0)
    }

    /// Creates a stream of characters with spans from the given text.
    pub fn stream(text: &str) -> Stream<'_, Self>
    where
        Self: chumsky::Span,
    {
        let eoi = text.len();
        chumsky::Stream::from_iter(
            Span(eoi, eoi),
            Map(text.chars(), OffsetTracker { offset: 0 }),
        )
    }

    #[cfg(feature = "line-numbers")]
    /// Converts the span's byte offsets to zero-based line/column pairs
    pub fn to_line_column(&self, text: &str) -> ((usize, usize), (usize, usize)) {
        let prefix = &text[..self.0];
        let (start_line, start_column) = line_column_of_end(prefix);
        let span_text = &text[self.0..self.1];
        let (end_line, end_column) = line_column_of_end(span_text);
        (
            (start_line, start_column),
            (
                start_line + end_line,
                if end_line == 0 {
                    start_column + end_column
                } else {
                    end_column
                },
            ),
        )
    }
}

fn line_column_of_end(text: &str) -> (usize, usize) {
    let mut caret_return = false;
    let mut line = 0;
    let mut last_line = text;
    let mut iter = text.chars();
    while let Some(c) = iter.next() {
        match c {
            '\n' if caret_return => {}
            '\r' | '\n' | '\x0C' | '\u{0085}' | '\u{2028}' | '\u{2029}' => {
                line += 1;
                last_line = iter.as_str();
            }
            _ => {}
        }
        caret_return = c == '\r';
    }
    let column = unicode_width::UnicodeWidthStr::width(last_line);
    (line, column)
}

/// Helper struct for computing spans
#[derive(Debug)]
pub struct OffsetTracker {
    offset: usize,
}

impl OffsetTracker {
    fn next_span(&mut self, c: char) -> Span {
        let offset = self.offset;
        self.offset += c.len_utf8();
        Span(offset, self.offset)
    }
}

/// A wrapper around an iterator that produces characters with spans.
#[allow(missing_debug_implementations)]
pub struct Map<I: Iterator<Item = char>>(pub(crate) I, pub(crate) OffsetTracker);

/// Short-hand for chumsky's `Stream` type with our spans and chars.
pub type Stream<'a, S> = chumsky::Stream<'a, char, S, Map<std::str::Chars<'a>>>;

impl<I> Iterator for Map<I>
where
    I: Iterator<Item = char>,
{
    type Item = (char, Span);
    fn next(&mut self) -> Option<(char, Span)> {
        self.0.next().map(|c| (c, self.1.next_span(c)))
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_line_column() {
        let text = "Hello\nWorld!\nThis is a test.\n";
        let span = Span(6, 12); // "World!"
        let ((start_line, start_col), (end_line, end_col)) = span.to_line_column(text);
        assert_eq!((start_line, start_col), (1, 0));
        assert_eq!((end_line, end_col), (1, 6));
        let span2 = Span(0, 5); // "Hello"
        let ((s_line, s_col), (e_line, e_col)) = span2.to_line_column(text);
        assert_eq!((s_line, s_col), (0, 0));
        assert_eq!((e_line, e_col), (0, 5));
        let span3 = Span(17, 25); // " is a te"
        let ((s_line3, s_col3), (e_line3, e_col3)) = span3.to_line_column(text);
        assert_eq!((s_line3, s_col3), (2, 4));
        assert_eq!((e_line3, e_col3), (2, 12));
    }

    #[test]
    fn test_line_column_carriage_return() {
        let text = "Line1\rLine2\r\nLine3\nLine4";
        let span = Span(6, 11); // "Line2"
        let ((start_line, start_col), (end_line, end_col)) = span.to_line_column(text);
        assert_eq!((start_line, start_col), (1, 0));
        assert_eq!((end_line, end_col), (1, 5));
    }

    #[test]
    fn test_line_column_multi_byte() {
        let text = "Hellö\n, Flöße";
        let span = Span(9, 16); // "Flöße"
        println!("Span: {}", &text[9..16]);
        let ((start_line, start_col), (end_line, end_col)) = span.to_line_column(text);
        assert_eq!((start_line, start_col), (1, 2));
        assert_eq!((end_line, end_col), (1, 7));
    }
}
