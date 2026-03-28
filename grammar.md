This is the full official grammar for KDL and should be considered
authoritative.

~~~abnf
document := bom? version? nodes

// Nodes
nodes := (line-space* node)* line-space*

base-node := slashdash? type? node-space* string
    (node-space* (node-space | slashdash) node-prop-or-arg)*
    // slashdashed node-children must always be after props and args.
    (node-space* slashdash node-children)*
    (node-space* node-children)?
    (node-space* slashdash node-children)*
    node-space*
node := base-node node-terminator
final-node := base-node node-terminator?

// Entries
node-prop-or-arg := prop | value
node-children := '{' nodes final-node? '}'
node-terminator := single-line-comment | newline | ';' | eof

prop := string node-space* '=' node-space* value
value := type? node-space* (string | number | keyword)
type := '(' node-space* string node-space* ')'

// Strings
string := identifier-string | quoted-string | raw-string ¶

identifier-string :=
    (unambiguous-ident | signed-ident | dotted-ident)
    - disallowed-keyword-identifiers
unambiguous-ident :=
    (identifier-char - digit - sign - '.') identifier-char*
signed-ident :=
    sign ((identifier-char - digit - '.') identifier-char*)?
dotted-ident :=
    sign? '.' ((identifier-char - digit) identifier-char*)?
identifier-char :=
    unicode - unicode-space - newline - [\\/(){};\[\]"#=]
    - disallowed-literal-code-points
disallowed-keyword-identifiers :=
    'true' | 'false' | 'null' | 'inf' | '-inf' | 'nan'

quoted-string :=
    '"' single-line-string-body '"' |
    '"""' newline
    (multi-line-string-body newline)?
    (unicode-space | ws-escape)* '"""'
single-line-string-body := (string-character - newline)*
multi-line-string-body := ('"' ^'"' | '""' ^'"' | string-character)*?
string-character :=
    '\\' (["\\bfnrts] |
    'u{' hex-unicode '}') |
    ws-escape |
    [^\\"] - disallowed-literal-code-points
ws-escape := '\\' (unicode-space | newline)+
hex-digit := [0-9a-fA-F]
hex-unicode := hex-digit{1, 6} - surrogate - above-max-scalar
surrogate := [0]{0, 2} [dD] [8-9a-fA-F] hex-digit{2}
//  U+D800-DFFF:         D   8          00
//                       D   F          FF
above-max-scalar = [2-9a-fA-F] hex-digit{5} |
    [1] [1-9a-fA-F] hex-digit{4}


raw-string := '#' raw-string-quotes '#' | '#' raw-string '#'
raw-string-quotes :=
    '"' single-line-raw-string-body '"' |
    '"""' newline
    (multi-line-raw-string-body newline)?
    unicode-space* '"""'
single-line-raw-string-body :=
    '' |
    (single-line-raw-string-char - '"')
        single-line-raw-string-char*? |
    '"' (single-line-raw-string-char - '"')
        single-line-raw-string-char*?
single-line-raw-string-char :=
    unicode - newline - disallowed-literal-code-points
multi-line-raw-string-body :=
    (unicode - disallowed-literal-code-points)*?

// Numbers
number := keyword-number | hex | octal | binary | decimal

decimal := sign? integer ('.' integer)? exponent?
exponent := ('e' | 'E') sign? integer
integer := digit (digit | '_')*
digit := [0-9]
sign := '+' | '-'

hex := sign? '0x' hex-digit (hex-digit | '_')*
octal := sign? '0o' [0-7] [0-7_]*
binary := sign? '0b' ('0' | '1') ('0' | '1' | '_')*

// Keywords and booleans.
keyword := boolean | '#null'
keyword-number := '#inf' | '#-inf' | '#nan'
boolean := '#true' | '#false'

// Specific code points
bom := '\u{FEFF}'
disallowed-literal-code-points :=
    See Table (Disallowed Literal Code Points)
unicode := Any Unicode Scalar Value
unicode-space := See Table
    (All White_Space unicode characters which are not `newline`)

// Comments
single-line-comment := '//' ^newline* (newline | eof)
multi-line-comment := '/*' commented-block
commented-block :=
    '*/' | (multi-line-comment | '*' | '/' | [^*/]+) commented-block
slashdash := '/-' line-space*

// Whitespace
ws := unicode-space | multi-line-comment
escline := '\\' ws* (single-line-comment | newline | eof)
newline := See Table (All Newline White_Space)
// Whitespace where newlines are allowed.
line-space := node-space | newline | single-line-comment
// Whitespace within nodes,
// where newline-ish things must be esclined.
node-space := ws* escline ws* | ws+

// Version marker
version :=
    '/-' unicode-space* 'kdl-version' unicode-space+ ('1' | '2')
    unicode-space* newline
~~~

## Whitespace

The following characters should be treated as non-Newline ({{newline}}) [white
space](https://www.unicode.org/Public/UCD/latest/ucd/PropList.txt):

| Name                      | Code Pt  |
| ------------------------- | -------- |
| Character Tabulation      | `U+0009` |
| Space                     | `U+0020` |
| No-Break Space            | `U+00A0` |
| Ogham Space Mark          | `U+1680` |
| En Quad                   | `U+2000` |
| Em Quad                   | `U+2001` |
| En Space                  | `U+2002` |
| Em Space                  | `U+2003` |
| Three-Per-Em Space        | `U+2004` |
| Four-Per-Em Space         | `U+2005` |
| Six-Per-Em Space          | `U+2006` |
| Figure Space              | `U+2007` |
| Punctuation Space         | `U+2008` |
| Thin Space                | `U+2009` |
| Hair Space                | `U+200A` |
| Narrow No-Break Space     | `U+202F` |
| Medium Mathematical Space | `U+205F` |
| Ideographic Space         | `U+3000` |

## Newline

The following character sequences [should be treated as new
lines](https://www.unicode.org/versions/Unicode16.0.0/core-spec/chapter-5/#G41643):

| Acronym | Name                          | Code Pt             |
| ------- | ----------------------------- | ------------------- |
| CRLF    | Carriage Return and Line Feed | `U+000D` + `U+000A` |
| CR      | Carriage Return               | `U+000D`            |
| LF      | Line Feed                     | `U+000A`            |
| NEL     | Next Line                     | `U+0085`            |
| VT      | Vertical tab                  | `U+000B`            |
| FF      | Form Feed                     | `U+000C`            |
| LS      | Line Separator                | `U+2028`            |
| PS      | Paragraph Separator           | `U+2029`            |

Note that for the purpose of new lines, the specific sequence `CRLF` is
considered _a single newline_.

## Disallowed Literal Code Points

The following code points may not appear literally anywhere in the document.
They may be represented in Strings (but not Raw Strings) using Unicode Escapes ({{escapes}}) (`\u{...}`,
except for non Unicode Scalar Value, which can't be represented even as escapes).

- The codepoints `U+0000-0008` or the codepoints `U+000E-001F` (various
  control characters).
- `U+007F` (the Delete control character).
- Any codepoint that is not a [Unicode Scalar
  Value](https://unicode.org/glossary/#unicode_scalar_value) (`U+D800-DFFF`).
- `U+200E-200F`, `U+202A-202E`, and `U+2066-2069`, the [unicode
  "direction control"
  characters](https://www.w3.org/International/questions/qa-bidi-unicode-controls)
- `U+FEFF`, aka Zero-width Non-breaking Space (ZWNBSP)/Byte Order Mark (BOM),
  except as the first code point in a document.

## Grammar language

The grammar language syntax is a combination of ABNF with some regex spice thrown in.
Specifically:

- Single quotes (`'`) are used to denote literal text. `\` within a literal
  string is used for escaping other single-quotes, for initiating unicode
  characters using hex values (`\u{FEFF}`), and for escaping `\` itself
  (`\\`).
- `*` is used for "zero or more", `+` is used for "one or more", and `?` is
  used for "zero or one". Per standard regex semantics, `*` and `+` are _greedy_;
  they match as many instances as possible without failing the match.
- `*?` (used only in raw strings) indicates a _non-greedy_ match;
  it matches as _few_ instances as possible without failing the match.
- `¶` is a _cut point_. It always matches and consumes no characters,
  but once matched, the parser is not allowed to backtrack past that point in the source.
  If a parser would rewind past the cut point, it must instead fail the overall parse,
  as if it had run out of options.
  (This is only used with the `raw-string` production,
  to ensure the first instance of the appropriate closing quote sequence
  is guaranteed to be the end of the raw string,
  rather than allowing it to potentially consume more of the document unexpectedly.)
- `()` can be used to group matches that must be matched together.
- `a | b` means `a or b`, whichever matches first. If multiple items are before
  a `|`, they are a single group. `a b c | d` is equivalent to `(a b c) | d`.
- `[]` are used for regex-style character matches, where any character between
  the brackets will be a single match. `\` is used to escape `\`, `[`, and
  `]`. They also support character ranges (`0-9`), and negation (`^`)
- `-` is used for "except for" or "minus" whatever follows it. For example,
  `a - 'x'` means "any `a`, except something that matches the literal `'x'`".
- The prefix `^` means "something that does not match" whatever follows it.
  For example, `^foo` means "must not match `foo`".
- A single definition may be split over multiple lines. Newlines are treated as
  spaces.
- `//` followed by text on its own line is used as comment syntax.
