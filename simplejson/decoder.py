"""Implementation of JSONDecoder
"""
from __future__ import absolute_import

import re
import struct
import sys

from .compat import PY3, unichr
from .scanner import JSONDecodeError, make_scanner


def _import_c_scanstring():
    try:
        from ._speedups import scanstring

        return scanstring
    except ImportError:
        return None


c_scanstring = _import_c_scanstring()

# NOTE (3.1.0): JSONDecodeError may still be imported from this module for
# compatibility, but it was never in the __all__
__all__ = ["JSONDecoder"]

FLAGS = re.VERBOSE | re.MULTILINE | re.DOTALL


def _floatconstants():
    if sys.version_info < (2, 6):
        _BYTES = "7FF80000000000007FF0000000000000".decode("hex")
        nan, inf = struct.unpack(">dd", _BYTES)
    else:
        nan = float("nan")
        inf = float("inf")
    return nan, inf, -inf


NaN, PosInf, NegInf = _floatconstants()

_CONSTANTS = {
    "-Infinity": NegInf,
    "Infinity": PosInf,
    "NaN": NaN,
}

STRINGCHUNK = re.compile(r'(.*?)(["\\\x00-\x1f])', FLAGS)

# & Support Single Quotes
STRINGCHUNKUNQUOTED = re.compile(r"(.*?)([:\\\x00-\x1f])", FLAGS)
STRINGCHUNKSINGLEQUOTED = re.compile(r"(.*?)(['\\\x00-\x1f])", FLAGS)

BACKSLASH = {
    '"': u'"',
    "\\": u"\\",
    "/": u"/",
    "b": u"\b",
    "f": u"\f",
    "n": u"\n",
    "r": u"\r",
    "t": u"\t",
}

# & Support Single Quote
SINGLE_QUOTE_BACKSLASH = {
    "'": u"'",
    "\\": u"\u005c",
    "/": u"/",
    "b": u"\b",
    "f": u"\f",
    "n": u"\n",
    "r": u"\r",
    "t": u"\t",
}

DEFAULT_ENCODING = "utf-8"

# & Support Single Quote
def parse_single_quoted_string(s, end, encoding=None, strict=True):
    return py_scanstring(
        s, end, encoding, strict, SINGLE_QUOTE_BACKSLASH, STRINGCHUNKSINGLEQUOTED.match
    )


def py_scanstring(
    s,
    end,
    encoding=None,
    strict=True,
    _b=BACKSLASH,
    _m=STRINGCHUNK.match,
    _join=u"".join,
    _PY3=PY3,
    _maxunicode=sys.maxunicode,
):
    """Scan the string s for a JSON string. End is the index of the
    character in s after the quote that started the JSON string.
    Unescapes all valid JSON string escape sequences and raises ValueError
    on attempt to decode an invalid string. If strict is False then literal
    control characters are allowed in the string.

    Returns a tuple of the decoded string and the index of the character in s
    after the end quote."""
    if encoding is None:
        encoding = DEFAULT_ENCODING
    chunks = []
    _append = chunks.append
    begin = end - 1
    while 1:
        chunk = _m(s, end)
        if chunk is None:
            raise JSONDecodeError("Unterminated string starting at", s, begin)
        end = chunk.end()
        content, terminator = chunk.groups()
        # Content is contains zero or more unescaped string characters
        if content:
            if not _PY3 and not isinstance(content, unicode):
                content = unicode(content, encoding)
            _append(content)
        # Terminator is the end of string, a literal control character,
        # or a backslash denoting that an escape sequence follows
        # if terminator == '"':
        #     break
        # & Support Single Quote / Non Quoted (Add behind flag?)
        if not is_not_quote(terminator):
            break
        elif terminator != "\\":
            if strict:
                msg = "Invalid control character %r at"
                raise JSONDecodeError(msg, s, end)
            else:
                _append(terminator)
                continue
        try:
            esc = s[end]
        except IndexError:
            raise JSONDecodeError("Unterminated string starting at", s, begin)
        # If not a unicode escape sequence, must be in the lookup table
        if esc != "u":
            try:
                char = _b[esc]
            except KeyError:
                msg = "Invalid \\X escape sequence %r"
                raise JSONDecodeError(msg, s, end)
            end += 1
        else:
            # Unicode escape sequence
            msg = "Invalid \\uXXXX escape sequence"
            esc = s[end + 1 : end + 5]
            escX = esc[1:2]
            if len(esc) != 4 or escX == "x" or escX == "X":
                raise JSONDecodeError(msg, s, end - 1)
            try:
                uni = int(esc, 16)
            except ValueError:
                raise JSONDecodeError(msg, s, end - 1)
            end += 5
            # Check for surrogate pair on UCS-4 systems
            # Note that this will join high/low surrogate pairs
            # but will also pass unpaired surrogates through
            if (
                _maxunicode > 65535
                and uni & 0xFC00 == 0xD800
                and s[end : end + 2] == "\\u"
            ):
                esc2 = s[end + 2 : end + 6]
                escX = esc2[1:2]
                if len(esc2) == 4 and not (escX == "x" or escX == "X"):
                    try:
                        uni2 = int(esc2, 16)
                    except ValueError:
                        raise JSONDecodeError(msg, s, end)
                    if uni2 & 0xFC00 == 0xDC00:
                        uni = 0x10000 + (((uni - 0xD800) << 10) | (uni2 - 0xDC00))
                        end += 6
            char = unichr(uni)
        # Append the unescaped character
        _append(char)
    return _join(chunks), end


# Use speedup if available
scanstring = py_scanstring

WHITESPACE = re.compile(r"[ \t\n\r]*", FLAGS)
WHITESPACE_STR = " \t\n\r"

# & Support Single Quote
UNQUOTEDDICT = {
    "/": "/",
    "\\": "\\",
    ";": ";",
    "#": "#",
    "=": "=",
    "{": "{",
    "}": "}",
    "[": "[",
    "]": "]",
    ":": ":",
    ",": ",",
    " ": " ",
    "\t": "\t",
    "\f": "\f",
    "\r": "\r",
    "\n": "\n",
}

# & Support Single Quote
QUOTE_DICT = {'"': '"', "'": "'"}

# & Support Single Quote
def is_literal(char):
    """
    Checks to see if the character
    should be treated literally
    """
    return not UNQUOTEDDICT.get(char, None)


# & Support Single Quote
def is_not_quote(char):
    """
    Checks to see if the character
    is a Quote both single or double
    """
    return not QUOTE_DICT.get(char, None)


# & Support Unquoted Quote
def nexUnquotedKey(s, end):
    """
    Checks to see if the key is unquoted
    and processes it properly
    """
    chunk = STRINGCHUNKUNQUOTED.match(s, end)
    for i in range(chunk.end()):
        index = i + end
        if not is_literal(s[index]):
            return s[end:index], index


def JSONObject(
    state,
    encoding,
    strict,
    scan_once,
    object_hook,
    object_pairs_hook,
    extended_support,
    memo=None,
    _w=WHITESPACE.match,
    _ws=WHITESPACE_STR,
):
    (s, end) = state
    # Backwards compatibility
    if memo is None:
        memo = {}
    memo_get = memo.setdefault
    pairs = []
    # Use a slice to prevent IndexError from being raised, the following
    # check will raise a more specific ValueError if the string is empty
    nextchar = s[end : end + 1]
    # Normally we expect nextchar == '"'
    literal_check = False

    # & Support Single Quote
    not_quote = is_not_quote(nextchar) if extended_support else nextchar != '"'
    if not_quote:
        if nextchar in _ws:
            end = _w(s, end).end()
            nextchar = s[end : end + 1]
        # Trivial empty object
        # & Support Single Quote
        if extended_support:
            literal_check = is_literal(nextchar)
        if nextchar == "}":
            if object_pairs_hook is not None:
                result = object_pairs_hook(pairs)
                return result, end + 1
            pairs = {}
            if object_hook is not None:
                pairs = object_hook(pairs)
            return pairs, end + 1
        elif nextchar != '"':
            if not literal_check:
                raise JSONDecodeError(
                    "Expecting property name enclosed in quotes", s, end
                )

    # & Support Single Quote
    if not literal_check:
        end += 1

    while True:
        # & Unquoted Support
        if literal_check and extended_support:
            key, end = nexUnquotedKey(s, end)
        else:
            # & Support Single Quote
            if nextchar == "'" and extended_support:
                key, end = scanstring(
                    s,
                    end,
                    encoding,
                    strict,
                    SINGLE_QUOTE_BACKSLASH,
                    STRINGCHUNKSINGLEQUOTED.match,
                )
            else:
                key, end = scanstring(s, end, encoding, strict)

        key = memo_get(key, key)

        # To skip some function call overhead we optimize the fast paths where
        # the JSON key separator is ": " or just ":".
        if s[end : end + 1] != ":":
            end = _w(s, end).end()
            if s[end : end + 1] != ":":
                raise JSONDecodeError("Expecting ':' delimiter", s, end)

        end += 1

        try:
            if s[end] in _ws:
                end += 1
                if s[end] in _ws:
                    end = _w(s, end + 1).end()
        except IndexError:
            pass

        value, end = scan_once(s, end)
        pairs.append((key, value))

        try:
            nextchar = s[end]
            if nextchar in _ws:
                end = _w(s, end + 1).end()
                nextchar = s[end]
        except IndexError:
            nextchar = ""
        end += 1

        if nextchar == "}":
            break
        elif nextchar != ",":
            raise JSONDecodeError("Expecting ',' delimiter or '}'", s, end - 1)

        try:
            nextchar = s[end]
            if nextchar in _ws:
                end += 1
                nextchar = s[end]
                if nextchar in _ws:
                    end = _w(s, end + 1).end()
                    nextchar = s[end]
        except IndexError:
            nextchar = ""

        # & Support Single Quote
        if not literal_check:
            end += 1
            # & Support Single Quote
            not_quote = is_not_quote(nextchar) if extended_support else nextchar != '"'
            if not_quote and not extended_support:
                raise JSONDecodeError(
                    "Expecting property name enclosed in double quotes", s, end - 1
                )
    if object_pairs_hook is not None:
        result = object_pairs_hook(pairs)
        return result, end
    pairs = dict(pairs)
    if object_hook is not None:
        pairs = object_hook(pairs)
    return pairs, end


def JSONArray(state, scan_once, _w=WHITESPACE.match, _ws=WHITESPACE_STR):
    (s, end) = state
    values = []
    nextchar = s[end : end + 1]
    if nextchar in _ws:
        end = _w(s, end + 1).end()
        nextchar = s[end : end + 1]
    # Look-ahead for trivial empty array
    if nextchar == "]":
        return values, end + 1
    elif nextchar == "":
        raise JSONDecodeError("Expecting value or ']'", s, end)
    _append = values.append
    while True:
        value, end = scan_once(s, end)
        _append(value)
        nextchar = s[end : end + 1]
        if nextchar in _ws:
            end = _w(s, end + 1).end()
            nextchar = s[end : end + 1]
        end += 1
        if nextchar == "]":
            break
        elif nextchar != ",":
            raise JSONDecodeError("Expecting ',' delimiter or ']'", s, end - 1)

        try:
            if s[end] in _ws:
                end += 1
                if s[end] in _ws:
                    end = _w(s, end + 1).end()
        except IndexError:
            pass

    return values, end


class JSONDecoder(object):
    """Simple JSON <http://json.org> decoder

    Performs the following translations in decoding by default:

    +---------------+-------------------+
    | JSON          | Python            |
    +===============+===================+
    | object        | dict              |
    +---------------+-------------------+
    | array         | list              |
    +---------------+-------------------+
    | string        | str, unicode      |
    +---------------+-------------------+
    | number (int)  | int, long         |
    +---------------+-------------------+
    | number (real) | float             |
    +---------------+-------------------+
    | true          | True              |
    +---------------+-------------------+
    | false         | False             |
    +---------------+-------------------+
    | null          | None              |
    +---------------+-------------------+

    It also understands ``NaN``, ``Infinity``, and ``-Infinity`` as
    their corresponding ``float`` values, which is outside the JSON spec.

    """

    def __init__(
        self,
        encoding=None,
        object_hook=None,
        parse_float=None,
        parse_int=None,
        parse_constant=None,
        extended_support=None,
        strict=True,
        object_pairs_hook=None,
    ):
        """
        *encoding* determines the encoding used to interpret any
        :class:`str` objects decoded by this instance (``'utf-8'`` by
        default).  It has no effect when decoding :class:`unicode` objects.

        Note that currently only encodings that are a superset of ASCII work,
        strings of other encodings should be passed in as :class:`unicode`.

        *object_hook*, if specified, will be called with the result of every
        JSON object decoded and its return value will be used in place of the
        given :class:`dict`.  This can be used to provide custom
        deserializations (e.g. to support JSON-RPC class hinting).

        *object_pairs_hook* is an optional function that will be called with
        the result of any object literal decode with an ordered list of pairs.
        The return value of *object_pairs_hook* will be used instead of the
        :class:`dict`.  This feature can be used to implement custom decoders
        that rely on the order that the key and value pairs are decoded (for
        example, :func:`collections.OrderedDict` will remember the order of
        insertion). If *object_hook* is also defined, the *object_pairs_hook*
        takes priority.

        *parse_float*, if specified, will be called with the string of every
        JSON float to be decoded.  By default, this is equivalent to
        ``float(num_str)``. This can be used to use another datatype or parser
        for JSON floats (e.g. :class:`decimal.Decimal`).

        *parse_int*, if specified, will be called with the string of every
        JSON int to be decoded.  By default, this is equivalent to
        ``int(num_str)``.  This can be used to use another datatype or parser
        for JSON integers (e.g. :class:`float`).

        *parse_constant*, if specified, will be called with one of the
        following strings: ``'-Infinity'``, ``'Infinity'``, ``'NaN'``.  This
        can be used to raise an exception if invalid JSON numbers are
        encountered.

        *strict* controls the parser's behavior when it encounters an
        invalid control character in a string. The default setting of
        ``True`` means that unescaped control characters are parse errors, if
        ``False`` then control characters will be allowed in strings.

        """
        if encoding is None:
            encoding = DEFAULT_ENCODING
        self.encoding = encoding
        self.object_hook = object_hook
        self.object_pairs_hook = object_pairs_hook
        self.parse_float = parse_float or float
        self.extended_support = extended_support
        self.parse_int = parse_int or int
        self.parse_constant = parse_constant or _CONSTANTS.__getitem__
        self.strict = strict
        self.parse_object = JSONObject
        self.parse_array = JSONArray
        # & Support Single Quote
        self.parse_single_quoted_string = parse_single_quoted_string
        self.parse_string = scanstring
        self.memo = {}
        self.scan_once = make_scanner(self)

    def decode(self, s, _w=WHITESPACE.match, _PY3=PY3):
        """Return the Python representation of ``s`` (a ``str`` or ``unicode``
        instance containing a JSON document)

        """
        if _PY3 and isinstance(s, bytes):
            s = str(s, self.encoding)
        obj, end = self.raw_decode(s)
        end = _w(s, end).end()
        if end != len(s):
            raise JSONDecodeError("Extra data", s, end, len(s))
        return obj

    def raw_decode(self, s, idx=0, _w=WHITESPACE.match, _PY3=PY3):
        """Decode a JSON document from ``s`` (a ``str`` or ``unicode``
        beginning with a JSON document) and return a 2-tuple of the Python
        representation and the index in ``s`` where the document ended.
        Optionally, ``idx`` can be used to specify an offset in ``s`` where
        the JSON document begins.

        This can be used to decode a JSON document from a string that may
        have extraneous data at the end.

        """
        if idx < 0:
            # Ensure that raw_decode bails on negative indexes, the regex
            # would otherwise mask this behavior. #98
            raise JSONDecodeError("Expecting value", s, idx)
        if _PY3 and not isinstance(s, str):
            raise TypeError("Input string must be text, not bytes")
        # strip UTF-8 bom
        if len(s) > idx:
            ord0 = ord(s[idx])
            if ord0 == 0xFEFF:
                idx += 1
            elif ord0 == 0xEF and s[idx : idx + 3] == "\xef\xbb\xbf":
                idx += 3
        return self.scan_once(s, idx=_w(s, idx).end())
