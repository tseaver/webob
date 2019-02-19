# code stolen from "six"
import os
import sys
import cgi
import types
from cgi import parse_header, FieldStorage as _cgi_FieldStorage
import rfc6266

# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3
PY2 = sys.version_info[0] == 2

if PY3:
    string_types = str,
    integer_types = int,
    class_types = type,
    text_type = str
    long = int
else:
    string_types = basestring,
    integer_types = (int, long)
    class_types = (type, types.ClassType)
    text_type = unicode
    long = long

# TODO check if errors is ever used

def text_(s, encoding='latin-1', errors='strict'):
    if isinstance(s, bytes):
        return s.decode(encoding, errors)
    return s

def bytes_(s, encoding='latin-1', errors='strict'):
    if isinstance(s, text_type):
        return s.encode(encoding, errors)
    return s

if PY3:
    def native_(s, encoding='latin-1', errors='strict'):
        if isinstance(s, text_type):
            return s
        return str(s, encoding, errors)
else:
    def native_(s, encoding='latin-1', errors='strict'):
        if isinstance(s, text_type):
            return s.encode(encoding, errors)
        return str(s)

try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty

try:
    from collections.abc import MutableMapping
    from collections.abc import Iterable
except ImportError:
    from collections import MutableMapping
    from collections import Iterable

if PY3:
    from urllib import parse
    urlparse = parse
    from urllib.parse import quote as url_quote
    from urllib.parse import urlencode as url_encode, quote_plus
    from urllib.request import urlopen as url_open
else:
    import urlparse
    from urllib import quote_plus
    from urllib import quote as url_quote
    from urllib import unquote as url_unquote
    from urllib import urlencode as url_encode
    from urllib2 import urlopen as url_open

if PY3: # pragma: no cover
    def reraise(exc_info):
        etype, exc, tb = exc_info
        if exc.__traceback__ is not tb:
            raise exc.with_traceback(tb)
        raise exc
else:
    exec("def reraise(exc): raise exc[0], exc[1], exc[2]")


if PY3:
    def iteritems_(d):
        return d.items()
    def itervalues_(d):
        return d.values()
else:
    def iteritems_(d):
        return d.iteritems()
    def itervalues_(d):
        return d.itervalues()


if PY3: # pragma: no cover
    def unquote(string):
        if not string:
            return b''
        res = string.split(b'%')
        if len(res) != 1:
            string = res[0]
            for item in res[1:]:
                try:
                    string += bytes([int(item[:2], 16)]) + item[2:]
                except ValueError:
                    string += b'%' + item
        return string

    def url_unquote(s):
        return unquote(s.encode('ascii')).decode('latin-1')

    def parse_qsl_text(qs, encoding='utf-8'):
        qs = qs.encode('latin-1')
        qs = qs.replace(b'+', b' ')
        pairs = [s2 for s1 in qs.split(b'&') for s2 in s1.split(b';') if s2]
        for name_value in pairs:
            nv = name_value.split(b'=', 1)
            if len(nv) != 2:
                nv.append('')
            name = unquote(nv[0])
            value = unquote(nv[1])
            yield (name.decode(encoding), value.decode(encoding))

else:
    from urlparse import parse_qsl

    def parse_qsl_text(qs, encoding='utf-8'):
        qsl = parse_qsl(
            qs,
            keep_blank_values=True,
            strict_parsing=False
        )
        for (x, y) in qsl:
            yield (x.decode(encoding), y.decode(encoding))


if PY3:
    from html import escape
else:
    from cgi import escape


if PY3:
    import tempfile
    from io import StringIO, BytesIO, TextIOWrapper
    from collections.abc import Mapping
    from email.message import Message
    import locale

    # Various different FieldStorage work-arounds required on Python 3.x
    class cgi_FieldStorage(_cgi_FieldStorage): # pragma: no cover

        def __init__(self, fp=None, headers=None, outerboundary=b'',
                     environ=os.environ, keep_blank_values=0, strict_parsing=0,
                     limit=None, encoding='utf-8', errors='replace',
                     max_num_fields=None):
            """Constructor.  Read multipart/* until last part.

            Arguments, all optional:

            fp              : file pointer; default: sys.stdin.buffer
                (not used when the request method is GET)
                Can be :
                1. a TextIOWrapper object
                2. an object whose read() and readline() methods return bytes

            headers         : header dictionary-like object; default:
                taken from environ as per CGI spec

            outerboundary   : terminating multipart boundary
                (for internal use only)

            environ         : environment dictionary; default: os.environ

            keep_blank_values: flag indicating whether blank values in
                percent-encoded forms should be treated as blank strings.
                A true value indicates that blanks should be retained as
                blank strings.  The default false value indicates that
                blank values are to be ignored and treated as if they were
                not included.

            strict_parsing: flag indicating what to do with parsing errors.
                If false (the default), errors are silently ignored.
                If true, errors raise a ValueError exception.

            limit : used internally to read parts of multipart/form-data forms,
                to exit from the reading loop when reached. It is the difference
                between the form content-length and the number of bytes already
                read

            encoding, errors : the encoding and error handler used to decode the
                binary stream to strings. Must be the same as the charset defined
                for the page sending the form (content-type : meta http-equiv or
                header)

            max_num_fields: int. If set, then __init__ throws a ValueError
                if there are more than n fields read by parse_qsl().

            """
            method = 'GET'
            self.keep_blank_values = keep_blank_values
            self.strict_parsing = strict_parsing
            self.max_num_fields = max_num_fields
            if 'REQUEST_METHOD' in environ:
                method = environ['REQUEST_METHOD'].upper()
            self.qs_on_post = None
            if method == 'GET' or method == 'HEAD':
                if 'QUERY_STRING' in environ:
                    qs = environ['QUERY_STRING']
                elif sys.argv[1:]:
                    qs = sys.argv[1]
                else:
                    qs = ""
                qs = qs.encode(locale.getpreferredencoding(), 'surrogateescape')
                fp = BytesIO(qs)
                if headers is None:
                    headers = {'content-type':
                                   "application/x-www-form-urlencoded"}
            if headers is None:
                headers = {}
                if method == 'POST':
                    # Set default content-type for POST to what's traditional
                    headers['content-type'] = "application/x-www-form-urlencoded"
                if 'CONTENT_TYPE' in environ:
                    headers['content-type'] = environ['CONTENT_TYPE']
                if 'QUERY_STRING' in environ:
                    self.qs_on_post = environ['QUERY_STRING']
                if 'CONTENT_LENGTH' in environ:
                    headers['content-length'] = environ['CONTENT_LENGTH']
            else:
                if not (isinstance(headers, (Mapping, Message))):
                    raise TypeError("headers must be mapping or an instance of "
                                    "email.message.Message")
            self.headers = headers
            if fp is None:
                self.fp = sys.stdin.buffer
            # self.fp.read() must return bytes
            elif isinstance(fp, TextIOWrapper):
                self.fp = fp.buffer
            else:
                if not (hasattr(fp, 'read') and hasattr(fp, 'readline')):
                    raise TypeError("fp must be file pointer")
                self.fp = fp

            self.encoding = encoding
            self.errors = errors

            if not isinstance(outerboundary, bytes):
                raise TypeError('outerboundary must be bytes, not %s'
                                % type(outerboundary).__name__)
            self.outerboundary = outerboundary

            self.bytes_read = 0
            self.limit = limit

            # Process content-disposition header
            cdisp, pdict = "", {}
            if 'content-disposition' in self.headers:
                cd = rfc6266.parse_headers(self.headers['content-disposition'], relaxed=True)
                cdisp, pdict = cd.disposition, cd.assocs
            self.disposition = cdisp
            self.disposition_options = pdict
            self.name = None
            if 'name' in pdict:
                self.name = pdict['name']
            self.filename = None
            if 'filename' in pdict:
                self.filename = pdict['filename']
            if 'filename*' in pdict:
                self.filename = pdict['filename*'].string

            self._binary_file = self.filename is not None

            # Process content-type header
            #
            # Honor any existing content-type header.  But if there is no
            # content-type header, use some sensible defaults.  Assume
            # outerboundary is "" at the outer level, but something non-false
            # inside a multi-part.  The default for an inner part is text/plain,
            # but for an outer part it should be urlencoded.  This should catch
            # bogus clients which erroneously forget to include a content-type
            # header.
            #
            # See below for what we do if there does exist a content-type header,
            # but it happens to be something we don't understand.
            if 'content-type' in self.headers:
                ctype, pdict = parse_header(self.headers['content-type'])
            elif self.outerboundary or method != 'POST':
                ctype, pdict = "text/plain", {}
            else:
                ctype, pdict = 'application/x-www-form-urlencoded', {}
            self.type = ctype
            self.type_options = pdict
            if 'boundary' in pdict:
                self.innerboundary = pdict['boundary'].encode(self.encoding,
                                                              self.errors)
            else:
                self.innerboundary = b""

            clen = -1
            if 'content-length' in self.headers:
                try:
                    clen = int(self.headers['content-length'])
                except ValueError:
                    pass
                if cgi.maxlen and clen > cgi.maxlen:
                    raise ValueError('Maximum content length exceeded')
            self.length = clen
            if self.limit is None and clen:
                self.limit = clen

            self.list = self.file = None
            self.done = 0
            if ctype == 'application/x-www-form-urlencoded':
                self.read_urlencoded()
            elif ctype[:10] == 'multipart/':
                self.read_multi(environ, keep_blank_values, strict_parsing)
            else:
                self.read_single()

        # Work around https://bugs.python.org/issue27777
        def make_file(self):
            if self._binary_file or self.length >= 0:
                return tempfile.TemporaryFile("wb+")
            else:
                return tempfile.TemporaryFile(
                    "w+",
                    encoding=self.encoding, newline='\n'
                )

        # Work around http://bugs.python.org/issue23801
        # This is taken exactly from Python 3.5's cgi.py module
        def read_multi(self, environ, keep_blank_values, strict_parsing):
            """Internal: read a part that is itself multipart."""
            ib = self.innerboundary
            if not cgi.valid_boundary(ib):
                raise ValueError(
                    'Invalid boundary in multipart form: %r' % (ib,))
            self.list = []
            if self.qs_on_post:
                query = cgi.urllib.parse.parse_qsl(
                    self.qs_on_post, self.keep_blank_values,
                    self.strict_parsing,
                    encoding=self.encoding, errors=self.errors)
                for key, value in query:
                    self.list.append(cgi.MiniFieldStorage(key, value))

            klass = self.FieldStorageClass or self.__class__
            first_line = self.fp.readline()  # bytes
            if not isinstance(first_line, bytes):
                raise ValueError("%s should return bytes, got %s"
                                 % (self.fp, type(first_line).__name__))
            self.bytes_read += len(first_line)

            # Ensure that we consume the file until we've hit our innerboundary
            while (first_line.strip() != (b"--" + self.innerboundary) and
                    first_line):
                first_line = self.fp.readline()
                self.bytes_read += len(first_line)

            while True:
                parser = cgi.FeedParser()
                hdr_text = b""
                while True:
                    data = self.fp.readline()
                    hdr_text += data
                    if not data.strip():
                        break
                if not hdr_text:
                    break
                # parser takes strings, not bytes
                self.bytes_read += len(hdr_text)
                parser.feed(hdr_text.decode(self.encoding, self.errors))
                headers = parser.close()
                # Some clients add Content-Length for part headers, ignore them
                if 'content-length' in headers:
                    filename = None
                    if 'content-disposition' in self.headers:
                        cdisp, pdict = parse_header(self.headers['content-disposition'])
                        if 'filename' in pdict:
                            filename = pdict['filename']
                    if filename is None:
                        del headers['content-length']
                part = klass(self.fp, headers, ib, environ, keep_blank_values,
                             strict_parsing, self.limit-self.bytes_read,
                             self.encoding, self.errors)
                self.bytes_read += part.bytes_read
                self.list.append(part)
                if part.done or self.bytes_read >= self.length > 0:
                    break
            self.skip_lines()
else:
    try:
        from cStringIO import StringIO
    except ImportError:  # pragma: no cover
        from StringIO import StringIO

    class cgi_FieldStorage(_cgi_FieldStorage):  # pragma: no cover
        def __init__(self, fp=None, headers=None, outerboundary="",
                     environ=os.environ, keep_blank_values=0, strict_parsing=0,
                     max_num_fields=None):
            """Constructor.  Read multipart/* until last part.

            Arguments, all optional:

            fp              : file pointer; default: sys.stdin
                (not used when the request method is GET)

            headers         : header dictionary-like object; default:
                taken from environ as per CGI spec

            outerboundary   : terminating multipart boundary
                (for internal use only)

            environ         : environment dictionary; default: os.environ

            keep_blank_values: flag indicating whether blank values in
                percent-encoded forms should be treated as blank strings.
                A true value indicates that blanks should be retained as
                blank strings.  The default false value indicates that
                blank values are to be ignored and treated as if they were
                not included.

            strict_parsing: flag indicating what to do with parsing errors.
                If false (the default), errors are silently ignored.
                If true, errors raise a ValueError exception.

            max_num_fields: int. If set, then __init__ throws a ValueError
                if there are more than n fields read by parse_qsl().

            """
            method = 'GET'
            self.keep_blank_values = keep_blank_values
            self.strict_parsing = strict_parsing
            self.max_num_fields = max_num_fields
            if 'REQUEST_METHOD' in environ:
                method = environ['REQUEST_METHOD'].upper()
            self.qs_on_post = None
            if method == 'GET' or method == 'HEAD':
                if 'QUERY_STRING' in environ:
                    qs = environ['QUERY_STRING']
                elif sys.argv[1:]:
                    qs = sys.argv[1]
                else:
                    qs = ""
                fp = StringIO(qs)
                if headers is None:
                    headers = {'content-type':
                                   "application/x-www-form-urlencoded"}
            if headers is None:
                headers = {}
                if method == 'POST':
                    # Set default content-type for POST to what's traditional
                    headers['content-type'] = "application/x-www-form-urlencoded"
                if 'CONTENT_TYPE' in environ:
                    headers['content-type'] = environ['CONTENT_TYPE']
                if 'QUERY_STRING' in environ:
                    self.qs_on_post = environ['QUERY_STRING']
                if 'CONTENT_LENGTH' in environ:
                    headers['content-length'] = environ['CONTENT_LENGTH']
            self.fp = fp or sys.stdin
            self.headers = headers
            self.outerboundary = outerboundary

            # Process content-disposition header
            cdisp, pdict = "", {}
            if 'content-disposition' in self.headers:
                cd = rfc6266.parse_headers(self.headers['content-disposition'], relaxed=True)
                cdisp, pdict = cd.disposition, cd.assocs

            self.disposition = cdisp
            self.disposition_options = pdict
            self.name = None
            if 'name' in pdict:
                self.name = pdict['name']
            self.filename = None
            if 'filename' in pdict:
                self.filename = pdict['filename']
            if 'filename*' in pdict:
                self.filename = pdict['filename*'].string
            if isinstance(self.filename, unicode):
                self.filename = self.filename.encode('utf8')

            # Process content-type header
            #
            # Honor any existing content-type header.  But if there is no
            # content-type header, use some sensible defaults.  Assume
            # outerboundary is "" at the outer level, but something non-false
            # inside a multi-part.  The default for an inner part is text/plain,
            # but for an outer part it should be urlencoded.  This should catch
            # bogus clients which erroneously forget to include a content-type
            # header.
            #
            # See below for what we do if there does exist a content-type header,
            # but it happens to be something we don't understand.
            if 'content-type' in self.headers:
                ctype, pdict = parse_header(self.headers['content-type'])
            elif self.outerboundary or method != 'POST':
                ctype, pdict = "text/plain", {}
            else:
                ctype, pdict = 'application/x-www-form-urlencoded', {}
            self.type = ctype
            self.type_options = pdict
            self.innerboundary = ""
            if 'boundary' in pdict:
                self.innerboundary = pdict['boundary']
            clen = -1
            if 'content-length' in self.headers:
                try:
                    clen = int(self.headers['content-length'])
                except ValueError:
                    pass
                if cgi.maxlen and clen > cgi.maxlen:
                    raise ValueError('Maximum content length exceeded')
            self.length = clen

            self.list = self.file = None
            self.done = 0
            if ctype == 'application/x-www-form-urlencoded':
                self.read_urlencoded()
            elif ctype[:10] == 'multipart/':
                self.read_multi(environ, keep_blank_values, strict_parsing)
            else:
                self.read_single()
