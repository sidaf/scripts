from Cookie import Morsel
from types import TupleType, DictType, ListType
from urlparse import urlparse, urlunparse, parse_qsl, urljoin
from urllib import quote, urlencode, quote_plus
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from cookielib import CookieJar, Cookie
from itertools import chain
from re import compile as re_compile
from string import capwords, ascii_letters, digits
import zlib
import json
import time
import os
import re
import sys
import random
import pycurl
try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree


def request(url=None, host=None, port='', scheme='http', path='/', params='', query='', fragment='',
            body='', header='', method='GET', auto_urlencode='1', user_pass='', auth_type='basic',
            follow='0', max_follow='5', cookiejar=None, proxy='', proxy_type='http', resolve='',
            ssl_cert='', timeout_tcp='10', timeout='20', max_mem='-1'):

    if url:
        scheme, host, path, params, query, fragment = urlparse(url)
        del url

    if host:
        if ':' in host:
            host, port = host.split(':')

    if resolve:
        resolve_host, resolve_ip = resolve.split(':', 1)
        if port:
            resolve_port = port
        else:
            resolve_port = 80
        resolve = '%s:%s:%s' % (resolve_host, resolve_port, resolve_ip)
    else:
        resolve = ''

    if proxy_type in PROXY_TYPE_MAP:
        proxy_type = PROXY_TYPE_MAP[proxy_type]
    else:
        raise ValueError('Invalid proxy_type %r' % proxy_type)

    fp = pycurl.Curl()
    fp.setopt(pycurl.SSL_VERIFYPEER, 0)
    fp.setopt(pycurl.SSL_VERIFYHOST, 0)
    fp.setopt(pycurl.HEADER, 1)
    fp.setopt(pycurl.USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0')
    fp.setopt(pycurl.NOSIGNAL, 1)
    fp.setopt(pycurl.FOLLOWLOCATION, int(follow))
    fp.setopt(pycurl.MAXREDIRS, int(max_follow))
    fp.setopt(pycurl.CONNECTTIMEOUT, int(timeout_tcp))
    fp.setopt(pycurl.TIMEOUT, int(timeout))
    fp.setopt(pycurl.PROXY, proxy)
    fp.setopt(pycurl.PROXYTYPE, proxy_type)
    fp.setopt(pycurl.RESOLVE, [resolve])

    headers_output, body_output = StringIO(), StringIO()
    fp.setopt(pycurl.HEADERFUNCTION, headers_output.write)
    fp.setopt(pycurl.HEADER, 0)
    fp.setopt(pycurl.WRITEFUNCTION, body_output.write)

    def debug_func(t, s):
        if max_mem > 0 and request.tell() > max_mem:
            return 0
        if t in (pycurl.INFOTYPE_HEADER_OUT, pycurl.INFOTYPE_DATA_OUT):
            request.write(s)

    max_mem = int(max_mem)
    request = StringIO()
    fp.setopt(pycurl.DEBUGFUNCTION, debug_func)

    fp.setopt(pycurl.VERBOSE, 1)

    if user_pass:
        fp.setopt(pycurl.USERPWD, user_pass)
        if auth_type == 'basic':
            fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
        elif auth_type == 'digest':
            fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
        elif auth_type == 'ntlm':
            fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
        else:
            raise ValueError('Incorrect auth_type %r' % auth_type)

    if ssl_cert:
        fp.setopt(pycurl.SSLCERT, ssl_cert)

    # Do not pass a Cookie: header into HTTPHEADER if using COOKIEFILE as it will produce requests with more than
    # one Cookie: header and the server will process only one of them (eg. Apache only reads the last one)
    if isinstance(cookiejar, CookieJar):
        cookies = cookiejar
    elif isinstance(cookiejar, (TupleType, DictType)):
        cookies = CookieUtils.to_cookiejar(cookiejar)
    else:
        cookies = None

    # Add cookies
    if cookies is not None:
        chunks = []
        for cookie in cookies:
            name, value = cookie.name, cookie.value
            name = quote_plus(name)
            value = quote_plus(value)
            chunks.append('%s=%s;' % (name, value))
        if chunks:
            fp.setopt(pycurl.COOKIE, ''.join(chunks))
        else:
            # set empty cookie to activate cURL cookies
            fp.setopt(pycurl.COOKIELIST, '')

    if auto_urlencode == '1':
        path = quote(path)
        query = urlencode(parse_qsl(query, True))
        body = urlencode(parse_qsl(body, True))

    if port:
        host = '%s:%s' % (host, port)

    url = urlunparse((scheme, host, path, params, query, fragment))
    fp.setopt(pycurl.URL, url)

    if method == 'GET':
        fp.setopt(pycurl.HTTPGET, 1)
    elif method == 'POST':
        fp.setopt(pycurl.POST, 1)
        fp.setopt(pycurl.POSTFIELDS, body)
    elif method in ('HEAD', 'OPTIONS', 'DELETE'):
        fp.setopt(pycurl.NOBODY, 1)
    elif method == "PUT":
        fp.setopt(pycurl.PUT, 1)
        fp.setopt(pycurl.HTTPPOST, body)
    else:
        fp.setopt(pycurl.CUSTOMREQUEST, method)

    headers = [h.strip('\r') for h in header.split('\n') if h]
    fp.setopt(pycurl.HTTPHEADER, headers)

    fp.perform()

    # TODO: Extract any new/updated cookies and update cookiejar...
    # Use match = re.match("^Set-Cookie: (.*)$", header)
    # if match:
    #       cookies.append(match.group(1))

    response = HttpResponse(url=url, curl_opener=fp, body_output=body_output.getvalue(),
                            headers_output=headers_output.getvalue(), request=request.getvalue(), cookiejar=cookies)

    body_output.close()
    headers_output.close()
    request.close()
    fp.close()

    return response


def detect_page_not_found(method, url, resolve=None, quiet=False):
    # Set good defaults
    ecode, emesg = 404, None

    # Generate a random resource that *should* not exist on the web server
    rand_dir = ''.join([random.choice(ascii_letters + digits) for n in xrange(10)])
    test_url = urljoin(url, rand_dir)

    # Curl it
    try:
        response = request(method=method, url=test_url, resolve=resolve)
    except:
        #import traceback
        #traceback.print_exc()
        if not quiet:
            sys.stderr.write("Error requesting '%s', detection of page not found identifier could not be performed.\n" % test_url)
        return ecode, emesg

    # Process the status code returned by the web server
    if 200 <= response.status_code <= 299:
        with open(os.path.join(os.path.realpath(__file__), '../wordlists/404_signatures.txt'), 'r') as fh:
            for sig in fh:
                sig = sig.rstrip()
                if sig in response.text:
                    emesg = sig
                    break
        if emesg is None:
            if not quiet:
                sys.stderr.write("Using first 256 bytes of the response as a page not found identifier.\n")
            emesg = response.text[0:256]
        else:
            if not quiet:
                sys.stderr.write("Using '%s' text as a page not found identifier.\n" % emesg)
    elif response.status_code == 301 or response.status_code == 302 \
            or response.status_code == 303 or response.status_code == 307:
        ecode = response.status_code
        if not quiet:
            sys.stderr.write("Using status code '%s' as a page not found identifier.\n" % str(ecode))
    else:
        ecode = response.status_code
        if not quiet:
            sys.stderr.write("Using status code '%s' as a page not found identifier.\n" % str(ecode))
    return ecode, emesg


def explode_target(url, vhost):
    # Tear down url
    scheme, netloc, path, params, query, fragment = urlparse(url)
    if ':' in netloc:
        host, port = netloc.split(':')
        port = int(port)
    else:
        host = netloc
        if scheme == 'https':
            port = 443
        else:
            port = 80

    # Check if 'host' actually holds an ip address!
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) is not None:
        ip_address = host
    else:
        ip_address = None

    # Replace host value with the virtual host value, if one exists.
    if vhost:
        host = vhost

    # Rebuild url
    if port:
        netloc = '%s:%s' % (host, port)
    else:
        netloc = host
    url = urlunparse((scheme, netloc, path, params, query, fragment))

    # Create resource for easier usage
    resource = url.replace(scheme + "://" + netloc, '')
    
    # if this is a server root, resource will be empty, so need to add a slash
    if not resource:
        resource = '/'

    # Build a resolve entry so that virtual hosts can be accessed
    if host != ip_address:
        resolve = '%s:%s' % (host, ip_address)
    else:
        resolve = None

    # So by now we should have gone from something like this:
    #    target: http://127.0.0.1:80
    #    vhost: www.home.com
    # To this:
    #    url: http://www.home.com:80
    #    resolve: www.home.com:127.0.0.1
    # This allows the use of curl's resolve argument rather than using a 'host:' header to access virtual hosts

    return url, scheme, host, ip_address, port, resource, resolve


class HttpResponse(object):

    def __init__(self, url, curl_opener, body_output, headers_output, request=None, cookiejar=None):
        # Requested url
        self._request_url = url
        self._url = None

        # Request object
        self._request = request

        # Response headers
        self._headers = None

        # Cookies dictionary
        self._cookies = None
        if isinstance(cookiejar, CookieJar):
            self._cookies_jar = cookiejar
        elif isinstance(cookiejar, (TupleType, DictType)):
            self._cookies_jar = CookieUtils.to_cookiejar(cookiejar)
        else:
            self._cookies_jar = None

        self._curl_opener = curl_opener

        # response body
        self._raw_body = body_output
        # response headers
        self._raw_headers = headers_output

        # :Response status code
        self._status_code = int(self._curl_opener.getinfo(pycurl.HTTP_CODE))

        # Unziped end decoded response body
        self._content = None

        # Redirects history
        self._history = []

        # list of parsed headers blocks
        self._headers_history = []

        # get data from curl_opener.getinfo before curl_opener.close()
        self._response_info = dict()
        self._get_curl_info()

        # not good call methods in __init__
        # it's really very BAD
        self._parse_headers_raw()

    def _get_curl_info(self):
        """Extract info from `self._curl_opener` with getinfo()
        """
        for field, value in CURL_INFO_MAP.iteritems():
            try:
                field_data = self._curl_opener.getinfo(value)
            except Exception, e:
                sys.stderr.write("HTTPResponse warning: %s\n" % e)
                continue
            else:
                self._response_info[field] = field_data
        self._url = self._response_info.get("EFFECTIVE_URL")
        return self._response_info

    @property
    def request(self):
        return self._request

    @property
    def url(self):
        if not self._url:
            self._get_curl_info()
        return self._url

    @property
    def status_code(self):
        return self._status_code

    @property
    def content_length(self):
        return int(self._response_info['CONTENT_LENGTH_DOWNLOAD'])

    @property
    def response_time(self):
        return self._response_info['TOTAL_TIME'] - self._response_info['PRETRANSFER_TIME']

    @property
    def cookiesjar(self):
        if not self._cookies_jar:
            self._cookies_jar = CookieJar()
            # add cookies from self._cookies
        return self._cookies_jar

    @property
    def charset(self):
        encoding = None
        if 'content-type' in self.headers:
            content_type = self.headers['content-type'].lower()
            match = re.search('charset=(\S+)', content_type)
            if match:
                encoding = match.group(1)
        if encoding is None:
            # Default encoding for HTML is iso-8859-1.
            # Other content types may have different default encoding,
            # or in case of binary data, may have no encoding at all.
            encoding = 'iso-8859-1'
        return encoding

    @property
    def raw_headers(self):
        return self._raw_headers

    @property
    def raw_body(self):
        """Returns decoded self._content
        """
        if not self._content:
            if 'gzip' in self.headers.get('Content-Encoding', '') and 'zlib' not in pycurl.version:
                try:
                    self._content = zlib.decompress(self._raw_body, 16 + zlib.MAX_WBITS)
                except zlib.error:
                    pass
            else:
                self._content = self._raw_body
        return self._content

    @property
    def text(self):
        """ Returns a charset decoded version of self.raw
        """
        try:
            return self.raw_body.decode(self.charset)
        except (UnicodeDecodeError, TypeError):
            return ''.join([char for char in self.raw_body if ord(char) in [9, 10, 13] + range(32, 126)])

    @property
    def json(self):
        """Returns the json-encoded content of a response
        """
        try:
            return json.loads(self.text)
        except ValueError:
            return None

    @property
    def xml(self):
        try:
            return ElementTree.parse(StringIO(self.text))
        except ElementTree.ParseError:
            return None

    @staticmethod
    def _split_headers_blocks(raw_headers):
        i = 0
        blocks = []
        for item in raw_headers.strip().split("\r\n"):
            if item.startswith("HTTP"):
                blocks.append([item])
                i = len(blocks) - 1
            elif item:
                blocks[i].append(item)
        return blocks

    def _parse_headers_raw(self):
        """Parse response headers and save as instance vars
        """
        def parse_header_block(raw_block):
            r"""Parse headers block
            Arguments:
            - `block`: raw header block
            Returns:
            - `headers_list`:
            """
            block_headers = []
            for header in raw_block:
                if not header:
                    continue
                elif not header.startswith("HTTP"):
                    field, value = map(lambda u: u.strip(), header.split(":", 1))
                    if field.startswith("Location"):
                        # maybe not good
                        if not value.startswith("http"):
                            value = urljoin(self.url, value)
                        self._history.append(value)
                    if value[:1] == value[-1:] == '"':
                        value = value[1:-1]  # strip "
                    block_headers.append((field, value.strip()))
                elif header.startswith("HTTP"):
                    # extract version, code, message from first header
                    try:
                        version, code, message = HTTP_GENERAL_RESPONSE_HEADER.findall(header)[0]
                    except Exception, e:
                        sys.stderr.write("HTTPResponse warning: %s\n" % e)
                        continue
                    else:
                        block_headers.append((version, code, message))
                else:
                    # raise ValueError("Wrong header field")
                    pass
            return block_headers

        raw_headers = self._raw_headers

        for raw_block in self._split_headers_blocks(raw_headers):
            block = parse_header_block(raw_block)
            self._headers_history.append(block)

        last_header = self._headers_history[-1]
        self._headers = CaseInsensitiveDict(last_header[1:])

        if not self._history:
            self._history.append(self.url)

    def parse_cookies(self):
        from Cookie import SimpleCookie, CookieError

        if not self._headers_history:
            self._parse_headers_raw()
        # Get cookies from endpoint
        cookies = []
        for header in chain(*self._headers_history):
            if len(header) > 2:
                continue
            key, value = header[0], header[1]
            if key.lower().startswith("set-cookie"):
                try:
                    cookie = SimpleCookie()
                    cookie.load(value)
                    cookies.extend(cookie.values())

                    # update cookie jar
                    for morsel in cookie.values():
                        if isinstance(self._cookies_jar, CookieJar):
                            self._cookies_jar.set_cookie(CookieUtils.morsel_to_cookie(morsel))
                except CookieError, e:
                    sys.stderr.write("HTTPResponse warning: %s\n" % e)
        self._cookies = dict([(cookie.key, cookie.value) for cookie in cookies])
        return self._cookies

    @property
    def headers(self):
        """Returns response headers
        """
        if not self._headers:
            self._parse_headers_raw()
        return self._headers

    @property
    def cookies(self):
        """Returns list of BaseCookie object
        All cookies in list are ``Cookie.Morsel`` instance
        :return self._cookies: cookies list
        """
        if not self._cookies:
            self.parse_cookies()
        return self._cookies

    @property
    def history(self):
        """Returns redirects history list
        :return: list of `Response` objects
        """
        if not self._history:
            self._parse_headers_raw()
        return self._history


class CookieUtils(object):

    @staticmethod
    def to_cookiejar(cookies):
        if isinstance(cookies, CookieJar):
            return cookies
        if isinstance(cookies, (TupleType, ListType)):
            tmp_cookies = cookies
        elif isinstance(cookies, DictType):
            tmp_cookies = [(k, v) for k, v in cookies.iteritems()]
        else:
            raise ValueError("Unsupported argument")
        cookie_jar = CookieJar()
        for k, v in tmp_cookies:
            cookie = Cookie(version=0, name=k, value=v, port=None, port_specified=False, domain='',
                            domain_specified=False, domain_initial_dot=False, path='/', path_specified=True,
                            secure=False, expires=None, discard=True, comment=None, comment_url=None,
                            rest={'HttpOnly': None}, rfc2109=False)
            cookie_jar.set_cookie(cookie)
        return cookie_jar

    @staticmethod
    def morsel_to_cookie(morsel):
        if not isinstance(morsel, Morsel):
            raise ValueError("morsel must be Morsel instance")

        # Cookies thinks an int expires x seconds in future,
        # cookielib thinks it is x seconds from epoch,
        # so doing the conversion to string for Cookies
        # fmt = '%a, %d %b %Y %H:%M:%S GMT'
        # sc[name]['expires'] = time.strftime(fmt,
        # time.gmtime(cookie.expires))

        # Morsel keys
        attrs = ('expires', 'path', 'comment', 'domain', 'secure', 'version', 'httponly')
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"

        tmp = dict(version=0, name=None, value=None, port=None, port_specified=False, domain='', domain_specified=False,
                   domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True,
                   comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)

        for attr in attrs:
            try:
                if 'httponly' == attr:
                    tmp['rest'] = {'HttpOnly': morsel[attr]}
                elif attr == 'expires':
                    # TODO: parse date?
                    tmp[attr] = time.mktime(time.strptime(morsel.get(attr), time_template))
                    # tmp[attr] = None
                else:
                    tmp[attr] = morsel.get(attr, None)
            except (IndexError, Exception):
                pass

        tmp['name'] = morsel.key
        tmp['value'] = morsel.value

        try:
            tmp['version'] = int(tmp['version'])
        except ValueError:
            tmp['version'] = 1

        cookie = Cookie(**tmp)
        return cookie


class CaseInsensitiveDict(dict):
    def __init__(self, *args, **kwargs):
        tmp_d = dict(*args, **kwargs)
        super(CaseInsensitiveDict, self).__init__([(k.lower(), v) for k, v in tmp_d.iteritems()])

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __delitem__(self, key):
        super(CaseInsensitiveDict, self).__delitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def has_key(self, key):
        return super(CaseInsensitiveDict, self).has_key(key.lower())

    def iteritems(self):
        return ((capwords(k, '-'), v) for k, v in super(CaseInsensitiveDict, self).iteritems())


HTTP_GENERAL_RESPONSE_HEADER = re_compile(r"(?P<version>HTTP\/.*?)\s+(?P<code>\d{3})\s+(?P<message>.*)")

PROXY_TYPE_MAP = {
    'http': pycurl.PROXYTYPE_HTTP,
    'socks4': pycurl.PROXYTYPE_SOCKS4,
    'socks4a': pycurl.PROXYTYPE_SOCKS4A,
    'socks5': pycurl.PROXYTYPE_SOCKS5,
    'socks5_with_hostname': pycurl.PROXYTYPE_SOCKS5_HOSTNAME,
}

# FULL LIST OF GETINFO OPTIONS
CURL_INFO_MAP = {
    # timers
    # An overview of the six time values available from curl_easy_getinfo()
    # perform() --> NAMELOOKUP --> CONNECT --> APPCONNECT
    # --> PRETRANSFER --> STARTTRANSFER --> TOTAL --> REDIRECT
    "TOTAL_TIME": pycurl.TOTAL_TIME,
    "NAMELOOKUP_TIME": pycurl.NAMELOOKUP_TIME,
    "CONNECT_TIME": pycurl.CONNECT_TIME,
    "APPCONNECT_TIME": pycurl.APPCONNECT_TIME,
    "PRETRANSFER_TIME": pycurl.PRETRANSFER_TIME,
    "STARTTRANSFER_TIME": pycurl.STARTTRANSFER_TIME,
    "REDIRECT_TIME": pycurl.REDIRECT_TIME,
    "HTTP_CODE": pycurl.HTTP_CODE,
    "REDIRECT_COUNT": pycurl.REDIRECT_COUNT,
    "REDIRECT_URL": pycurl.REDIRECT_URL,
    "SIZE_UPLOAD": pycurl.SIZE_UPLOAD,
    "SIZE_DOWNLOAD": pycurl.SIZE_DOWNLOAD,
    "SPEED_DOWNLOAD": pycurl.SPEED_DOWNLOAD,
    "SPEED_UPLOAD": pycurl.SPEED_UPLOAD,
    "HEADER_SIZE": pycurl.HEADER_SIZE,
    "REQUEST_SIZE": pycurl.REQUEST_SIZE,
    "SSL_VERIFYRESULT": pycurl.SSL_VERIFYRESULT,
    "SSL_ENGINES": pycurl.SSL_ENGINES,
    "CONTENT_LENGTH_DOWNLOAD": pycurl.CONTENT_LENGTH_DOWNLOAD,
    "CONTENT_LENGTH_UPLOAD": pycurl.CONTENT_LENGTH_UPLOAD,
    "CONTENT_TYPE": pycurl.CONTENT_TYPE,
    "HTTPAUTH_AVAIL": pycurl.HTTPAUTH_AVAIL,
    "PROXYAUTH_AVAIL": pycurl.PROXYAUTH_AVAIL,
    "OS_ERRNO": pycurl.OS_ERRNO,
    "NUM_CONNECTS": pycurl.NUM_CONNECTS,
    "PRIMARY_IP": pycurl.PRIMARY_IP,
    "CURLINFO_LASTSOCKET": pycurl.LASTSOCKET,
    "EFFECTIVE_URL": pycurl.EFFECTIVE_URL,
    "INFO_COOKIELIST": pycurl.INFO_COOKIELIST,
    "RESPONSE_CODE": pycurl.RESPONSE_CODE,
    "HTTP_CONNECTCODE": pycurl.HTTP_CONNECTCODE,
    # "FILETIME": pycurl.FILETIME
    # "PRIVATE": pycurl.PRIVATE, # (Added in 7.10.3)
    # "CERTINFO": pycurl.CERTINFO,
    # "PRIMARY_PORT": pycurl.PRIMARY_PORT,
    }
