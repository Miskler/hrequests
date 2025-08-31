import base64
import re
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union, Mapping
from urllib.parse import urlencode

from geventhttpclient import HTTPClient
from geventhttpclient.header import Headers
from orjson import dumps, loads, JSONDecodeError

from gzip import decompress as gunzip

import hrequests
from hrequests.cffi import library
from hrequests.proxies import BaseProxy

from .cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    cookiejar_to_list,
    extract_cookies_to_jar,
    list_to_cookiejar,
    merge_cookies,
)
from .exceptions import ClientException, ProxyFormatException
from .toolbelt import CaseInsensitiveDict

'''
TLSClient heavily based on https://github.com/FlorianREGAZ/Python-Tls-Client
Copyright (c) 2022 Florian Zager
'''

SUPPORTED_PROXIES: Set[str] = {'http', 'https', 'socks5'}
PROXY_PATTERN: re.Pattern = re.compile(
    rf"^(?:{'|'.join(SUPPORTED_PROXIES)})://(?:[^\:]+:[^@]+@)?.*?(?:\:\d+)?$"
)


def verify_proxy(proxy: str) -> None:
    # verify that the proxy is valid with regex
    if not PROXY_PATTERN.match(proxy):
        raise ProxyFormatException(f'Invalid proxy: {proxy}')


class _SanitizedCID(CaseInsensitiveDict):
    def __setitem__(self, key, value):
        super().__setitem__(key, None if value is None else str(value))
    def update(self, other=None, **kwargs):
        if other:
            if hasattr(other, "items"):
                other = {k: (None if v is None else str(v)) for k, v in other.items()}
            else:
                other = [(k, None if v is None else str(v)) for k, v in other]
        if kwargs:
            kwargs = {k: (None if v is None else str(v)) for k, v in kwargs.items()}
        return super().update(other, **kwargs)


def _to_str(x) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode("latin-1", errors="replace")
    return str(x)

def _normalize_headers(headers_obj) -> dict[str, object]:
    if not headers_obj:
        return {}
    from collections.abc import Mapping as _Mapping
    if isinstance(headers_obj, _Mapping):
        out = {}
        for k, v in headers_obj.items():
            k = _to_str(k)
            if isinstance(v, (list, tuple)):
                out[k] = [_to_str(x) for x in v]
            else:
                out[k] = _to_str(v)
        return out
    out = {}
    try:
        for pair in headers_obj:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            k, v = pair
            k = _to_str(k); v = _to_str(v)
            if k in out:
                if isinstance(out[k], list):
                    out[k].append(v)
                else:
                    out[k] = [out[k], v]
            else:
                out[k] = v
    except Exception:
        return {}
    return out

def _get_header(headers: Mapping[str, object], name: str) -> Optional[str]:
    name_l = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == name_l:
            if isinstance(v, (list, tuple)):
                return _to_str(v[0]) if v else None
            return _to_str(v)
    return None

def _maybe_gunzip(body: bytes, headers: Mapping[str, object]) -> bytes:
    enc = (_get_header(headers, "Content-Encoding") or "").lower()
    if "gzip" in enc and body and not (body.startswith(b"{") or body.startswith(b"[")):
        try:
            return gunzip(body)
        except Exception as e:
            raise RuntimeError(f"Gzip decompress failed: {e}. Prefix={body[:80]!r}") from e
    return body

def _looks_like_json_bytes(b: bytes) -> bool:
    b = b.lstrip()
    return b.startswith(b"{") or b.startswith(b"[")

def _unwrap_bytearray_repr(body: bytes) -> Optional[bytes]:
    if not body.startswith(b"bytearray("):
        return None
    from ast import literal_eval
    try:
        obj = literal_eval(body.decode("utf-8", "replace"))
        if isinstance(obj, (bytearray, bytes)):
            return bytes(obj)
    except Exception:
        pass
    return None

@dataclass
class TLSClient:
    client_identifier: Optional[str] = None
    random_tls_extension_order: bool = True
    force_http1: bool = False
    catch_panics: bool = False
    debug: bool = False
    proxy: Optional[Union[str, BaseProxy]] = None
    cookies: Optional[RequestsCookieJar] = None
    certificate_pinning: Optional[Dict[str, List[str]]] = None
    disable_ipv6: bool = False
    detect_encoding: bool = True  # only disable if you are confident the encoding is utf-8

    # custom TLS profile
    ja3_string: Optional[str] = None
    h2_settings: Optional[Dict[str, int]] = None
    h2_settings_order: Optional[List[str]] = None
    supported_signature_algorithms: Optional[List[str]] = None
    supported_delegated_credentials_algorithms: Optional[List[str]] = None
    supported_versions: Optional[List[str]] = None
    key_share_curves: Optional[List[str]] = None
    cert_compression_algo: Optional[str] = None
    additional_decode: Optional[str] = None
    pseudo_header_order: Optional[List[str]] = None
    connection_flow: Optional[int] = None
    priority_frames: Optional[list] = None
    header_order: Optional[List[str]] = None
    header_priority: Optional[List[str]] = None

    '''
    Synopsis:
    
    self.client_identifier examples:
    - Chrome > chrome_120 + other versions
    - Firefox > firefox_117 + other versions
    - see here for others: https://bogdanfinn.gitbook.io/open-source-oasis/tls-client/supported-and-tested-client-profiles

    self.ja3_string example:
    - 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0

    HTTP2 Header Frame Settings
    - HEADER_TABLE_SIZE
    - SETTINGS_ENABLE_PUSH
    - MAX_CONCURRENT_STREAMS
    - INITIAL_WINDOW_SIZE
    - MAX_FRAME_SIZE
    - MAX_HEADER_LIST_SIZE

    self.h2_settings example:
    {
        "HEADER_TABLE_SIZE": 65536,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_HEADER_LIST_SIZE": 262144
    }

    HTTP2 Header Frame Settings Order
    self.h2_settings_order example:
    [
        "HEADER_TABLE_SIZE",
        "MAX_CONCURRENT_STREAMS",
        "INITIAL_WINDOW_SIZE",
        "MAX_HEADER_LIST_SIZE"
    ]

    Supported Signature Algorithms
    - PKCS1WithSHA256
    - PKCS1WithSHA384
    - PKCS1WithSHA512
    - PSSWithSHA256
    - PSSWithSHA384
    - PSSWithSHA512
    - ECDSAWithP256AndSHA256
    - ECDSAWithP384AndSHA384
    - ECDSAWithP521AndSHA512
    - PKCS1WithSHA1
    - ECDSAWithSHA1

    self.supported_signature_algorithms example:
    [
        "ECDSAWithP256AndSHA256",
        "PSSWithSHA256",
        "PKCS1WithSHA256",
        "ECDSAWithP384AndSHA384",
        "PSSWithSHA384",
        "PKCS1WithSHA384",
        "PSSWithSHA512",
        "PKCS1WithSHA512",
    ]

    Supported Delegated Credentials Algorithms
    - PKCS1WithSHA256
    - PKCS1WithSHA384
    - PKCS1WithSHA512
    - PSSWithSHA256
    - PSSWithSHA384
    - PSSWithSHA512
    - ECDSAWithP256AndSHA256
    - ECDSAWithP384AndSHA384
    - ECDSAWithP521AndSHA512
    - PKCS1WithSHA1
    - ECDSAWithSHA1

    self.supported_delegated_credentials_algorithms example:
    [
        "ECDSAWithP256AndSHA256",
        "PSSWithSHA256",
        "PKCS1WithSHA256",
        "ECDSAWithP384AndSHA384",
        "PSSWithSHA384",
        "PKCS1WithSHA384",
        "PSSWithSHA512",
        "PKCS1WithSHA512",
    ]

    Supported Versions
    - GREASE
    - 1.3
    - 1.2
    - 1.1
    - 1.0

    self.supported_versions example:
    [
        "GREASE",
        "1.3",
        "1.2"
    ]

    Key Share Curves
    - GREASE
    - P256
    - P384
    - P521
    - X25519

    self.key_share_curves example:
    [
        "GREASE",
        "X25519"
    ]

    Cert Compression Algorithm
    self.cert_compression_algo examples: "zlib", "brotli", "zstd"

    Additional Decode
    Make sure the go code decodes the response body once explicit by provided algorithm.
    self.additional_decode examples: null, "gzip", "br", "deflate"

    Pseudo Header Order (:authority, :method, :path, :scheme)
    self.pseudo_header_order examples:
    [
        ":method",
        ":authority",
        ":scheme",
        ":path"
    ]

    Connection Flow / Window Size Increment
    self.connection_flow example:
    15663105

    self.priority_frames example:
    [
        {
        "streamID": 3,
        "priorityParam": {
            "weight": 201,
            "streamDep": 0,
            "exclusive": false
        }
        },
        {
        "streamID": 5,
        "priorityParam": {
            "weight": 101,
            "streamDep": false,
            "exclusive": 0
        }
        }
    ]

    Order of your headers
    self.header_order example:
    [
        "key1",
        "key2"
    ]

    Header Priority
    self.header_priority example:
    {
        "streamDep": 1,
        "exclusive": true,
        "weight": 1
    }
    
    Proxies
    self.proxy usage:
    - "http://user:pass@ip:port",
    - "http://user:pass@ip:port"
    '''

    def __post_init__(self) -> None:
        self.id: str = str(uuid.uuid4())

        # http client for local go server
        self.server: HTTPClient = HTTPClient(
            '127.0.0.1',
            library.PORT,
            ssl=False,
            insecure=True,
            connection_timeout=1e9,
            network_timeout=1e9,
        )
        # CookieJar containing all currently outstanding cookies set on this session
        self.headers: CaseInsensitiveDict = _SanitizedCID()
        self.cookies: RequestsCookieJar = self.cookies or RequestsCookieJar()
        self._closed: bool = False  # indicate if session is closed

    def close(self):
        if not self._closed:
            self._closed = True
            library.destroy_session(self.id)
            self.server.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()

    def build_request(
        self,
        method: str,
        url: str,
        headers: Optional[Union[dict, CaseInsensitiveDict]] = None,
        data: Optional[Union[str, bytes, bytearray, dict]] = None,
        cookies: Optional[Union[RequestsCookieJar, dict, list]] = None,
        json: Optional[Union[dict, list, str]] = None,
        allow_redirects: bool = False,
        history: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = None,
        proxy: Optional[Union[str, BaseProxy]] = None,
    ):
        # Prepare request body - build request body
        # Data has priority. JSON is only used if data is None.
        if data is None and json is not None:
            if type(json) in (dict, list):
                json = dumps(json).decode('utf-8')
            request_body = json
            content_type = 'application/json'
        elif data is not None and type(data) not in (str, bytes, bytearray):
            request_body = urlencode(data, doseq=True)
            content_type = 'application/x-www-form-urlencoded'
        else:
            request_body = data
            content_type = None
        # set content type if it isn't set
        if content_type is not None and 'content-type' not in self.headers:
            self.headers['Content-Type'] = content_type

        # Prepare Headers
        if self.headers is None:
            headers = CaseInsensitiveDict(headers)
        elif headers is None:
            headers = self.headers
        else:
            merged_headers = _SanitizedCID(self.headers)
            merged_headers.update(headers)   # значения приведутся к str
            none_keys = [k for (k, v) in merged_headers.items() if v is None or k is None]
            for key in none_keys:
                del merged_headers[key]
            headers = merged_headers

        # Cookies
        if isinstance(cookies, RequestsCookieJar):
            merge_cookies(self.cookies, cookies)
        elif isinstance(cookies, list):
            merge_cookies(self.cookies, list_to_cookiejar(cookies))
        elif isinstance(cookies, dict):
            self.cookies.set_cookie(cookiejar_from_dict(cookies))

        # turn cookie jar into dict

        # Proxy
        proxy = proxy or self.proxy
        if isinstance(proxy, BaseProxy):
            proxy = str(proxy)
        if proxy:
            verify_proxy(proxy)

        # Request
        is_byte_request = isinstance(request_body, (bytes, bytearray))
        request_payload = {
            'sessionId': self.id,
            'followRedirects': allow_redirects,
            'wantHistory': history,
            'forceHttp1': self.force_http1,
            'withDebug': self.debug,
            'catchPanics': self.catch_panics,
            'headers': dict(headers) if isinstance(headers, CaseInsensitiveDict) else headers,
            'headerOrder': self.header_order,
            'insecureSkipVerify': not verify if verify is not None else False,
            'isByteRequest': is_byte_request,
            'detectEncoding': self.detect_encoding,
            'additionalDecode': self.additional_decode,
            'proxyUrl': proxy,
            'requestUrl': url,
            'requestMethod': method,
            'requestBody': (
                base64.b64encode(request_body).decode()
                if is_byte_request and request_body is not None
                else request_body
            ),
            'requestCookies': cookiejar_to_list(self.cookies),
            'timeoutMilliseconds': int((timeout or 0) * 1000),
            'withoutCookieJar': False,
            'disableIPv6': self.disable_ipv6,
        }
        if self.certificate_pinning:
            request_payload['certificatePinning'] = self.certificate_pinning
        if self.client_identifier is None:
            request_payload['customTlsClient'] = {
                'ja3String': self.ja3_string,
                'h2Settings': self.h2_settings,
                'h2SettingsOrder': self.h2_settings_order,
                'pseudoHeaderOrder': self.pseudo_header_order,
                'connectionFlow': self.connection_flow,
                'priorityFrames': self.priority_frames,
                'headerPriority': self.header_priority,
                'certCompressionAlgo': self.cert_compression_algo,
                'supportedVersions': self.supported_versions,
                'supportedSignatureAlgorithms': self.supported_signature_algorithms,
                'supportedDelegatedCredentialsAlgorithms': self.supported_delegated_credentials_algorithms,
                'keyShareCurves': self.key_share_curves,
            }
        else:
            request_payload['tlsClientIdentifier'] = self.client_identifier
            request_payload['withRandomTLSExtensionOrder'] = self.random_tls_extension_order

        return request_payload, headers

    def build_response_obj(
        self,
        url: str,
        headers: Optional[Union[dict, CaseInsensitiveDict]],
        response_object: dict,
        proxy: str,
    ):
        if response_object['status'] == 0:
            raise ClientException(response_object['body'])
        # Set response cookies
        response_cookie_jar = extract_cookies_to_jar(
            request_url=url,
            request_headers=headers,
            cookie_jar=self.cookies,
            response_headers=response_object['headers'],
        )
        # build response class
        return hrequests.response.build_response(response_object, response_cookie_jar, proxy)

    def build_response(
        self,
        url,
        headers: Optional[Union[dict, CaseInsensitiveDict]],
        response_object: dict,
        proxy: str,
    ):  # sourcery skip: assign-if-exp
        history: list = []
        if not response_object['isHistory']:
            return self.build_response_obj(url, headers, response_object['response'], proxy)
        resps: list = response_object['history']
        for index, item in enumerate(resps):
            if index:  # > 0
                # get the location redirect url from the previous response
                item_url = resps[index - 1]['headers']['Location'][0]
            else:
                # use the original url
                item_url = url
            history.append(self.build_response_obj(item_url, headers, item, proxy))
        # assign history to last response
        resp = history[-1]
        resp.history = history[:-1]
        return resp

    def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Union[dict, CaseInsensitiveDict]] = None,
        *args,
        **kwargs,
    ):
        '''
        execute a single request and return a response object
        '''
        # build request payload
        request_payload, headers = self.build_request(method, url, headers, *args, **kwargs)

        # приводим headers в payload к простому dict[str,str]
        safe_headers = {}
        for k, v in (request_payload.get('headers') or {}).items():
            if v is None:
                continue
            safe_headers[str(k)] = str(v)
        request_payload['headers'] = safe_headers

        payload_bytes = dumps(request_payload)

        # ВАЖНО: используем geventhttpclient.header.Headers, чтобы избежать str/bytes-каши
        req_headers = Headers()
        req_headers.add('Content-Type', 'application/json')
        req_headers.add('Accept', 'application/json')

        resp = self.server.post(
            f'http://127.0.0.1:{library.PORT}/request',
            body=payload_bytes,
            headers=req_headers,
        )

        raw = resp.read()
        status = getattr(resp, "status_code", getattr(resp, "status", "NA"))
        resp_headers = _normalize_headers(getattr(resp, "headers", {}) or {})

        if not raw:
            raise ValueError("Empty response body from local proxy /request")

        body = _maybe_gunzip(raw, resp_headers)
        print(f"[local-proxy] status={status} prefix={body[:120]!r}")

        if not _looks_like_json_bytes(body):
            unwrapped = _unwrap_bytearray_repr(body)
            if unwrapped is not None:
                body = unwrapped

        if not _looks_like_json_bytes(body):
            ct = _get_header(resp_headers, "Content-Type") or ""
            if body.lstrip().startswith(b"<") or ("html" in ct.lower()):
                raise RuntimeError(
                    f"Local proxy returned HTML/error page (status={status}), not JSON. "
                    f"Content-Type={ct!r}, prefix={body[:120]!r}"
                )
            raise RuntimeError(
                f"Local proxy returned non-JSON payload (status={status}). "
                f"Content-Type={ct!r}, prefix={body[:120]!r}"
            )

        try:
            response_object = loads(body)
        except JSONDecodeError as e:
            raise JSONDecodeError(f"{e}: prefix={body[:160]!r}", e.doc, e.pos)

        return self.build_response(url, headers, response_object, request_payload['proxyUrl'])
