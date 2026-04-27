#!/usr/bin/env python3

"""Enumerate web applications and resources using HTTP fingerprints."""

from __future__ import annotations

import argparse
import ipaddress
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from textwrap import dedent
from typing import Any
from urllib.parse import urlparse

import pycurl
import yaml


BASE_DIR = Path(__file__).resolve().parent
FINGERPRINTS = BASE_DIR / "wordlists/web/http_fingerprints.yml"
USER_AGENTS = BASE_DIR / "wordlists/web/user_agents.txt"
HTTP_404_SIGS = BASE_DIR / "wordlists/web/404_signatures.txt"
IGNORE_SERVERS = BASE_DIR / "wordlists/web/ignore_servers.txt"
HOST = None
MAX_CONCURRENCY = 50
MAX_TIMEOUTS = 10
MAX_ERRORS = 10
STATUS_CODES = {200, 401}
CONNECT_TIMEOUT = 15
REQUEST_TIMEOUT = 20

_PRINT_LOCK = threading.Lock()
USER_AGENT_POOL: list[str] = []

HELP_DESCRIPTION = dedent(
        """\
        Enumerate web applications and resources using HTTP fingerprints.

        Input targets must be full URLs, one per line, for example:
            http://example.test
            https://10.10.10.20:8443

        For each target, the tool first performs a single precheck request to identify a
        target-specific not-found condition. Targets that cannot produce a usable not-found
        code or body signature are omitted from the scan.
        """
)

HELP_EPILOG = dedent(
        """\
        Supporting files:
            --fingerprints     YAML list of fingerprints. Each fingerprint contains probes and matches.
            --ignore-servers   One rule per line. Blank lines and lines starting with # are ignored.
                                                 Literal rules are case-insensitive substring matches.
                                                 Regex rules must start with regex: and are also case-insensitive.
                                                 The rules are checked against the Server and Via headers during precheck.
            --user-agents      One User-Agent value per line. At least one entry is required.
            --http-404-sigs    One response-body string per line for identifying soft-404 pages.

        Output:
            Matching checks are written to stdout as CSV lines in this form:
                matched_output,url,method,status_code,vhost

        Execution modes:
            target-first       Schedule all fingerprints for one prepared target, then the next target.
            fingerprint-first  Schedule one fingerprint across all prepared targets, then the next.

        Delay behavior:
            --delay 0          No scheduling barrier; groups are submitted in order and may overlap.
            --delay > 0        Wait for the current scheduling group to finish, sleep, then submit the
                                                 next group. A group is one target in target-first mode or one fingerprint
                                                 in fingerprint-first mode.

        Proxy support:
            --proxy accepts libcurl-compatible proxy URLs such as:
                http://127.0.0.1:8080
                socks5h://127.0.0.1:1080
            --proxy-credentials must be username:password and requires --proxy.

        Examples:
            web_enum.py -i targets.txt
            web_enum.py -i targets.txt --execution-mode fingerprint-first
            web_enum.py -i targets.txt --execution-mode target-first --delay 2
            web_enum.py -i targets.txt --proxy http://127.0.0.1:8080
            web_enum.py -i targets.txt --proxy http://127.0.0.1:8080 --proxy-credentials alice:secret
            web_enum.py -i targets.txt -f wordlists/web/pyweb_enum_validation.yml
        """
)


class HelpFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter,
):
        """Help formatter that preserves layout and shows defaults."""

LUA_PATTERN_MAP = {
    "a": r"[A-Za-z]",
    "A": r"[^A-Za-z]",
    "c": r"[\x00-\x1f\x7f]",
    "C": r"[^\x00-\x1f\x7f]",
    "d": r"\d",
    "D": r"\D",
    "g": r"[^\s\x00-\x1f\x7f]",
    "G": r"[\s\x00-\x1f\x7f]",
    "l": r"[a-z]",
    "L": r"[^a-z]",
    "p": r"[!\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]",
    "P": r"[^!\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]",
    "s": r"\s",
    "S": r"\S",
    "u": r"[A-Z]",
    "U": r"[^A-Z]",
    "w": r"[A-Za-z0-9]",
    "W": r"[^A-Za-z0-9]",
    "x": r"[A-Fa-f0-9]",
    "X": r"[^A-Fa-f0-9]",
    "z": r"\x00",
    "Z": r"[^\x00]",
}

LUA_CLASS_MAP = {
    "a": "A-Za-z",
    "c": r"\x00-\x1f\x7f",
    "d": r"\d",
    "l": "a-z",
    "p": r"!\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~",
    "s": r"\s",
    "u": "A-Z",
    "w": "A-Za-z0-9",
    "x": "A-Fa-f0-9",
    "z": r"\x00",
}


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response container for fingerprint matching.

    Attributes:
        status_code: HTTP status code returned by the server.
        headers: Raw response headers as a text string.
        body: Raw response body decoded as latin-1.
        timed_out: Whether the request hit the configured timeout.
        errored: Whether libcurl failed before an HTTP response was received.
    """

    status_code: int
    headers: str
    body: str
    timed_out: bool = False
    errored: bool = False


@dataclass(frozen=True)
class ProxyConfig:
    """Proxy settings applied to all outgoing requests."""

    server: str
    credentials: str | None = None


@dataclass(frozen=True)
class TargetCheckContext:
    """Prepared target state reused across fingerprint checks."""

    target: str
    ecode: int | None
    emesg: str | None


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=HelpFormatter,
    )
    required_group = parser.add_argument_group("Required input")
    files_group = parser.add_argument_group("Supporting files")
    network_group = parser.add_argument_group("Networking")
    execution_group = parser.add_argument_group("Execution")
    output_group = parser.add_argument_group("Output")

    required_group.add_argument(
        "-i",
        "--input",
        required=True,
        help="File containing one full target URL per line",
    )
    files_group.add_argument(
        "-f",
        "--fingerprints",
        default=str(FINGERPRINTS),
        help="Fingerprint YAML file to use",
    )
    files_group.add_argument(
        "--ignore-servers",
        default=str(IGNORE_SERVERS),
        help="Ignore rules file for Server/Via header filtering",
    )
    files_group.add_argument(
        "--user-agents",
        default=str(USER_AGENTS),
        help="User-Agent values file",
    )
    files_group.add_argument(
        "--http-404-sigs",
        default=str(HTTP_404_SIGS),
        help="Soft-404 signature strings file",
    )
    network_group.add_argument(
        "--proxy",
        help="Proxy server to use for requests, for example http://127.0.0.1:8080",
    )
    network_group.add_argument(
        "--proxy-credentials",
        help="Optional proxy credentials in the form username:password",
    )
    execution_group.add_argument(
        "--execution-mode",
        choices=("target-first", "fingerprint-first"),
        default="target-first",
        help="Submit checks in target-first or fingerprint-first order",
    )
    execution_group.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between each target or fingerprint scheduling group",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr",
    )
    return parser.parse_args()


def read_lines(path: Path) -> list[str]:
    """Read newline-delimited values from a file."""
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def require_non_empty_lines(path: Path, description: str) -> list[str]:
    """Read a newline-delimited file and require at least one usable entry."""
    values = read_lines(path)
    if not values:
        raise ValueError(f"{description} file {path} does not contain any usable entries")
    return values


def read_ignore_rules(path: Path) -> list[str]:
    """Read ignore rules, skipping blank lines and comments."""
    rules: list[str] = []
    for line in path.read_text().splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        rules.append(rule)
    return rules


def log(message: str, *, error: bool = False) -> None:
    """Write a single synchronized log line."""
    stream = sys.stderr if error else sys.stdout
    with _PRINT_LOCK:
        stream.write(f"{message}\n")
        stream.flush()


def extract_header_values(headers: str, header_name: str) -> list[str]:
    """Extract values for a named HTTP header from raw response headers."""
    values: list[str] = []
    needle = header_name.lower()
    for line in headers.splitlines():
        name, separator, value = line.partition(":")
        if not separator:
            continue
        if name.strip().lower() == needle:
            values.append(value.strip())
    return values


def is_regex_ignore_rule(rule: str) -> bool:
    """Return whether an ignore rule should be treated as regex."""
    return rule.lower().startswith("regex:")


def regex_ignore_pattern(rule: str) -> str:
    """Extract the regex pattern from an ignore rule."""
    return rule.split(":", 1)[1]


@lru_cache(maxsize=256)
def compile_ignore_regex(pattern: str) -> re.Pattern[str]:
    """Compile a case-insensitive ignore regex."""
    return re.compile(pattern, re.IGNORECASE)


def validate_ignore_rules(ignore_rules: list[str]) -> None:
    """Fail fast on invalid ignore rules."""
    for rule in ignore_rules:
        if is_regex_ignore_rule(rule):
            compile_ignore_regex(regex_ignore_pattern(rule))


def match_ignored_header(
    headers: str,
    ignore_rules: list[str],
    header_names: tuple[str, ...] = ("Server", "Via"),
) -> tuple[str | None, str | None, str | None]:
    """Return the matching header name, value, and rule when a target should be skipped."""
    if not ignore_rules:
        return None, None, None

    for header_name in header_names:
        for header_value in extract_header_values(headers, header_name):
            for rule in ignore_rules:
                if is_regex_ignore_rule(rule):
                    if compile_ignore_regex(regex_ignore_pattern(rule)).search(header_value):
                        return header_name, header_value, rule
                    continue

                if rule.lower() in header_value.lower():
                    return header_name, header_value, rule

    return None, None, None


def default_port(parsed_url: Any) -> int:
    """Return the effective port for a parsed URL."""
    if parsed_url.port is not None:
        return parsed_url.port
    return 443 if parsed_url.scheme == "https" else 80


def resolve_target(target: str, hostname: str | None) -> tuple[str, int, str]:
    """Resolve the virtual host, port, and upstream address for a target."""
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Invalid target URL: {target}")
    return hostname or parsed.hostname, default_port(parsed), parsed.hostname


def build_resolve_entry(vhost: str, port: int, upstream_host: str) -> str | None:
    """Return a libcurl RESOLVE entry only when it points a vhost at a literal IP."""
    if vhost == upstream_host:
        return None

    try:
        ipaddress.ip_address(upstream_host)
    except ValueError:
        return None

    return f"{vhost}:{port}:{upstream_host}"


def parse_proxy_config(args: argparse.Namespace) -> ProxyConfig | None:
    """Build proxy configuration from CLI arguments."""
    if args.proxy_credentials and not args.proxy:
        raise ValueError("--proxy-credentials requires --proxy")

    if not args.proxy:
        return None

    return ProxyConfig(server=args.proxy, credentials=args.proxy_credentials)


def make_request(
    url: str,
    method: str,
    user_agent: str,
    resolve_entry: str | None,
    proxy_config: ProxyConfig | None = None,
) -> HttpResponse:
    """Perform a single HTTP request using libcurl with optional host pinning."""
    curl = pycurl.Curl()
    headers_buffer = BytesIO()
    body_buffer = BytesIO()

    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.USERAGENT, user_agent)
    curl.setopt(pycurl.NOSIGNAL, 1)
    curl.setopt(pycurl.FOLLOWLOCATION, 0)
    curl.setopt(pycurl.CONNECTTIMEOUT, CONNECT_TIMEOUT)
    curl.setopt(pycurl.TIMEOUT, REQUEST_TIMEOUT)
    curl.setopt(pycurl.SSL_VERIFYHOST, 0)
    curl.setopt(pycurl.SSL_VERIFYPEER, 0)
    curl.setopt(pycurl.HEADERFUNCTION, headers_buffer.write)
    curl.setopt(pycurl.WRITEFUNCTION, body_buffer.write)

    if resolve_entry:
        curl.setopt(pycurl.RESOLVE, [resolve_entry])
    if proxy_config:
        curl.setopt(pycurl.PROXY, proxy_config.server)
        if proxy_config.credentials:
            curl.setopt(pycurl.PROXYUSERPWD, proxy_config.credentials)
            curl.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_ANY)

    normalized_method = method.upper()
    if normalized_method == "GET":
        curl.setopt(pycurl.HTTPGET, 1)
    elif normalized_method == "HEAD":
        curl.setopt(pycurl.NOBODY, 1)
        curl.setopt(pycurl.CUSTOMREQUEST, "HEAD")
    else:
        curl.setopt(pycurl.CUSTOMREQUEST, normalized_method)

    try:
        curl.perform()
        status_code = int(curl.getinfo(pycurl.RESPONSE_CODE))
        return HttpResponse(
            status_code=status_code,
            headers=headers_buffer.getvalue().decode("latin-1", errors="replace"),
            body=body_buffer.getvalue().decode("latin-1", errors="replace"),
        )
    except pycurl.error as exc:
        error_code = exc.args[0] if exc.args else None
        timed_out = error_code == pycurl.E_OPERATION_TIMEDOUT
        return HttpResponse(status_code=0, headers="", body="", timed_out=timed_out, errored=True)
    finally:
        curl.close()


def detect_page_not_found(
    target: str,
    hostname: str | None,
    signatures: list[str],
    ignore_rules: list[str],
    proxy_config: ProxyConfig | None,
    verbose: bool,
) -> tuple[int | None, str | None, bool]:
    """Determine a not-found status code or custom body signature for a target."""
    vhost, port, upstream_host = resolve_target(target, hostname)
    resolve_entry = build_resolve_entry(vhost, port, upstream_host)
    random_string = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    url = f"{target.rstrip('/')}/{random_string}.html"
    response = make_request(
        url,
        "GET",
        random.choice(USER_AGENT_POOL),
        resolve_entry,
        proxy_config,
    )

    matched_header, matched_value, matched_rule = match_ignored_header(
        response.headers,
        ignore_rules,
    )
    if matched_header and matched_value and matched_rule:
        log(
            (
                f"[INFO] Ignoring {target} because {matched_header} header '{matched_value}' "
                f"matched rule '{matched_rule}'"
            ),
            error=True,
        )
        return None, None, True

    if response.timed_out or response.status_code == 0:
        return None, None, False

    if 200 <= response.status_code <= 299:
        for signature in signatures:
            if signature and signature in response.body:
                if verbose:
                    log(f"[INFO] Using custom 404 string of '{signature}' for {target}", error=True)
                return None, signature, False
        return None, None, False

    if verbose:
        log(f"[INFO] Using code '{response.status_code}' as not found for {target}", error=True)
    return response.status_code, None, False


def consume_character_class(pattern: str, start_index: int) -> tuple[str, int]:
    """Consume a Lua character class and return its raw content and end index."""
    index = start_index
    content: list[str] = []
    while index < len(pattern):
        character = pattern[index]
        if character == "]" and (index == start_index or pattern[index - 1] != "%"):
            return "".join(content), index
        content.append(character)
        index += 1
    return "".join(content), len(pattern)


def translate_character_class(content: str) -> str:
    """Translate Lua character class syntax into Python regex character classes."""
    pieces: list[str] = []
    index = 0

    if content.startswith("^"):
        pieces.append("^")
        index = 1

    while index < len(content):
        character = content[index]
        if character == "\\" and index + 1 < len(content):
            pieces.append(f"\\{content[index + 1]}")
            index += 2
            continue
        if character == "%" and index + 1 < len(content):
            token = content[index + 1]
            pieces.append(LUA_CLASS_MAP.get(token, re.escape(token)))
            index += 2
            continue
        if character in {"\\", "]"}:
            pieces.append(f"\\{character}")
        else:
            pieces.append(character)
        index += 1

    return "".join(pieces)


def translate_lua_pattern(pattern: str) -> str:
    """Translate the subset of Lua patterns used by the fingerprints into regex."""
    pieces: list[str] = []
    index = 0
    repeatable = False

    while index < len(pattern):
        character = pattern[index]

        if character == "\\" and index + 1 < len(pattern):
            pieces.append(f"\\{pattern[index + 1]}")
            repeatable = True
            index += 2
            continue

        if character == "%" and index + 1 < len(pattern):
            token = pattern[index + 1]
            if token == "f" and index + 2 < len(pattern) and pattern[index + 2] == "[":
                raw_class, end_index = consume_character_class(pattern, index + 3)
                translated = translate_character_class(raw_class)
                pieces.append(f"(?<![{translated}])(?=[{translated}])")
                repeatable = False
                index = end_index + 1
                continue
            if token == "b" and index + 3 < len(pattern):
                open_char = re.escape(pattern[index + 2])
                close_char = re.escape(pattern[index + 3])
                pieces.append(f"{open_char}[^{open_char}{close_char}]*{close_char}")
                repeatable = True
                index += 4
                continue
            if token.isdigit():
                pieces.append(f"\\{token}")
            else:
                pieces.append(LUA_PATTERN_MAP.get(token, re.escape(token)))
            repeatable = True
            index += 2
            continue

        if character == "[":
            raw_class, end_index = consume_character_class(pattern, index + 1)
            if end_index < len(pattern):
                translated = translate_character_class(raw_class)
                pieces.append(f"[{translated}]")
                repeatable = True
                index = end_index + 1
                continue

        if character == "-":
            if repeatable:
                pieces.append("*?")
                repeatable = False
            else:
                pieces.append("-")
                repeatable = True
        elif character in {"*", "+", "?"}:
            if repeatable:
                pieces.append(character)
                repeatable = False
            else:
                pieces.append(re.escape(character))
                repeatable = True
        elif character == ".":
            pieces.append(character)
            repeatable = True
        elif character == "(":
            pieces.append(character)
            repeatable = False
        elif character == ")":
            pieces.append(character)
            repeatable = True
        elif character in {"^", "$"}:
            pieces.append(character)
            repeatable = False
        else:
            pieces.append(re.escape(character))
            repeatable = True

        index += 1

    return "".join(pieces)


@lru_cache(maxsize=8192)
def compile_pattern(pattern: str, case_sensitive: bool = False) -> re.Pattern[str]:
    """Compile a Lua pattern into a Python regex object."""
    flags = re.DOTALL
    if not case_sensitive:
        flags |= re.IGNORECASE
    return re.compile(translate_lua_pattern(pattern), flags)


def response_contains(
    response: HttpResponse,
    pattern: str | None,
    case_sensitive: bool = False,
) -> tuple[bool, tuple[str, ...]]:
    """Search the response headers and body for a Lua pattern."""
    if not pattern:
        return True, ()

    regex = compile_pattern(pattern, case_sensitive)
    for haystack in (response.headers, response.body):
        match = regex.search(haystack)
        if match:
            captures = tuple(capture or "" for capture in match.groups())
            return True, captures

    return False, ()


def apply_captures(output: str, captures: tuple[str, ...]) -> str:
    """Replace capture placeholders like \1 with captured values."""
    rendered = output
    for index, capture in enumerate(captures, start=1):
        rendered = rendered.replace(f"\\{index}", capture)
    return rendered


def probe_url(target: str, probe: Any) -> tuple[str, str]:
    """Build the full URL and method for a fingerprint probe."""
    if isinstance(probe, str):
        return f"{target.rstrip('/')}{probe}", "GET"
    path = probe.get("path", "")
    method = probe.get("method", "GET")
    return f"{target.rstrip('/')}{path}", method


def check(
    target: str,
    hostname: str | None,
    fingerprint: dict[str, Any],
    ecode: int | None,
    emesg: str | None,
    proxy_config: ProxyConfig | None,
    verbose: bool,
) -> None:
    """Run all probes for a single fingerprint against one target."""
    vhost, port, upstream_host = resolve_target(target, hostname)
    resolve_entry = build_resolve_entry(vhost, port, upstream_host)
    user_agent = random.choice(USER_AGENT_POOL)
    timeout_count = 0
    error_count = 0

    for probe in fingerprint.get("probes", []):
        url, method = probe_url(target, probe)
        response = make_request(url, method, user_agent, resolve_entry, proxy_config)

        if response.timed_out:
            timeout_count += 1
            if timeout_count < MAX_TIMEOUTS:
                if verbose:
                    log(f"[TIMEOUT] {url}", error=True)
                continue
            if verbose:
                log("[TIMEOUT] Too many timeouts encountered, aborting fingerprint.", error=True)
            return

        if response.errored or response.status_code == 0:
            error_count += 1
            if error_count < MAX_ERRORS:
                if verbose:
                    log(f"[ERROR] {url}", error=True)
                continue
            if verbose:
                log("[ERROR] Too many errors encountered, aborting fingerprint.", error=True)
            return

        if response.status_code not in STATUS_CODES:
            continue
        if response.status_code == ecode:
            continue
        if emesg and emesg in response.body:
            continue

        for match in fingerprint.get("matches", []):
            success, captures = response_contains(response, match.get("match"))
            output = apply_captures(match["output"], captures) if success else None

            dontmatch = match.get("dontmatch")
            if output and dontmatch:
                matched, _ = response_contains(response, dontmatch)
                if matched:
                    output = None

            if output:
                rendered = output.replace(",", "")
                log(f"{rendered},{url},{method},{response.status_code},{vhost}")
                break


def prepare_targets(
    targets: list[str],
    signatures: list[str],
    ignore_rules: list[str],
    proxy_config: ProxyConfig | None,
    verbose: bool,
) -> list[TargetCheckContext]:
    """Run prechecks and return prepared target state for later scheduling."""
    target_contexts: list[TargetCheckContext] = []

    for target in targets:
        try:
            ecode, emesg, ignored = detect_page_not_found(
                target,
                HOST,
                signatures,
                ignore_rules,
                proxy_config,
                verbose,
            )
        except ValueError as exc:
            log(f"[ERROR] {exc}", error=True)
            continue

        if ignored:
            continue

        if ecode is None and emesg is None:
            log(
                f"[ERROR] 'Page Not Found' identifier could not be found, omitting {target}",
                error=True,
            )
            continue

        target_contexts.append(TargetCheckContext(target=target, ecode=ecode, emesg=emesg))

    return target_contexts


def validate_delay(delay_seconds: float) -> None:
    """Fail fast on invalid scheduling delay values."""
    if delay_seconds < 0:
        raise ValueError("--delay must be greater than or equal to 0")


def execute_check_groups(
    executor: ThreadPoolExecutor,
    check_groups: list[list[tuple[TargetCheckContext, dict[str, Any]]]],
    proxy_config: ProxyConfig | None,
    delay_seconds: float,
    verbose: bool,
) -> None:
    """Submit grouped checks in order and wait for overall completion."""
    futures: list[Future[None]] = []

    for index, check_group in enumerate(check_groups):
        group_futures = [
            executor.submit(
                check,
                target_context.target,
                HOST,
                fingerprint,
                target_context.ecode,
                target_context.emesg,
                proxy_config,
                verbose,
            )
            for target_context, fingerprint in check_group
        ]

        if delay_seconds > 0:
            for future in as_completed(group_futures):
                future.result()

            if index < len(check_groups) - 1:
                time.sleep(delay_seconds)
            continue

        futures.extend(group_futures)

    if futures:
        for future in as_completed(futures):
            future.result()


def build_check_groups(
    target_contexts: list[TargetCheckContext],
    fingerprints: list[dict[str, Any]],
    execution_mode: str,
) -> list[list[tuple[TargetCheckContext, dict[str, Any]]]]:
    """Build the ordered scheduling groups for the selected execution mode."""
    if execution_mode == "target-first":
        return [
            [
                (target_context, fingerprint)
                for fingerprint in fingerprints
            ]
            for target_context in target_contexts
        ]

    return [
        [
            (target_context, fingerprint)
            for target_context in target_contexts
        ]
        for fingerprint in fingerprints
    ]


def main() -> int:
    """Run the fingerprint enumeration workflow."""
    global USER_AGENT_POOL

    args = parse_args()
    input_path = Path(args.input)
    fingerprint_path = Path(args.fingerprints)
    ignore_path = Path(args.ignore_servers)
    user_agents_path = Path(args.user_agents)
    http_404_sigs_path = Path(args.http_404_sigs)

    if not input_path.exists():
        sys.stderr.write(f"{input_path} does not exist!\n")
        return 1
    if not fingerprint_path.exists():
        sys.stderr.write(f"{fingerprint_path} does not exist!\n")
        return 1
    if not ignore_path.exists():
        sys.stderr.write(f"{ignore_path} does not exist!\n")
        return 1
    if not user_agents_path.exists():
        sys.stderr.write(f"{user_agents_path} does not exist!\n")
        return 1
    if not http_404_sigs_path.exists():
        sys.stderr.write(f"{http_404_sigs_path} does not exist!\n")
        return 1

    targets = read_lines(input_path)
    try:
        USER_AGENT_POOL = require_non_empty_lines(user_agents_path, "User agents")
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    try:
        proxy_config = parse_proxy_config(args)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    try:
        validate_delay(args.delay)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    signatures = read_lines(http_404_sigs_path)
    ignore_rules = read_ignore_rules(ignore_path)
    validate_ignore_rules(ignore_rules)
    with fingerprint_path.open("r", encoding="utf-8") as handle:
        fingerprints = yaml.safe_load(handle) or []

    target_contexts = prepare_targets(
        targets,
        signatures,
        ignore_rules,
        proxy_config,
        args.verbose,
    )
    check_groups = build_check_groups(
        target_contexts,
        fingerprints,
        args.execution_mode,
    )

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as executor:
        execute_check_groups(
            executor,
            check_groups,
            proxy_config,
            args.delay,
            args.verbose,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())