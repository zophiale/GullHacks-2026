"""Generate benign and attack-shaped HTTP traffic for the local victim server."""

from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class TrafficRequest:
    """A request template used by the traffic generator."""

    name: str
    path: str
    params: dict[str, str]
    malicious: bool

    def url(self, target: str) -> str:
        """Build a URL while preserving any path configured on the target."""
        base = target.rstrip("/") + "/"
        request_url = urljoin(base, self.path.lstrip("/"))
        parts = urlsplit(request_url)
        query = urlencode(self.params)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


BENIGN_REQUESTS = (
    TrafficRequest("home", "/", {"page": "home"}, False),
    TrafficRequest("health", "/health", {"verbose": "false"}, False),
    TrafficRequest("search", "/search", {"q": "network monitoring"}, False),
    TrafficRequest("status", "/api/status", {"format": "json"}, False),
)

MALICIOUS_REQUESTS = (
    TrafficRequest("sql-injection", "/search", {"q": "' OR '1'='1' --"}, True),
    TrafficRequest("command-injection", "/api/status", {"host": "127.0.0.1; id"}, True),
    TrafficRequest("path-traversal", "/download", {"file": "../../etc/passwd"}, True),
    TrafficRequest("xss-probe", "/search", {"q": "<script>alert(1)</script>"}, True),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send a configurable mix of benign and attack-shaped HTTP requests."
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:5000",
        help="victim base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="number of requests to send (default: %(default)s)",
    )
    parser.add_argument(
        "--malicious-ratio",
        type=float,
        default=0.5,
        help="fraction of requests selected from malicious templates (default: %(default)s)",
    )
    parser.add_argument("--interval", type=float, default=0.0, help="seconds between requests")
    parser.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    parser.add_argument("--seed", type=int, help="seed for reproducible template selection")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the generated requests without sending them",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.count < 0:
        raise ValueError("--count must be non-negative")
    if not 0 <= args.malicious_ratio <= 1:
        raise ValueError("--malicious-ratio must be between 0 and 1")
    if args.interval < 0:
        raise ValueError("--interval must be non-negative")
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than zero")
    parsed_target = urlsplit(args.target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
        raise ValueError("--target must be an absolute http:// or https:// URL")


def generate_requests(
    count: int,
    malicious_ratio: float,
    rng: random.Random,
) -> Iterable[TrafficRequest]:
    """Yield templates according to the requested mix."""
    for _ in range(count):
        if rng.random() < malicious_ratio:
            yield rng.choice(MALICIOUS_REQUESTS)
        else:
            yield rng.choice(BENIGN_REQUESTS)


def send_request(request_url: str, timeout: float) -> tuple[int, str]:
    """Send one request and return its status and response body."""
    request = Request(request_url, method="GET", headers={"User-Agent": "GullHacks-attacker/1.0"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(256).decode("utf-8", errors="replace")
        return response.status, body


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    rng = random.Random(args.seed)
    sent = 0
    failed = 0

    for traffic_request in generate_requests(args.count, args.malicious_ratio, rng):
        request_url = traffic_request.url(args.target)
        label = "malicious" if traffic_request.malicious else "benign"
        if args.dry_run:
            print(json.dumps({"label": label, "name": traffic_request.name, "url": request_url}))
        else:
            try:
                status, _ = send_request(request_url, args.timeout)
                print(json.dumps({"label": label, "name": traffic_request.name, "status": status}))
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                failed += 1
                print(
                    json.dumps(
                        {
                            "label": label,
                            "name": traffic_request.name,
                            "url": request_url,
                            "error": str(exc),
                        }
                    )
                )
        sent += 1
        if args.interval and sent < args.count:
            time.sleep(args.interval)

    print(json.dumps({"sent": sent, "failed": failed, "dry_run": args.dry_run}))
    return 1 if failed else 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())