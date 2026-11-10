"""Tiny, dependency-free DNS and HTTP sinkhole for the isolated lab network."""

from __future__ import annotations

import base64
import datetime as dt
import http.server
import json
import socket
import socketserver
import threading


SINKHOLE_IP = "172.29.41.2"


def log(event: dict[str, object]) -> None:
    event["time"] = dt.datetime.now(dt.timezone.utc).isoformat()
    print(json.dumps(event, sort_keys=True), flush=True)


class DNSHandler(socketserver.DatagramRequestHandler):
    def handle(self) -> None:
        request = self.packet
        if len(request) < 12:
            return
        question_end = 12
        labels = []
        try:
            while question_end < len(request):
                size = request[question_end]
                question_end += 1
                if size == 0:
                    break
                if size > 63 or question_end + size > len(request):
                    return
                labels.append(request[question_end:question_end + size].decode("ascii", "replace"))
                question_end += size
            if question_end + 4 > len(request):
                return
            qtype = int.from_bytes(request[question_end:question_end + 2], "big")
            question_end += 4
            qname = ".".join(labels)
            answer = b""
            count = 0
            if qtype == 1:
                address = socket.inet_aton(SINKHOLE_IP)
                answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x04" + address
                count = 1
            response_flags = 0x8180
            header = request[:2] + response_flags.to_bytes(2, "big") + b"\x00\x01" + count.to_bytes(2, "big") + b"\x00\x00\x00\x00"
            self.wfile.write(header + request[12:question_end] + answer)
            log({"kind": "dns", "client": self.client_address[0], "query": qname, "qtype": qtype, "answer": SINKHOLE_IP if count else None})
        except (IndexError, ValueError, OSError):
            return


class DNSUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FirmSightSinkhole/1.0"

    def _handle(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0") or 0), 65536)
        body = self.rfile.read(length) if length else b""
        log({"kind": "http", "client": self.client_address[0], "method": self.command,
             "host": self.headers.get("Host"), "path": self.path,
             "headers": dict(self.headers.items()),
             "body_base64": base64.b64encode(body).decode("ascii") if body else ""})
        response = b"FirmSight isolated sinkhole\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_PATCH = _handle

    def log_message(self, _format: str, *_args: object) -> None:
        return


class TLSAttemptHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(4096)
        log({"kind": "tls_attempt", "client": self.client_address[0],
             "server_name_and_client_hello_base64": base64.b64encode(data).decode("ascii")})


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    dns = DNSUDPServer(("0.0.0.0", 53), DNSHandler)
    tls = ThreadedTCPServer(("0.0.0.0", 443), TLSAttemptHandler)
    threading.Thread(target=dns.serve_forever, daemon=True).start()
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", 80), HTTPHandler).serve_forever()


if __name__ == "__main__":
    main()
