from http.server import BaseHTTPRequestHandler, HTTPServer
import threading


class BaseLabHandler(BaseHTTPRequestHandler):
    server_version = "BakulaLab/1.0"

    def log_message(self, fmt, *args):
        return

    def _write(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


class MainSiteHandler(BaseLabHandler):
    def do_GET(self):
        self._write(
            200,
            """<!doctype html><html><head><title>Bakula Demo Web</title></head>
            <body><h1>Bakula Demo Web</h1><p>Řízená cílová aplikace pro HTTPX fingerprinting.</p></body></html>""",
        )


class BasicAuthHandler(BaseLabHandler):
    def do_GET(self):
        self._write(
            401,
            """<!doctype html><html><head><title>Admin Login</title></head>
            <body><h1>Admin Login</h1><p>Authentication required.</p></body></html>""",
            headers={"WWW-Authenticate": 'Basic realm="Admin"'},
        )


class MetricsHandler(BaseLabHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self._write(
                200,
                "# HELP bakula_requests_total Example metric\n# TYPE bakula_requests_total counter\nbakula_requests_total 42\n",
                content_type="text/plain; version=0.0.4",
            )
            return
        self._write(
            200,
            """<!doctype html><html><head><title>Metrics Service</title></head>
            <body><h1>Metrics</h1><p>Prometheus endpoint je na /metrics.</p></body></html>""",
        )


class SwaggerHandler(BaseLabHandler):
    def do_GET(self):
        if self.path in ("/swagger-ui/", "/swagger-ui/index.html"):
            self._write(
                200,
                """<!doctype html><html><head><title>Swagger UI</title></head>
                <body><h1>Swagger UI</h1><p>Interactive API documentation.</p></body></html>""",
            )
            return
        self._write(
            200,
            """<!doctype html><html><head><title>API Portal</title></head>
            <body><h1>API Portal</h1><p>Swagger UI je dostupné na /swagger-ui/.</p></body></html>""",
        )


class ListingHandler(BaseLabHandler):
    def do_GET(self):
        self._write(
            200,
            """<!doctype html><html><head><title>Directory listing for /</title></head>
            <body><h1>Directory listing for /</h1><ul><li>backup/</li><li>logs/</li></ul></body></html>""",
        )


def start_server(port, handler):
    server = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    servers = [
        start_server(18080, MainSiteHandler),
        start_server(18081, BasicAuthHandler),
        start_server(18082, MetricsHandler),
        start_server(18083, SwaggerHandler),
        start_server(18084, ListingHandler),
    ]
    print("Bakula web lab běží na:")
    print("  http://127.0.0.1:18080/")
    print("  http://127.0.0.1:18081/")
    print("  http://127.0.0.1:18082/metrics")
    print("  http://127.0.0.1:18083/swagger-ui/")
    print("  http://127.0.0.1:18084/")
    print("Ukončení: Ctrl+C")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
