from http.server import BaseHTTPRequestHandler, HTTPServer
import datetime
LOG = "/logs/webhook.log"
class H(BaseHTTPRequestHandler):
    def _handle(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode(errors="replace")
            line = f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} POST {self.path} {body}"
            print(line, flush=True)
            with open(LOG, "a") as f:
                f.write(line + "\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        except Exception as ex:
            print("handler error:", ex, flush=True)
            self.send_response(500); self.end_headers()
    do_POST = _handle
    def log_message(self, *a):
        pass
print("webhook catcher listening on :9090", flush=True)
HTTPServer(("0.0.0.0", 9090), H).serve_forever()
