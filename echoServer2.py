"""A simple http server that prints out all received requests"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import binascii
import requests


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Disable default log behavior

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello, GET request received\n")

    def do_POST(self):
        print(f"{self.command} {self.path} {self.protocol_version}")
        print(self.headers)

        content_length = int(self.headers["content-length"])
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
        try:
            print(body.decode("utf-8"))  # Print the whole HTTP request to the console
        except UnicodeDecodeError:
            print(binascii.hexlify(body).decode("utf8"))


def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print("Echo server is running on port", port)
    httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        run(port=int(sys.argv[1]))
    else:
        run()
