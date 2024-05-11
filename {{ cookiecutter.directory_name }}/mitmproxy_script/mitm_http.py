"""
Handle http traffic
"""

import random
import time
from typing import Callable, Protocol
import mitmproxy
import mitmproxy.http
import mitmproxy.ctx as ctx
import json

# from utils.mysm4 import sm4_decrypt_ecb, sm4_encrypt_ecb
import clipboard

sqlFuzz = "'\"#()--"


def log(msg: str):
    ctx.log(msg, "warn")


class Interceptor:
    def __init__(self) -> None:
        pass

    def load(self, loader):
        ctx.options.console_eventlog_verbosity = "warn"

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if "Content-Type" not in flow.request.headers:
            flow.request.headers["Content-Type"] = "application/json"

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass


addons = [Interceptor()]
