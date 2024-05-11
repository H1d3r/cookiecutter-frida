"""
Send http request, employed by burpTracer.py
"""

import requests
import json

# from mysm4 import sm4_decrypt_ecb
import time
from urllib.parse import quote
from datetime import datetime
import urllib3
from utils.aes import AESDecrypt
import binascii

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sendRequest(
    req_data: str, sign: str, key: str, salt: str, method: str, cookie: str = ""
):
    data = f""
    proxy = {"https": "127.0.0.1:8080", "http": "127.0.0.1:8080"}
    header = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent": "okhttp/3.12.12",
        "Connection": "close",
    }
    res = requests.post(
        "",
        data=data,
        headers=header,
        proxies=proxy,
        verify=False,
    )
    ret = json.loads(res.text)

    return ret
