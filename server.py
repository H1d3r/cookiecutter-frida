"""A http server that handle request encryption using Frida RPC"""

import sys
import time
from flask import Flask, request, jsonify
import flask
import frida
import json
from client import frida_process_message, logger

app = Flask(__name__)

rpc_request = None


@app.route("/request", methods=["FRIDA"])
def send_request():
    if request.method == "FRIDA":
        data = request.get_data()
        path = request.headers.get("Operation-Type")
        print(f"{path}: {data}")
        res = rpc_request(path, data.decode("utf8"))
        res = str(json.loads(res))
        print(res)
        response = flask.Response(res, 200, content_type="application/json")
        response.data = res
        return response
    else:
        flask.abort(405)


def inject_and_run(script_name):
    process_name = "金银钱包"
    device = frida.get_remote_device()
    device = frida.get_device_manager().add_remote_device("192.168.43.230:3333")
    process = device.attach(process_name)

    with open(script_name, encoding="utf-8", errors="ignore") as f:
        script = process.create_script(f.read())
    script.on("message", frida_process_message)
    script.load()
    logger.info("Load Script")

    logger.info(script.list_exports_sync())
    run(script)


def run(script):
    global rpc_request
    rpc_request = script.exports_sync.request
    getCtx = script.exports_sync.getctx

    while True:
        if getCtx() is None:
            print(f"Trigger a request first, waiting...")
            time.sleep(1)
        else:
            break
    if rpc_request is None:
        print(f"Fail to load rpc request function")
    print("Server start...")
    app.run(port=8989)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {__name__}.py <script_name>")
        exit(0)
    inject_and_run(sys.argv[1])
