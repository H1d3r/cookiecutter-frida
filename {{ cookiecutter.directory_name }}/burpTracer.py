from codecs import ignore_errors
import threading
import frida
import requests
import time
import sys
import os
import socket
import argparse

# from request import sendRequest
from utils.log import *
import binascii
import base64

#
print(
    """\033[1;31m \n
  _____    _     _         ___       _             ____           _
|  ___| __(_) __| | __ _  |_ _|_ __ | |_ ___ _ __ / ___|___ _ __ | |_
| |_ | '__| |/ _` |/ _` |  | || '_ \| __/ _ \ '__| |   / _ \ '_ \| __|
|  _|| |  | | (_| | (_| |  | || | | | ||  __/ |  | |__|  __/ |_) | |_
|_|  |_|  |_|\__,_|\__,_| |___|_| |_|\__\___|_|   \____\___| .__/ \__|
                       #pyth0n                             |_|     
                Intercept Api in Android Application
"""
)

print("\033[1;34m[*]___author___: @Pyth0n\033[1;37m")
print("\033[1;34m[*]___version___: 1.0\033[1;37m")
print("")

BURP_HOST = "127.0.0.1"
BURP_PORT = 26080
# BURP_PORT = 8989


def check_platform():
    try:
        platforms = {
            "linux": "Linux",
            "linux1": "Linux",
            "linux2": "Linux",
            "darwin": "OS X",
            "win32": "Windows",
        }
        if sys.platform not in platforms:
            sys.exit(logger.error("[x_x] Your platform currently does not support."))
    except Exception as e:
        logger.error(
            "[x_x] Something went wrong, please check your error message.\n Message - {0}".format(
                e
            )
        )


def check_ps_for_win32():
    try:
        if sys.platform == "win32":
            PROCESSNAME = "iTunes.exe"
            for proc in psutil.process_iter():
                try:
                    if proc.name() == PROCESSNAME:
                        return True
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ) as e:
                    pass
            return sys.exit(
                logger.error(
                    "[x_x] Please install iTunes on MicrosoftStore or run iTunes frist."
                )
            )
    except Exception as e:
        logger.error(
            "[x_x] Something went wrong, please check your error message.\n Message - {0}".format(
                e
            )
        )


def check_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1", 27080))
    if result == 0:
        logger.info("[*] Connect to echoServer successfully.")
    else:
        sock.close()
        sys.exit(logger.error("[x_x] Please start echoServer."))


def run():
    # check platform support
    check_platform()
    # check process iTunes for Win32s
    # check_ps_for_win32()
    # check python version
    if sys.version_info < (3, 0):
        logger.error("[x_x] iOS hook requires Python 3.x")
        sys.exit(0)
    else:
        handle_del_log()
        main()


def handle_del_log():
    try:
        pwd = os.getcwd()
        path = pwd + "/errors.log"
        file_stats = os.stat(path)
        if file_stats.st_size > 1024000000:  # delete errors.log if file size > 1024 MB
            os.remove(path)
        else:
            return True
    except Exception as e:
        logger.error(
            "[x_x] Something went wrong when clear error log. Please clear error log manual.\n [Error Message] - {0}".format(
                e
            )
        )


def start_rpc(script):
    from server import run

    threading.Thread(target=run, args=(script,), daemon=True).start()


def main():
    def frida_process_message(message, data):

        handled = False
        if message["type"] == "input":
            handled = True
        elif message["type"] == "send":
            body = message["payload"]

            if body["from"] == "log":
                logger.info(f"[*] Log from JS: {body['payload']}")
            else:
                API_PATH = body["api_path"]
                if str(API_PATH).__contains__("request"):
                    method = body["method"]
                else:
                    method = ""
                if body["from"] == "/http":
                    try:
                        # 把数据发给 本地burp 监听的 26080端口
                        req = requests.request(
                            "FRIDA",
                            "http://%s:%d/%s" % (BURP_HOST, BURP_PORT, API_PATH),
                            headers={
                                "content-type": "application/json",
                                "operation-type": method,
                            },
                            data=body["payload"].encode("utf-8"),
                        )
                        script.post(
                            {"type": "input", "payload": req.text}
                        )  # 把修改后的数据传输回给js
                        handled = True
                    except requests.exceptions.RequestException as e:
                        logger.error(
                            "[x_x] Connection refused, please check configurage on BurpSute.\n [Error Message] - {0}".format(
                                e
                            )
                        )
                elif body["from"] == "/http_base64":
                    try:
                        # 把数据发给 本地burp 监听的 26080端口
                        data = base64.b64decode(body["payload"])
                        req = requests.request(
                            "FRIDA",
                            "http://%s:%d/%s" % (BURP_HOST, BURP_PORT, API_PATH),
                            headers={"content-type": "application/json"},
                            data=data,
                        )
                        b = base64.b64encode(req.content).decode("utf8")
                        script.post(
                            {"type": "input", "payload": b}
                        )  # 把修改后的数据传输回给js
                        handled = True
                    except requests.exceptions.RequestException as e:
                        logger.error(
                            "[x_x] Connection refused, please check configurage on BurpSute.\n [Error Message] - {0}".format(
                                e
                            )
                        )
                # elif body["from"] == "/sendRequest":
                #     logger.info(f"sendRequest")
                #     req_data = body["req_data"]
                #     sign = body["sign"]
                #     method = body["method"]
                #     try:
                #         logger.info("[+] sendRequest")
                #         res = sendRequest(req_data, sign, method)
                #         logger.info("sssssss")
                #         script.post({"type": "input", "payload": res})
                #     except requests.exceptions.RequestException as e:
                #         logger.error("[x_x] SendRequest Failed - {0}".format(e))
                #         script.post({"type": "input", "payload": f"{e}"})
                elif body["from"] == "/response":
                    logger.info(body)
                    res_base = body["payload"]
                    res = base64.b64decode(res_base).decode("utf8")
                    logger.info(f"Response: {res}")
                elif body["from"] == "/sendSms":
                    payload = body["payload"]
                    phone = body["phone"]
                    try:
                        logger.info("[+] sendSms")
                        sendSms(phone, payload)
                    except requests.exceptions.RequestException as e:
                        logger.error("[x_x] SendSms Failed - {0}".format(e))
                elif body["from"] == "/httpHex":
                    try:
                        # 把数据发给 本地burp 监听的 26080端口
                        payload = binascii.unhexlify(body["payload"]).decode("utf8")
                        req = requests.request(
                            "FRIDA",
                            "http://%s:%d/%s" % (BURP_HOST, BURP_PORT, API_PATH),
                            headers={"content-type": "application/json"},
                            data=payload.encode("utf-8"),
                        )
                        res = binascii.hexlify(req.text.encode("utf8"))
                        res = str(res)[2:-1]
                        # print(res)
                        script.post(
                            {"type": "input", "payload": res}
                        )  # 把修改后的数据传输回给js
                        handled = True
                    except requests.exceptions.RequestException as e:
                        logger.error(
                            "[x_x] Connection refused, please check configurage on BurpSute.\n [Error Message] - {0}".format(
                                e
                            )
                        )
                else:
                    logger.info(f"[-] Unhandled message: {body['from']}")

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--package")
    parser.add_argument("-n", "--name")
    parser.add_argument("-s", "--script", help="custom handler script")
    parser.add_argument("-r", "--remote", help="远程主机")
    parser.add_argument("--rpc", help="RPC script", required=False)
    parser.add_argument("-a", "--addition", help="Additional script", required=False)

    args, leftovers = parser.parse_known_args()

    try:
        # Spawning application with default script
        if args.package is not None and args.script is None:
            # check echoServer
            check_echo_server()
            #
            logger.info("[*] Spawning: " + args.package)
            logger.info("[*] Script: " + "handlers.js")
            time.sleep(2)
            device = frida.get_usb_device()
            pid = device.spawn(args.package)
            device.resume(pid)
            time.sleep(1)
            session = device.attach(pid)
            with open("handlers.js") as f:
                script = session.create_script(f.read())
            script.on("message", frida_process_message)
            script.load()
            input()
        # Attaching default script to application
        if args.name is not None and args.script is None:
            # check echoServer
            check_echo_server()
            #
            logger.info("[*] Attaching: " + args.name)
            logger.info("[*] Script: " + "handlers.js")
            time.sleep(2)
            process = frida.get_usb_device().attach(args.name)
            with open("handlers.js") as f:
                script = process.create_script(f.read())
            script.on("message", frida_process_message)
            script.load()
            input()
        # Spawing application with custom script
        if args.package is not None and args.script is not None:
            # check echoServer
            check_echo_server()
            #
            if os.path.isfile(args.script):
                logger.info("[*] Spawning: " + args.package)
                logger.info("[*] Script: " + args.script)
                time.sleep(2)
                device = frida.get_remote_device()
                if args.remote is not None:
                    logger.info(f"[*] Remote: {args.remote}")
                    device = frida.get_device_manager().add_remote_device(args.remote)
                pid = device.spawn(args.package)
                device.resume(pid)

                time.sleep(1)
                session = device.attach(pid)
                with open(args.script, encoding="utf-8", errors="ignore") as f:
                    script = session.create_script(f.read())
                script.on("message", frida_process_message)
                script.load()
                input()
            else:
                logger.error("[?] Script not found!")

        # Attaching custom script to application
        if args.name is not None and args.script is not None:
            # check echoServer
            check_echo_server()
            #
            logger.info("[*] Attaching: " + args.name)
            logger.info("[*] Script: " + args.script)
            time.sleep(2)

            if args.remote is not None:
                device = frida.get_remote_device()
                logger.info(f"[*] Remote: {args.remote}")
                device = frida.get_device_manager().add_remote_device(args.remote)
            else:
                device = frida.get_usb_device()
            process = device.attach(args.name)

            all_script = ""
            if args.rpc is not None:
                with open(args.rpc, encoding="utf8", errors="ignore") as f:
                    rpc_script = f.read() + "\n"
                    all_script += rpc_script
                # logger.info(f"[*] Starting rpc server: {args.rpc}")
                # start_rpc(args.rpc)
            if args.addition is not None:
                with open(args.addition, encoding="utf8", errors="ignore") as f:
                    all_script += f.read() + "\n"
                    logger.info(f"[*] Additional script: {args.addition}")
            with open(args.script, encoding="utf-8", errors="ignore") as f:
                all_script += f.read()
                script = process.create_script(all_script)
            script.on("message", frida_process_message)
            script.load()
            if args.rpc is not None:
                logger.info(f"[*] Starting rpc server: {args.rpc}")
                start_rpc(script)

            input()

        if args.remote is not None and args.script is not None:
            # check echoServer
            check_echo_server()
            #
            logger.info("[*] Attaching: " + args.remote)
            logger.info("[*] Script: " + args.script)
            time.sleep(2)
            process = frida.get_remote_device().attach(args.remote)
            with open(args.script, encoding="utf-8", errors="ignore") as f:
                script = process.create_script(f.read())
            script.on("message", frida_process_message)
            script.load()
            input()

    # EXCEPTION FOR FRIDA
    except frida.ServerNotRunningError:
        logger.error("Frida server is not running.")
    except frida.TimedOutError:
        logger.error("Timed out while waiting for device to appear.")
    except frida.TransportError:
        logger.error("[x_x] The application may crash or lose connection.")
    # EXCEPTION FOR OPTIONPARSING

    # EXCEPTION FOR SYSTEM
    except Exception as e:
        logger.error(
            "[x_x] Something went wrong, please check your error message.\n Message - {0}".format(
                e
            )
        )

    except KeyboardInterrupt:
        logger.info("Bye bro!!")
        # sys.exit(0)


if __name__ == "__main__":
    run()
