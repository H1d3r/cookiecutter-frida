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
successNum = 0
fail = 0


def sendRequest(
    req_data: str, sign: str, key: str, salt: str, method: str, cookie: str = ""
):
    global successNum, fail
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encoded_time = quote(current_time)
    # req_data = req_data.replace("\n", "")
    # sign = sign.replace("\n", "")
    # key = key.replace("\n", "")
    # salt = salt.replace("\n", "")
    data = f"sign={quote(sign)}&method={method}&version=1.0&app_id=CFCAMBS&req_data={quote(req_data)}&key={quote(key)}&salt={quote(salt)}"
    proxy = {"https": "127.0.0.1:8080", "http": "127.0.0.1:8080"}
    header = {
        "Host": "mfbank.beeb.com.cn",
        "Basic_eauth": cookie,
        "System": "android",
        "Version": "3.1.5",
        "Systemversion": "13",
        "Platform": "app",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        # 'Content-Length': '3000',
        # 'Accept-Encoding': 'gzip, deflate, br',
        "User-Agent": "okhttp/3.12.12",
        "Connection": "close",
    }
    res = requests.post(
        "https://mfbank.beeb.com.cn/gateway",
        data=data,
        headers=header,
        proxies=proxy,
        verify=False,
    )
    # print(res.status_code)
    # print(len(res.text))
    ret = json.loads(res.text)
    # try:
    #     ret = json.loads(res.text)["resp_data"]
    # except KeyError:
    #     try:
    #         ret = json.loads(res.text)["msg"]
    #         print(f"Response Error: {ret}")
    #     except KeyError:
    #         ret = "<empty>"
    #         print(f"Response Error: {ret}")

    return ret
    # isSuccess = False
    # if (len(res.text) < 400) or res.status_code != 200:
    #     fail += 1
    #     isSuccess = False
    # else:
    #     successNum += 1
    #     isSuccess = True
    # print(f"success: {successNum} fail:{fail}")
    # return isSuccess
    # try:
    #     print("Decryption: " + sm4_decrypt_ecb(res.text, "0000000000000000"))
    #     print("")
    # except Exception as e:
    #     print("Decryption failed ")
    # finally:
    #     return isSuccess
    # print(e)
    # print(res.text)


def sendSms(phone: str, data: str):
    isSuccess = sendRequest(data)
    print(f"SMS: {phone} {isSuccess}")
    time.sleep(0.5)


if __name__ == "__main__":
    # for i in range(10):
    #     time.sleep(0.5)
    #     sendRequest(
    #         "#01e0cbb8530a051a60ccbdd6bf99cb17898c2d344b168691f135aa125a12664556<GS>69bb4a15e52b0cd83f07609b97550553d34982536d309c4ce3e355df45e2fed6709c6dbf3766b6f214d6bb52b8e97a7ff523a97f130c4e96ede9d69aeca5bb0573eb4c513f3b3f09f813101e0b2caee40df4b9203a1cfba3cfc580087a34e1f19376d2125731fde402bc1bdf86fd4c50ec9b61023de88b576384d06acc3e8217ccdb88eb9d6c943a4f69eadad252b6a3cc93c105b5c3bdf8d03e025a690fab4699a61efda6ca6a450825bb90a866e71942e6d15be391f5db70ec2e3a503aacca3c75757d022f85701871b8d1e0deb9a605b26eacec22ee593a297bfeb2ceda6a54de2466dd6a9e2b397efc83c1d3cceabb847005945afbf9f7351ad85b487eeaccb8a77b40cf66d01641c5704ce4df0dc8ceafaf522326b6930a48837600befbf1500ca6e6d27d3428cce7392662cbae34f86775a332c1da7b53e3ea6b8490c8144b21ad00c7655eca783219f1ce98b44b01f491f4b388dc699ee6a07e2608a2d1f357613d5a8a9ffa266d8ca35e5bcf0908a56b041811af5e905d62e91d593e974738f9d84bc49db41be7177575cf9d<GS>2a42ef7de7c2046f87791087b3855fd7da12578565392d69af4888703c3486f5b68f5a893d6f4476fba4837ded4ff4beef21ef62a3f21cab88f8fb50bab81bc92224d2be7a76d5e6bda0fda685e792e277ab55bd8239350cf0031174052f28d829c6a57e81acfce30766fc87255ce662"
    #     )
    # print(f"success: {successNum}, fail:{fail}")
    header_str = """equipid: 03A0038F664736A132B86AA04585ED7A28742F6D
abtest: undefined
channelno: OB03
isroot: 0
securityflag: 0
pssid: 
nbversion: 1.0.0.38
icifid: 222
packagetype: 00
subterminaltype: android
appversion: 2.1.46
mobilebrand: google
bankcorpcode: 15601
commtype: 1
macvalue: 
clientip: 127.0.0.1
versionno: 0.1
wdbranchy: 
wdbranchx: 
nbappid: 20190027
maccode: 02:00:00:00:00:00
Platform: ANDROID
WorkspaceId: product
AppId: 147ECC8171707
productVersion: 1.8.5.230913152350
productId: 147ECC8171707_ANDROID
Version: 2
Did: Zh8wYiD8XLUDAC7GsyrHZ7dV
Operation-Type: com.ZX400009
Ts: OxgbjTe
Sign: f59d274a57dd347f712c395f55b0e15bc2e1c1e5509a53c730852552993a0a3d
signType: sm3
x-app-sys-Id: com.rmjinhua
Connection: Keep-Alive
Cookie: 
TargetIPPORT: 123.157.158.166:10441
Content-Type: application/json
Content-Length: 344
Host: 123.157.158.166:10441
Accept-Encoding: gzip
User-Agent: okhttp/3.11.0"""
    body = binascii.a2b_hex(
        "0100010074d09f2a748ac0e4f3094b14e0544ad9cce4c1c32f32997552209e3d08fb0d24022f2531dddb93f85d625c1f4497dbe40603db27bc7f7874262ef895cbca82f3cc22297972c67de78af8422f0073cfd6ee9448c577cd7582b11e70b8f4035eda90662d77af6ee06afc7b36a72286fe70de2fb9ef9958e662f0fd59b15f07f9266f9344a33a6b11a4d90fec75fa8e42466046da1a6d878ede9b140b6fef70d1b27bcc10bbbe6134090e184703a34280087aa08e3d646034e23e1537037f1af53ba3c7a39d3261af95adf4fda7b26ce0594768c1e297af4360f63c84802092e7b9d417a51b445b4d07cb1323ae0d23422b2c086e8fa636d24852aad645099658fc0f000050679b28538eeccac806b0f1ac5055f317b0a67cfb74e77ce5ccb4617811d80a740f70518ef01182a7b2fb79034eba097ede5fe0a98503dce03554a720b784452529f51f7886750a95db1e05fbb0ac8ba3"
    )

    header_dict = dict()
    header_lines = header_str.split("\n")
    for line in header_lines:
        l = line.split(":")
        header_dict[l[0].strip()] = l[1].strip()
    # proxy = {"https": "192.168.43.230:8892"}
    proxy = {"https": "127.0.0.1:8083", "http": "127.0.0.1:8083"}
    url = "https://mpaassmapi.czcb.com.cn:10441/mgw.htm"
    res = requests.post(
        url, proxies=proxy, headers=header_dict, verify=False, data=body
    )
    print(res.status_code)
