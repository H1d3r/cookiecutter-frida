var globalCtx = null

function hook() {
    Java.perform(function () {
        var client = Java.use("com.rmjinhua.manager.SecurityManager")
        client.doPost.implementation = function (url, body, s1, class0) {
            // var jsonStr = jsonClz.$new().toJson(body)
            // console.log(`request: url=${url}, body=${jsonStr}, s1=${s1}, class=${class0}, context=${this.mContext.value}`)
            globalCtx = this.mContext.value
            console.log(`Initialized`)
            return this.doPost(url, body, s1, class0)
        }
    })
}

function request(path, body) {
    if (globalCtx == null) {
        console.error(`have not init`)
        return null
    }
    var data = "NONE"
    Java.performNow(function () {
        var requestBuilder = Java.use("com.rmjinhua.b.a")
        var jsonClz = Java.use("org.json.JSONObject")
        var encryptClz = Java.use("cn.microdone.txcrypto.txcrypto")
        var requestClient = Java.use("com.rmjinhua.util.k")

        var txcrypto0 = encryptClz.$new();
        txcrypto0.SetLicense(
            "YUpkc0plQnBrRkRGcXM5eng3ZzZ0KzFZTXY3WmU4SWY2cFU2V1dDekcxNTAzcXRPcnlWeldiZXZBVi9obitDU1J2MHdJT0xzRHRaalcySmdDZk5NQXFPb2h0WW41bGxSYVlCcVI2R2IrVnVCTVZtaTdxQjV5NHp0eC80R09MSkl5OHY2azhZNHpLUlpuQWlBcDVnY3NHeS82cEp3NDlSblZwWFZLZ1ZqZHlFPXsiaWQiOjEsInR5cGUiOiJwcm9kdWN0IiwicGFja2FnZSI6WyJjb20ucm1qaW5odWEiXSwiYXBwbHluYW1lIjpbIumHkemTtumSseWMhSJdLCJwbGF0Zm9ybSI6Mn0=",
            globalCtx
        );

        // requestBuilder.a.implementation = function(ctx, path, enc_body,txnCode){

        // }
        var enc_body = txcrypto0.EncryptLite(body)
        var txnCode = JSON.parse(body)['txnCode']
        var requestObj = requestBuilder.a(globalCtx, path, enc_body, txnCode)
        var requestStr = requestObj['toString']()
        console.log(`request: ${requestStr}`)

        var client = requestClient.$new(globalCtx)
        client.init()
        client.setServerUrl(client.getServerUrl() + "/" + path)
        console.log(`url: ${client.getServerUrl()}`)

        var response = client.submitProcess(requestStr, null)
        console.log(`response: ${response}`)
        var respObj = JSON.parse(response)
        var respData = respObj['respData']
        var respCode = respObj['respCode']
        respData = new String(respData)
        respData = respData.replaceAll("\r", "")
        respData = respData.replaceAll("\n", "")
        var respDataDec = txcrypto0.DecryptLite(respData)
        console.log(`respdata:${respData}\nresp data dec: ${respDataDec}`)
        respObj['respData'] = respDataDec
        // data = JSON.stringify(respDataDec)
        data = respDataDec

    })
    return data
}

hook()
var path = "211.211005"
var body = { "moblNo": "13273487268", "pwd": "56811BF80AA739FBF6CF479402222841", "pwdTp": "10", "userId": "7348132726816861", "busCode": "UM0039", "channel": "412", "reqDate": "20240510", "reqSsn": "20240510111450raCyIs", "reqTime": "111450", "stepCode": "01", "termCd": "24884a8905de8926", "txnCode": "504.0009" }
var body_str = JSON.stringify(body)

function getctx() {
    return globalCtx
}

// rpc.exports.decrypt = decrypt
// rpc.exports.encrypt = encrypt
// rpc.exports.key = getKey
// rpc.exports.uuid = getUuid

rpc.exports.request = request
rpc.exports.getctx = getctx