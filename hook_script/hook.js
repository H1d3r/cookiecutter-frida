// setTimeout(function () {
//     Java.perform(function () {
//         var proxyUtil = Java.use("com.tzb.mobilehub.launcher.utils.ProxyUtils")
//         proxyUtil.isWifiProxy.implementation = function (ctx) {
//             console.log("intercept")
//             return false;
//         }
//     })
// }, 2000)
var strClz = Java.use("java.lang.String")

function hasOwnProperty(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return obj.hasOwnProperty(name);
    }
}

function getHandle(object) {
    if (hasOwnProperty(object, '$handle')) {
        if (object.$handle != undefined) {
            return object.$handle;
        }
    }
    if (hasOwnProperty(object, '$h')) {
        if (object.$h != undefined) {
            return object.$h;
        }
    }
    return null;
}
//查看域值
function inspectObjectField(obj) {
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    console.log("Inspecting Fields: => ", isInstance, " => ", obj_class.toString());
    var fields = obj_class.getDeclaredFields();
    for (var i in fields) {
        if (isInstance || Boolean(fields[i].toString().indexOf("static ") >= 0)) {
            // output = output.concat("\t\t static static static " + fields[i].toString());
            var className = obj_class.toString().trim().split(" ")[1];
            // console.Red("className is => ",className);
            var fieldName = fields[i].toString().split(className.concat(".")).pop();
            var fieldType = fields[i].toString().split(" ").slice(-2)[0];
            var fieldValue = undefined;
            if (!(obj[fieldName] === undefined))
                fieldValue = obj[fieldName].value;
            console.log(fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
        }
    }
    return null;
}

function inspectObject(obj) {
    // if (obj == undefined || obj == null) {
    //     console.log("null");
    //     return;
    // }
    var isInstance = false;
    var obj_class = null;
    if (getHandle(obj) === null) {
        obj_class = obj.class;
    } else {
        var Class = Java.use("java.lang.Class");
        obj_class = Java.cast(obj.getClass(), Class);
        isInstance = true;
    }
    var obj_class = Java.cast(obj.getClass(), Class);
    var fields = obj_class.getDeclaredFields();
    var methods = obj_class.getMethods();
    console.log("Inspecting->" + obj.getClass().toString());
    console.log("\t Fields: type, name value, jsonvalue")
    for (var i in fields) {
        var className = obj_class.toString().trim().split(" ")[1];
        var fieldName = fields[i].toString().split(className.concat(".")).pop();
        var fieldType = fields[i].toString().split(" ").slice(-2)[0];
        var fieldValue = undefined;
        if (!(obj[fieldName] === undefined)) {
            fieldValue = obj[fieldName].value;
        }
        // console.log("\t\t" + fields[i].toString());
        console.log("\t\t" + fieldType + " \t" + fieldName + " => ", fieldValue + " => ", JSON.stringify(fieldValue));
    }
    console.log("\t Methods:")
    for (var i in methods) {
        console.log("\t\t" + methods[i].toString())
    }
}
function stack() {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new());
    console.log(stackinfo)
}
function getStack() {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new());
    return stackinfo
}
function okhttpproxy() {
    Java.perform(function () {
        var proxy = Java.use("java.net.Proxy")
        var proxyType = Java.use("java.net.Proxy$Type")
        var inet = Java.use("java.net.InetSocketAddress")
        var ins = proxy.$new(proxyType.valueOf("HTTP"), inet.$new("192.168.43.247", 18080))
        var okhttpClient = Java.use("okhttp3.OkHttpClient")
        okhttpClient.proxy.implementation = function () {
            console.log("okhttp proxy intercept")
            return ins;
        }

        var builder = Java.use("okhttp3.OkHttpClient$Builder")
        builder.proxy.implementation = function (p) {
            console.log("okhttp builder hook")
            var a = Java.cast(ins, proxy)
            return this.proxy(a)
        }

    })
}
function okhttpClient() {
    Java.perform(function () {
        var sClz = Java.use('java.lang.String');
        var clz = Java.use("okhttp3.OkHttpClient")
        clz.protocols.implementation = function () {
            var ret = this.protocols()
            console.log(`protocols: ${ret['getClass']()}`)
            return ret;
        }
    })
}
function connSpec() {
    Java.perform(function () {
        var clz = Java.use("okhttp3.ConnectionSpec")
        clz.tlsVersions.implementation = function () {
            var ret = this.tlsVersions()
            var len = ret.size()
            for (var i = 0; i < len; i++) {
                console.log(`version:${ret.get(i)}`)
            }
            return ret
        }
        clz.isCompatible.implementation = function (socket) {
            var ret = this.isCompatible(socket)
            console.log(`isCompatible: ${ret}`)
            return ret
        }
    })
}
function decodeUTF8(uint8Array) {
    let result = '';
    let i = 0;

    while (i < uint8Array.length) {
        let byte = uint8Array[i];

        if (byte < 0x80) {
            result += String.fromCharCode(byte);
            i++;
        } else if (byte < 0xE0) {
            let codePoint = ((byte & 0x1F) << 6) | (uint8Array[i + 1] & 0x3F);
            result += String.fromCharCode(codePoint);
            i += 2;
        } else if (byte < 0xF0) {
            let codePoint = ((byte & 0x0F) << 12) | ((uint8Array[i + 1] & 0x3F) << 6) | (uint8Array[i + 2] & 0x3F);
            result += String.fromCharCode(codePoint);
            i += 3;
        } else {
            // Handle 4-byte sequences if needed
            // Not required for basic UTF-8
        }
    }

    return result;
}
function encodeUTF8(input) {
    const bytes = [];

    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);

        if (charCode < 128) {
            bytes.push(charCode);
        } else if (charCode < 2048) {
            bytes.push((charCode >> 6) | 192);
            bytes.push((charCode & 63) | 128);
        } else if ((charCode & 0xfc00) == 0xd800 && i + 1 < input.length && (input.charCodeAt(i + 1) & 0xfc00) == 0xdc00) {
            // Surrogate pair
            charCode = 0x10000 + ((charCode & 0x03ff) << 10) + (input.charCodeAt(++i) & 0x03ff);
            bytes.push((charCode >> 18) | 240);
            bytes.push(((charCode >> 12) & 63) | 128);
            bytes.push(((charCode >> 6) & 63) | 128);
            bytes.push((charCode & 63) | 128);
        } else {
            bytes.push((charCode >> 12) | 224);
            bytes.push(((charCode >> 6) & 63) | 128);
            bytes.push((charCode & 63) | 128);
        }
    }

    return bytes;
}
function array2str(ret) {
    return decodeUTF8(byteToUint8Array(ret))

}
function str2ByteArray(str) {
    return (encodeUTF8(str))
}
function byteArray2HexStr(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}
function hexStr2ByteArray(hexString) {
    const result = [];
    for (let i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(result);
}
function byteToUint8Array(byteArray) {
    var uint8Array = new Uint8Array(byteArray.length);
    for (var i = 0; i < uint8Array.length; i++) {
        uint8Array[i] = byteArray[i];
    }

    return uint8Array;
}
function uint8ArrayToArray(uint8Array) {
    var array = [];

    for (var i = 0; i < uint8Array.byteLength; i++) {
        array[i] = uint8Array[i];
    }

    return array;
}
function sendToBurpReq(res, operation_type = "") {
    var data = res.toString()
    send({ from: "/http", payload: data, api_path: "request", method: operation_type });
    var op = recv("input", function (value) {
        data = value.payload
    });
    op.wait();
    return data
}
function sendToBurpRes(res) {
    var data = res.toString()
    send({ from: "/http", payload: data, api_path: "response" });
    var op = recv("input", function (value) {
        data = value.payload
    });
    op.wait();
    return data
}
function sendHexToBurp(res) {
    var data = res.toString()
    send({ from: "/httpHex", payload: data, api_path: "request" });
    var op = recv("input", function (value) {
        data = value.payload
    });
    op.wait();
    return data
}
function reqRes() {
    Java.perform(function () {
        try {
            var currentPath = "unknown"
            var client = Java.use("com.rmjinhua.manager.SecurityManager")
            // conflict with encrypt_rpc.js
            // client.doPost.implementation = function (url, body, s1, class0) {
            //     // var jsonStr = jsonClz.$new().toJson(body)
            //     // console.log(`request: url=${url}, body=${jsonStr}, s1=${s1}, class=${class0}, context=${this.mContext.value}`)
            //     currentPath = url
            //     return this.doPost(url, body, s1, class0)
            // }
            var requestBuilder = Java.use("com.rmjinhua.b.a")
            requestBuilder.a.implementation = function (ctx, path, enc_body, txnCode) {
                currentPath = path
                return this.a(ctx, path, enc_body, txnCode)
            }


            //request
            var jsonClz = Java.use("com.google.gson.Gson")
            var encryptClz = Java.use("cn.microdone.txcrypto.txcrypto")
            encryptClz.EncryptLite.implementation = function (s) {
                // var jsonObj = JSON.parse(s)
                var data = sendToBurpReq(s, currentPath)
                var res = this.EncryptLite(data)

                console.log(`\nencrypt: ${s}\n=> ${data}`)
                return res
            }
            //response
            encryptClz.DecryptLite.implementation = function (s) {
                var res = this.DecryptLite(s)
                var data = sendToBurpRes(res)

                console.log(`\ndecrypt: ${res}\n => ${data}`)
                return data
            }

        } catch (error) {
            console.error(error)
        }
    }

    )

}
function trace() {
    Java.perform(function () {
        var jsonClz = Java.use("com.google.gson.Gson")
        var encryptClz = Java.use("cn.microdone.txcrypto.txcrypto")
        encryptClz.EncryptLite.implementation = function (s) {
            var res = this.EncryptLite(s)
            console.log(`encrypt: ${s}\n=>${res}`)
            return res
        }
        encryptClz.DecryptLite.implementation = function (s) {
            var res = this.DecryptLite(s)
            console.log(`decrypt: ${s}\n => ${res}`)
            return res
        }
        var client = Java.use("com.rmjinhua.manager.SecurityManager")
        var globalCtx = null
        client.doPost.implementation = function (url, body, s1, class0) {
            var jsonStr = jsonClz.$new().toJson(body)
            console.log(`request: url=${url}, body=${jsonStr}, s1=${s1}, class=${class0}, context=${this.mContext.value}`)
            globalCtx = this.mContext.value
            return this.doPost(url, body, s1, class0)
        }




    })


}


reqRes()
// trace()
// encrypt_init()
// encrypt()
// connSpec()
// okhttpClient()
// okhttpproxy()
// trace_response()

