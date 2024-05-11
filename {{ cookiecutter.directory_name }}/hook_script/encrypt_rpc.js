/**
 * Implement encryption/decryption hook function and exports to Frida RPC
 */
var globalCtx = null // required parameter for actively function call 

function hook() {
    Java.perform(function () {
        // Initialize Parameters:
        // var client = Java.use("xxx")
        // client.doPost.implementation = function (url, body, s1, class0) {
        //     // console.log(`request: url=${url}, body=${jsonStr}, s1=${s1}, class=${class0}, context=${this.mContext.value}`)
        //     globalCtx = this.mContext.value
        //     console.log(`Initialized`)
        //     return this.doPost(url, body, s1, class0)
        // }
    })
}

/**
 * Send request and get response by frida
 * @param {*} path 
 * @param {*} body 
 * @returns 
 */
function request(path, body) {
    if (globalCtx == null) {
        console.error(`have not init`)
        return null
    }
    var data = "NONE"
    Java.performNow(function () {
        // send request and get response
        // store response in data
    })
    return data
}

/**
 * Encryption by frida
 * @param {*} body 
 * @returns 
 */
function encrypt(body) {
    if (globalCtx == null) {
        console.error(`have not init`)
        return null
    }
    var data = "NONE"
    Java.performNow(function () {
        // encrypt body and get encryption result
    })
    return data
}
/**
 * Decryption by frida
 * @param {*} body 
 * @returns 
 */
function decrypt(body) {
    if (globalCtx == null) {
        console.error(`have not init`)
        return null
    }
    var data = "NONE"
    Java.performNow(function () {
        // decrypt body and get decryption result
    })
    return data
}


/**
 * Check whether the environment is prepared
 * @returns 
 */
function getctx() {
    return globalCtx
}

hook() // prepare environment


rpc.exports.decrypt = decrypt
rpc.exports.encrypt = encrypt
rpc.exports.request = request
rpc.exports.getctx = getctx