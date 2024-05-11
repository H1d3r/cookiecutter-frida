/**
 * Hook java proxy class
 */
function start() {
    Java.perform(function () {
        let proxyClz = Java.use("java.net.Proxy")
        let addressClz = Java.use("java.net.InetSocketAddress")
        proxyClz.address.implementation = function () {
            var res = this.address()
            let myproxy = addressClz.$new("{{ cookiecutter.mitm_http_port }}", {{ cookiecutter.mitm_http_port }}) // change here

    console.log(`Proxy: ${res} -> ${myproxy}`)
    return myproxy
}
    })
}
start()//need to spawn