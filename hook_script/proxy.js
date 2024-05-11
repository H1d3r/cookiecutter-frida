function start() {
    Java.perform(function () {
        let proxyClz = Java.use("java.net.Proxy")
        let addressClz = Java.use("java.net.InetSocketAddress")
        proxyClz.address.implementation = function () {
            var res = this.address()
            let myproxy = addressClz.$new("192.168.43.246", 8082) // change here

            console.log(`Proxy: ${res} -> ${myproxy}`)
            return myproxy
        }
    })
}
start()//need to spawn