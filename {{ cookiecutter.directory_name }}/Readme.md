# Overview
This is a cookiecutter template for bypassing the traffic encryption in Android app. Please Read [this article](https://www.wolai.com/secnote/4Bq9JWA49txJA8gYBa55SR) first.

# Launch
## Start echoServer
```bash
python echoServer.py
```

## Start mitmproxy
```bash
mitmproxy -s mitmproxy_script/mitm.py --listen-host 0.0.0.0 -p {{ cookiecutter.mitm_frida_port }} --mode upstream:http://127.0.0.1:27080 -k
```
```bash
mitmproxy -s mitmproxy_script/mitm_http.py --listen-host 0.0.0.0 -p {{ cookiecutter.mitm_http_port }} --mode upstream:http://127.0.0.1:8081 -k
```

## Spawn target App
Run `hook_script/spawn.sh` or start the app manually.

## Start burpTracer, inject js
```bash
python burpTracer.py -s hook_script/hook.js -r {{ cookiecutter.frida_ip }}:{{ cookiecutter.frida_port }} -n {{ cookiecutter.app_name }}
```
or start rpc server:
```bash
python burpTracer.py -s hook_script/hook.js -r {{ cookiecutter.frida_ip }}:{{ cookiecutter.frida_port }} -n {{ cookiecutter.app_name }} --rpc hook_script/encrypt_rpc.js -a hook_script/proxy.js
```


## Start RPC server
```bash
python rpc_server.py hook_script/encrypt_rpc.js
```