# Overview
This is a cookiecutter template for bypassing the traffic encryption in Android app. Please read [this article](https://xz.aliyun.com/t/14454) first.

# Install
```bash
> cookiecutter https://github.com/PadishahIII/cookiecutter-frida.git
  [1/9] directory_name (sample_project): frida
  [2/9] package_name (com.certain.package): com.xxxbank
  [3/9] app_name (AppName): 某某银行
  [4/9] local_ip (192.168.43.246): 
  [5/9] mitm_http_port (8082):
  [6/9] mitm_frida_port (27081):
  [7/9] frida_ip (127.0.0.1): 192.168.43.230
  [8/9] frida_port (3333):
  [9/9] rpc_server_port (8989):

> cd frida
> pip install -r requirements.txt
```

# Launch
## Start echoServer
```bash
python echoServer.py
```

## Start mitmproxy
```bash
mitmproxy -s mitmproxy_script/mitm.py --listen-host 0.0.0.0 -p {{ cookiecutter.mitm_frida_port }} --mode upstream:http://127.0.0.1:27080 -k
```
Optional:
```bash
mitmproxy -s mitmproxy_script/mitm_http.py --listen-host 0.0.0.0 -p {{ cookiecutter.mitm_http_port }} --mode upstream:http://127.0.0.1:8081 -k
```

## Configure Burp
- Start a burp listener on local port 26080 and redirect to port 27081.
- (Optional) Start a burp listener on local port 8081

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
