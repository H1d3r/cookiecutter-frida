if [ -z "$1" ]; then
frida -H {{ cookiecutter.frida_ip }}:{{ cookiecutter.frida_port }} -f {{ cookiecutter.package_name }} 
else frida -H {{ cookiecutter.frida_ip }}:{{ cookiecutter.frida_port }} -f {{ cookiecutter.package_name }} -l $1
fi