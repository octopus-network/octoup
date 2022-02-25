[validator]
%{ for idx, addr in public_ips ~}
${addr}
%{ endfor ~}

[validator:vars]
ansible_python_interpreter=/usr/bin/python3
