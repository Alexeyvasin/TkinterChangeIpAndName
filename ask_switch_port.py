import telnetlib

import pythonping


def ask_sw_port(ip, port):
    tn = telnetlib.Telnet(ip, timeout=5)
    tn.read_until(b"UserName:")
    user = 'admin'
    password = 'admin'
    tn.write(user.encode() + b"\n")
    tn.read_until(b"PassWord:")
    tn.write(password.encode() + b"\n")
    tn.write(('show fdb port ' + str(port)).encode() + b'\n')
    res = tn.read_until('Priori'.encode(), timeout=0.5)
    rsl_list = res.decode('ascii').split()
#    print(rsl_list)
    return rsl_list[26]


def main():
    cam = input('В каком свитче и порту ищем? (например 62.1.2: ')
    cam = cam.strip()
    l_cam = cam.split('.')
    ip = f'10.100.{l_cam[0]}.{l_cam[1]}'
    port = f'{l_cam[2]}'
    print(ask_sw_port(ip, port))
    print(pythonping.ping(f'192.{cam}'))


if __name__ == '__main__':
    main()
