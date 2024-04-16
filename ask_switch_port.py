import telnetlib


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
    return rsl_list[26]


def main():
    cam = input('В каом свитче ищем?: ')
    l_cam = cam.split('.')
    ip = f'10.100.{l_cam[0]}.{l_cam[1]}'
    port = f'{l_cam[2]}'
    print(ask_sw_port(ip, port))


if __name__ == '__main__':
    main()
