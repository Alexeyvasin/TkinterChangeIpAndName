from time import sleep
import socket
import pythonping
import re
from threading import Lock, Thread
import queue

lock = Lock()


def sender():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # print('*local_ip', local_ip)
        sock.bind((local_ip, 0))
        for i in range(3):
            payload_hex_string = "f0debcfa88c30800"
            payload = bytes.fromhex(payload_hex_string)
            sock.sendto(payload, ("255.255.255.255", 6011))
        sock.close()
        sleep(0.3)


def wiretapping(mac: str):

    print(mac)
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # чтобы на одной машине можно было слушать тот же порт
        sock.setsockopt(socket.SOL_SOCKET, 1, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # hostname = socket.gethostname()
        # local_ip = socket.gethostbyname(hostname)
        # print('*local_ip', local_ip)
        # sock.bind((local_ip, 0))
        try:
            sock.bind(('', 6010))
            data, addr = sock.recvfrom(6000)
            data_str = ''
            for ch in data:
                data_str += chr(ch)
        except ConnectionError as exc:
            data_str = addr = None
            print(exc)
        try:
            if data_str and mac in data_str:
                q.put((addr, data_str))
                return addr, data_str

        except UnicodeDecodeError as exc:
            print(exc)
            print(data_str)


def replace_ip(new_ip, cam_mac):
    if len(new_ip.split('.')) != 4:
        return 'Wrong IP!'
    auth = 'admin:admin'
    net_mask = '255.0.0.0'
    gateway = '192.168.1.1'

    prls = ['ðÞ¼ú‰Ãh\x03', 152, auth.split(':')[0], 64 - (len(auth.split(':')[0])),
            auth.split(':')[1],
            20 - (len(auth.split(':')[1])), cam_mac, 7, '\x01', 7, new_ip, 16 - len(new_ip),
            net_mask, 148 - len(net_mask), gateway, 440 - len(gateway)]

    prl = ''
    for i, p in enumerate(prls):
        if i % 2 == 0:
            prl += p

        else:
            for n in range(p):
                prl += chr(0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print('*local_ip', local_ip)
    sock.bind((local_ip, 0))

    for _ in range(3):
        payload_hex_string = prl.encode('cp1252').hex()
        payload = bytes.fromhex(payload_hex_string)
        print(payload)
        sock.sendto(payload, ("255.255.255.255", 6011))
    sock.close()
    return 'Done maybe!'


if __name__ == '__main__':
    q = queue.Queue()
    mac = input('Введите MAC камеры которую будем искать: ').strip()
    mac = mac.replace('-', ':')
    mac = mac.lower()
    thread_wiretapping = Thread(target=wiretapping, args=(mac,), daemon=True)
    thread_sender = Thread(target=sender, daemon=True)

    thread_wiretapping.start()
    thread_sender.start()
    thread_wiretapping.join()
    result = q.get()
    print(result)

    ip = input('На какой ip заменяем?: ').strip()
    print(replace_ip(ip, mac))
