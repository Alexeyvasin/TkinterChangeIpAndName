import socket
import selectors
from time import time

from time import sleep


def sender(sock):
    for i in range(2):
        if i == 0:
            payload_hex_string = "fdfd0800a100ffffffffffff00000000000001000000"
        if i == 1:
            payload_hex_string = "fdfd1000a100ffffffffffff00000000000002000000"
        payload = bytes.fromhex(payload_hex_string)

        sock.sendto(payload, ("255.255.255.255", 62976))


def receiver(sock):
    switches = set()
    data, addr = sock.recvfrom(1024)

    while data:
        data_dec = ""
        for ch in data:
            if ch == 0:
                data_dec += '\n'
                continue
            data_dec += chr(ch)
        # print(data_dec)
        data = tuple(data_dec.split())
        switches.add((addr, data))

        # if switches == switches_next and time() - t0 > 1:
        #     break

        sleep(0.05)
        try:
            data, addr = sock.recvfrom(1024)
        except BlockingIOError:
            break

    return switches


def ss():
    sel = selectors.DefaultSelector()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:

        sock.bind(("192.0.0.133", 62992))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)

        sender(sock)

        sel.register(sock, selectors.EVENT_READ)
        while True:
            events = sel.select(timeout=0.1)

            #print(sel.get_map().values())
            if events:
                break

        for key, mask in events:
            switches = receiver(sock)

        return switches

if __name__ == "__main__":
    print(*ss(), sep="\n")
