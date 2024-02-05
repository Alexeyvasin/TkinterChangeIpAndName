import re
import socket
import telnetlib
import tkinter as tk
from threading import Lock
from threading import Thread
from time import sleep
from tkinter import ttk
import requests
from pythonping import ping
from threading import Event

range_of_shwitches_start = "10.100.2.0"
range_of_shwitches_stop = "10.100.70.16"
net_mask = "255.0.0.0"
gateway = "192.168.1.1"
ips_of_switches = ("10.100.2.3", "10.100.2.1", "10.100.2.2", "10.100.11.3", "10.100.11.4",
                   "10.100.11.5", "10.100.11.6", "10.100.12.3", "10.100.12.4", "10.100.12.5", "10.100.12.6",
                   "10.100.13.3", "10.100.13.4", "10.100.13.5", "10.100.14.3", "10.100.14.4", "10.100.14.5",
                   "10.100.14.6", "10.100.14.7", "10.100.15.3","10.100.15.4", "10.100.15.5", "10.100.15.6",
                   "10.100.15.7", "10.100.15.8", "10.100.15.9", "10.100.15.10", "10.100.16.3", "10.100.16.4",
                   "10.100.16.5", "10.100.16.6", "10.100.16.7", "10.100.16.8", "10.100.16.9", "10.100.17.3",
                   "10.100.17.4", "10.100.17.5", "10.100.17.6", "10.100.17.7", "10.100.17.8", "10.100.17.9",
                   "10.100.18.3", "10.100.18.4", "10.100.18.5", "10.100.18.6", "10.100.18.7", "10.100.19.3",
                   "10.100.19.4", "10.100.19.5", "10.100.19.6", "10.100.19.7", "10.100.19.8", "10.100.20.3",
                   "10.100.20.4", "10.100.20.5", "10.100.20.6", "10.100.20.7","10.100.21.3", "10.100.21.4",
                   "10.100.21.5", "10.100.21.6", "10.100.21.7",  "10.100.21.8", "10.100.21.9", "10.100.21.10",
                   "10.100.21.11", "10.100.21.12", "10.100.95.3", "10.100.96.3", "10.100.31.1", "10.100.31.2",
                   "10.100.31.3", "10.100.31.4", "10.100.31.5", "10.100.32.1", "10.100.32.2", "10.100.32.3",
                   "10.100.32.4", "10.100.32.5", "10.100.32.6", "10.100.32.7", "10.100.32.8", "10.100.32.9",
                   "10.100.32.10", "10.100.32.11", "10.100.32.12", "10.100.32.13", "10.100.32.14", "10.100.33.3",
                   "10.100.33.4", "10.100.33.5", "10.100.33.6", "10.100.33.7", "10.100.33.8", "10.100.33.9",
                   "10.100.33.10", "10.100.33.11", "10.100.33.12", "10.100.33.13", "10.100.33.14", "10.100.33.15",
                   "10.100.33.16", "10.100.96.3", "10.100.34.1", "10.100.34.2", "10.100.34.3", "10.100.34.4",
                   "10.100.34.5", "10.100.34.6", "10.100.34.7", "10.100.34.8", "10.100.34.9", "10.100.34.10",
                   "10.100.34.11", "10.100.34.12", "10.100.34.13", "10.100.34.14", "10.100.34.15", "10.100.42.1",
                   "10.100.42.2", "10.100.51.3", "10.100.51.4", "10.100.51.5", "10.100.52.3", "10.100.52.4",
                   "10.100.52.5", "10.100.53.3", "10.100.53.4", "10.100.53.5", "10.100.54.3", "10.100.54.4",
                   "10.100.54.5", "10.100.54.6", "10.100.54.7", "10.100.55.3", "10.100.55.4", "10.100.55.5",
                   "10.100.55.6", "10.100.56.3", "10.100.56.4", "10.100.56.5", "10.100.57.3", "10.100.57.4",
                   "10.100.58.3", "10.100.58.4", "10.100.59.3", "10.100.59.4", "10.100.59.5", "10.100.60.3",
                   "10.100.62.1", "10.100.62.2", "10.100.71.3", "10.100.71.4", "10.100.71.5", "10.100.71.6",
                   "10.100.72.3", "10.100.72.4", "10.100.72.5", "10.100.72.6", "10.100.73.3", "10.100.73.4",
                   "10.100.73.5", "10.100.74.3", "10.100.74.4", "10.100.74.5", "10.100.74.6", "10.100.74.7",
                   "10.100.74.8", "10.100.74.9", "10.100.74.10", "10.100.74.11", "10.100.75.3", "10.100.75.4",
                   "10.100.75.5", "10.100.75.6", "10.100.75.7", "10.100.75.8", "10.100.75.9", "10.100.75.10",
                   "10.100.76.3", "10.100.76.4", "10.100.76.5", "10.100.76.6", "10.100.76.7", "10.100.76.8",
                   "10.100.76.9", "10.100.77.3", "10.100.77.4", "10.100.77.5", "10.100.77.6", "10.100.78.3",
                   "10.100.78.4", "10.100.78.5", "10.100.78.6", "10.100.78.7", "10.100.79.3", "10.100.79.4",
                   "10.100.79.5", "10.100.79.6", "10.100.79.7", "10.100.79.8", "10.100.81.3", "10.100.81.4",
                   "10.100.81.5", "10.100.81.6", "10.100.91.1", "10.100.91.2", "10.100.91.3", "10.100.91.4",
                   "10.100.91.5", "10.100.91.6", "10.100.91.7", "10.100.91.8", "10.100.91.9", "10.100.91.10",
                   "10.100.91.11", "10.100.91.12", "10.100.91.13", "10.100.91.14", "10.100.92.3", "10.100.92.4",
                   "10.100.92.5", "10.100.92.6", "10.100.92.7", "10.100.92.8", "10.100.92.9", "10.100.92.10",
                   "10.100.92.11", "10.100.92.12", "10.100.92.13", "10.100.92.14", "10.100.92.15", "10.100.92.16",
                   "10.100.93.1", "10.100.93.2", "10.100.93.3", "10.100.93.4", "10.100.93.5", "10.100.93.6",
                   "10.100.93.7", "10.100.93.8", "10.100.93.9", "10.100.93.10", "10.100.93.11", "10.100.93.12",
                   "10.100.93.13", "10.100.93.14", "10.100.93.15", "10.100.94.1", "10.100.94.2", "10.100.94.3",
                   "10.100.94.4", "10.100.94.5", "10.100.94.6", "10.100.94.7", "10.100.94.8", "10.100.94.9",
                   "10.100.94.10", "10.100.94.11", "10.100.94.12", "10.100.97.1", "10.100.97.2", "10.100.97.3",
                   "10.100.97.4", "10.100.97.5", "10.100.97.6")
ips_def = []  # [["def_ip", ip, mac], ...]
names_def = []
ips_for_change = []  # [[self.IP(sw), port, target_mac],...]
names_for_change = []
auth = "admin:admin"
changing_ip = []
changing_name = []
changed_scsf = False
changed_scsf_name = False
found_sw = []
found_mac = Event()
switches = []


def start_thread_for_change_name():
    global auth
    global net_mask
    global gateway
    tr_change_name = Thread(target=change_name, daemon=True)
    if button_change_name["text"] == "Change Name":
        auth = f"{entry_log.get()}:{entry_pass.get()}"
        net_mask = entry_mask.get()
        gateway = entry_getway.get()
        button_change_name["bg"] = "red"
        button_change_name["text"] = "Stop"
        tr_change_name.start()
    else:
        button_change_name["bg"] = "#ADFF2F"
        button_change_name["text"] = "Change Name"


def start_thread_for_change_ip():
    global auth
    global net_mask
    global gateway
    tr_change_ip = Thread(target=change_ip, daemon=True)
    if button_change_ip["text"] == "Change IP":
        auth = f"{entry_log.get()}:{entry_pass.get()}"
        net_mask = entry_mask.get()
        gateway = entry_getway.get()
        button_change_ip["bg"] = "red"
        button_change_ip["text"] = "Stop"
        tr_change_ip.start()
    else:
        button_change_ip["bg"] = "#ADFF2F"
        button_change_ip["text"] = "Change IP"


def change_ip():
    global changing_ip
    global changed_scsf
    global ips_def
    while button_change_ip["text"] == "Stop":
        if not ips_for_change:
            sleep(1)
            continue
        # lock.acquire()
        changing_ip = ips_for_change.pop()
        while True:
            request_for_change_ip()
            sleep(0.5)
            if changed_scsf:
                str_ch_ip = f"192.{changing_ip[0].split('.')[2]}.{changing_ip[0].split('.')[3]}.{changing_ip[1]}"
                changed_scsf = False
                for n, i in enumerate(ips_def):
                    if changing_ip and changing_ip[2] == i[2]:
                        ips_def[n][0] = "non_def_ip"
                        ips_def[n][1] = str_ch_ip
                        changing_ip = []

                break
            break
        sleep(0.1)


def change_name():
    global changing_name
    global changed_scsf_name
    global names_def
    while button_change_name["text"] == "Stop":
        if not names_for_change:
            sleep(1)
            continue
        # lock.acquire()
        changing_name = names_for_change.pop()
        while True:
            request_for_change_name()
            sleep(0.5)

            if changed_scsf_name:
                l_ch_name = changing_name[1].split('.')
                str_ch_name = f"{l_ch_name[1]}.{l_ch_name[2]}.{l_ch_name[3]}"
                changed_scsf_name = False
                for n, i in enumerate(names_def):
                    if changing_name and changing_name[2] == i[2]:
                        names_def[n][0] = "non_def_name"
                        names_def[n][2] = str_ch_name
                        changing_name = []

                break
            break
        sleep(0.1)


def request_for_change_ip():
    global auth
    ip = changing_ip[0]
    port = changing_ip[1]
    mac = changing_ip[2]
    ip_list = ip.split('.')
    new_ip = '192.' + ip_list[2] + '.' + ip_list[3] + '.' + str(port)
    prls = ['ðÞ¼ú‰Ãh\x03', 152, auth.split(':')[0], 64 - (len(auth.split(':')[0])),
            auth.split(':')[1],
            20 - (len(auth.split(':')[1])), mac, 7, '\x01', 7, new_ip, 16 - len(new_ip),
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
    for _ in range(3):
        payload_hex_string = prl.encode('cp1252').hex()
        payload = bytes.fromhex(payload_hex_string)
        sock.sendto(payload, ("255.255.255.255", 6011))
    sock.close()


def request_for_change_name():
    global changed_scsf_name
    ip = changing_name[1]
    with requests.get(f'http://admin:admin@{ip}/action/get?subject=devpara') as req:
        # check status code for response received
        # success code - 200
        if '200' in str(req):
            resp = req.content.decode()
            old_name = re.search('<name>(TR-.+)</name>', resp).groups()[0]
            new_xml = resp.replace(old_name, ip[4:])

    url = f"http://admin:admin@{ip}/action/set"
    headers = {"Accept": "*/*", "Content-Type": "text/xml;charset=utf-8", "Content-Length": "203"}
    data = new_xml
    params = {"subject": "devpara"}
    res = requests.post(url=url, headers=headers, data=data, params=params)
    if res.status_code == 200:
        changed_scsf_name = True
        pass


def creator_sw():
    global ips_def
    global auth
    global found_mac
    while True:
        for ip in ips_def:
            if "192.168.1.188" == ip[1]:
                if ip[2] in [i[2] for i in ips_for_change]:
                    continue
                for sw in ips_of_switches:
                    if found_mac.is_set():
                        break
                    if not ping(sw, count=1, timeout=0.1).success():
                        continue
                    switch = Switch(sw, auth, ip[2])
                    switches.append(switch)
                    switch.start()
                for _ in range(len(switches)):
                    swd = switches.pop()
                    del(swd)
                found_mac.clear()
            else:
                sleep(0.5)
        sleep(0.5)
    # sleep(1)


class Switch(Thread):
    def __init__(self, ip, auth_tion, target_mac):
        super().__init__()
        self.IP = ip
        self.AUTH_SW = auth_tion
        self.target_mac = target_mac
        #self.run()

    global ips_for_change

    def run(self):
        for i in range(1):
            try:
                self.search_mac_telnet(self.target_mac)
            except ConnectionError as exc:
                print("Wrong", exc)
            except EOFError as exc:
                print ("Wrong", exc)
                pass

    def search_mac_telnet(self, target_mac):
        try:
            tn = telnetlib.Telnet(self.IP)
        except TimeoutError as exc:
            print(exc)
            tn = None
            return
        tn.read_until(b"UserName:")
        user = self.AUTH_SW.strip().split(':')[0]
        password = self.AUTH_SW.strip().split(':')[1]
        tn.write(user.encode() + b"\n")
        tn.read_until(b"PassWord:")
        tn.write(password.encode() + b"\n")
        for p in range(1, 25):
            if found_mac.is_set():
                break
            tn.write(('show fdb port ' + str(p)).encode() + b'\n')
            res = tn.read_until('Priori'.encode(), timeout=0.1)
            rsl_list = res.decode('ascii').split()

            for i, s in enumerate(rsl_list):
                r = re.search(r'F0-23-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]', str(s))
                if r:
                    res2 = r
                    spl_mac = str(res2.group()).lower().split('-')
                    mac = spl_mac[0] + ':' + spl_mac[1] + ':' + spl_mac[2] + ':' + spl_mac[3] + ':' \
                          + spl_mac[4] + ':' + spl_mac[5]
                    try:
                        port = rsl_list[i + 1]
                    except IndexError as exc:
                        print(rsl_list, exc)

                    if mac == target_mac:
                        # lock.acquire()
                        ips_for_change.append((self.IP, port, target_mac))
                        found_mac.set()
                        # lock.release()
                else:
                    continue
        tn.close()


def wiretapping():
    global ips_def
    global changing_ip
    global changed_scsf

    ip_def = False
    while True:
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            # чтобы на одной машине можно было слушать тот же порт
            sock.setsockopt(socket.SOL_SOCKET, 1, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind(('', 6010))
                data, addr = sock.recvfrom(6000)
            except ConnectionError:
                data = None
                addr = None
                pass
            if changing_ip:
                str_ch_ip = f"192.{changing_ip[0].split('.')[2]}.{changing_ip[0].split('.')[3]}.{changing_ip[1]}"
                if str_ch_ip in addr:
                    changed_scsf = True
            if '192.168.1.188' in addr:
                ip_def = True
                break
            else:
                if data and addr:
                    try:
                        nonamed = re.search(r'(TR-.*)', str(data.decode('cp1252'))[150:162])
                    except UnicodeDecodeError:
                        nonamed = None
                    if nonamed:
                        name_def = True
                        # names_def.append(["name_def", addr[0], nonamed[0]])
                        break
        if ip_def:
            s = ''
            for i in data:
                s += chr(i)
            mac = re.findall('.*TR-.+_(f0:23:..:..:..:..).+', s)
            lock.acquire()
            is_mac = 0
            for i in ips_def:
                if mac and i and i[2] == mac[0]:
                    is_mac = 1
            if mac and is_mac == 0:
                ips_def.append(["def_ip", "192.168.1.188", mac[0]])
            lock.release()
            ip_def = False
        elif name_def:
            s = ''
            for i in data:
                s += chr(i)
            mac = re.findall('.*TR-.+_(f0:23:..:..:..:..).+', s)
            for_append = ["def_name", addr[0], nonamed[0], mac[0]]
            if for_append not in names_def:
                names_def.append(for_append)
                names_for_change.append(for_append)
            name_def = False


def sender():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for i in range(3):
            payload_hex_string = "f0debcfa88c30800"
            payload = bytes.fromhex(payload_hex_string)
            sock.sendto(payload, ("255.255.255.255", 6011))
        sock.close()
        sleep(1)


root = tk.Tk()
root.title("Change IP, Name")
# root.geometry("500x600")

frame_main = tk.Frame(root)
frame_main.grid(row=0, column=0, sticky="news")

tk.Label(
    frame_main,
    text="Change IP:",
    font=("Bold", 14)
).grid(row=0, column=0, )

tk.Label(
    frame_main,
    text="Change Name:",
    font=("Bold", 14)
).grid(row=0, column=1, )

frame_IP = tk.Frame(
    frame_main,
    width=300,
    height=300,
    bg="#ADFF2F",

)
frame_IP.grid(row=1, column=0, padx=10, pady=10, sticky="nesw")
table_IP = ttk.Treeview(frame_IP, columns=("ip", "mac"), show="headings")
table_IP.column("ip", width=100)
table_IP.heading("ip", text="IP")
table_IP.heading("mac", text="MAC")
table_IP.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

frame_main.columnconfigure(0, weight=1)
frame_main.rowconfigure(1, weight=1)
frame_main.columnconfigure(1, weight=1)

scroll_IP = tk.Scrollbar(frame_IP, orient=tk.VERTICAL, command=table_IP.yview)
scroll_IP.pack(side=tk.RIGHT, fill=tk.Y)

table_IP.configure(yscrollcommand=scroll_IP.set)

frame_Name = tk.Frame(
    frame_main,
    width=300,
    height=300,
    bg="red"
)
frame_Name.grid(row=1, column=1, padx=10, pady=10, sticky="news")

table_Name = ttk.Treeview(frame_Name, columns=("ip", "name"), show="headings")
table_Name.column("ip", width=100)
table_Name.heading("ip", text="IP")
table_Name.heading("name", text="Name")
table_Name.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scroll_Name = tk.Scrollbar(frame_Name, orient=tk.VERTICAL, command=table_IP.yview)
scroll_Name.pack(side=tk.RIGHT, fill=tk.Y)

table_Name.configure(yscrollcommand=scroll_Name.set)

frame_login = tk.Frame(
    frame_main,
)
frame_login.grid(row=3, column=0)

frame_mask = tk.Frame(
    frame_main,
)
frame_mask.grid(row=3, column=1)

frame_pass = tk.Frame(
    frame_main,
)
frame_pass.grid(row=4, column=0)

frame_getway = tk.Frame(
    frame_main,
)
frame_getway.grid(row=4, column=1)

label_login = tk.Label(
    frame_login,
    text="login: ",
    width=10
)
label_login.pack(side=tk.LEFT)

entry_log = tk.Entry(
    frame_login,

)
entry_log.insert(tk.END, "admin")
entry_log.pack(side=tk.RIGHT)

label_pass = tk.Label(
    frame_pass,
    text="password: ",
    width=10
)
label_pass.pack(side=tk.LEFT)

entry_pass = tk.Entry(
    frame_pass,
    show="*"
)
entry_pass.insert(tk.END, "admin")
entry_pass.pack(side=tk.RIGHT)

label_mask = tk.Label(frame_mask,
                      text="mask",
                      width=10
                      )
label_mask.pack(side=tk.LEFT)

entry_mask = tk.Entry(
    frame_mask,
)

entry_mask.insert(tk.END, "255.0.0.0")
entry_mask.pack(side=tk.RIGHT)

label_getway = tk.Label(frame_getway,
                        text="getway",
                        width=10
                        )
label_getway.pack(side=tk.LEFT)

entry_getway = tk.Entry(
    frame_getway,
)
entry_getway.insert(tk.END, "192.168.1.188")
entry_getway.pack(side=tk.RIGHT)

button_change_ip = tk.Button(
    frame_main,
    text="Change IP",
    command=start_thread_for_change_ip,
    bg="#ADFF2F"
)
button_change_ip.grid(row=5, column=0, pady=10)

button_change_name = tk.Button(
    frame_main,
    text="Change Name",
    command=start_thread_for_change_name,
    bg="#ADFF2F"
)
button_change_name.grid(row=5, column=1, pady=10)


def filler_of_table():
    while True:
        global ips_def
        global table_IP
        table_IP.delete(*table_IP.get_children())
        table_IP.tag_configure("def_ip", background="red")
        table_IP.tag_configure("non_def_ip", background="#ADFF2F")
        for row in ips_def:
            table_IP.insert(parent="", index=tk.END, values=(row[1], row[2]), tag=row[0])
        sleep(0.5)


def filler_of_table_Name():
    while True:
        global ips_def
        global table_IP
        table_Name.delete(*table_Name.get_children())
        table_Name.tag_configure("def_name", background="red")
        table_Name.tag_configure("non_def_name", background="#ADFF2F")
        for row in names_def:
            table_Name.insert(parent="", index=tk.END, values=(row[1], row[2]), tag=row[0])
        sleep(0.5)


def searche_of_switch():
    global range_of_shwitches_stop
    global range_of_shwitches_start

    def gen_sw(range_of_shwitches_start, range_of_shwitches_stop):

        range_start = [int(sw) for sw in range_of_shwitches_start.split(".")]
        range_stop = [int(sw) for sw in range_of_shwitches_stop.split(".")]

        cur_sw = range_of_shwitches_start
        yield cur_sw
        while cur_sw != range_of_shwitches_stop:
            l_cur_sw = [int(i) for i in (cur_sw.split("."))]
            if l_cur_sw[2] >= 100:
                yield "stop"
                return
            if l_cur_sw[3] >= 20:
                l_cur_sw[2], l_cur_sw[3] = l_cur_sw[2] + 1, 1
                cur_sw = ".".join([str(i) for i in l_cur_sw])
                yield cur_sw
                continue
            l_cur_sw[3] = l_cur_sw[3] + 1
            cur_sw = ".".join([str(i) for i in l_cur_sw])
            yield cur_sw
        return

    for _ in range(2):
        cur_sw = gen_sw(range_of_shwitches_start, range_of_shwitches_stop)

        for sw in cur_sw:
            if sw in found_sw: continue
            if ping(sw, count=1, timeout=0.02).success():
                found_sw.append(sw)


print(len(ips_of_switches))

lock = Lock()

tr1 = Thread(target=filler_of_table, daemon=True)
tr1.start()

tr2 = Thread(target=filler_of_table_Name, daemon=True)
tr2.start()

# tr_search_sw = Thread(target=searche_of_switch, daemon=True)
# tr_search_sw.start()

tr_wiretapping = Thread(target=wiretapping, daemon=True)
tr_wiretapping.start()

tr_senderUDP = Thread(target=sender, daemon=True)
tr_senderUDP.start()

tr_create_Sw = Thread(target=creator_sw, daemon=True)
tr_create_Sw.start()

root.mainloop()
