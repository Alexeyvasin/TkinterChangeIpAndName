# config.py
from dataclasses import dataclass
from typing import Tuple

@dataclass
class NetworkConfig:
    RANGE_START: str = "10.100.2.0"
    RANGE_STOP: str = "10.100.70.16"
    NET_MASK: str = "255.0.0.0"
    GATEWAY: str = "192.168.1.1"
    DEFAULT_AUTH: str = "admin:admin"
    BROADCAST_PORT: int = 6011
    LISTEN_PORT: int = 6010
    DEFAULT_IP: str = "192.168.1.188"
    
    @property
    def auth_credentials(self) -> Tuple[str, str]:
        username, password = self.DEFAULT_AUTH.split(':')
        return username, password

# models.py
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Device:
    ip: str
    mac: str
    name: Optional[str] = None
    is_default: bool = True

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "name": self.name
        }

# network_scanner.py
import socket
import re
from pythonping import ping
from typing import List
from threading import Event
from time import sleep

class NetworkScanner:
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.found_devices: List[Device] = []
        self.stop_event = Event()
        
    def scan_range(self) -> List[str]:
        found_switches = []
        cur_ip = self.config.RANGE_START
        
        while cur_ip != self.config.RANGE_STOP and not self.stop_event.is_set():
            if ping(cur_ip, count=1, timeout=0.02).success():
                found_switches.append(cur_ip)
            
            # Generate next IP
            ip_parts = [int(x) for x in cur_ip.split('.')]
            if ip_parts[2] >= 100:
                break
                
            if ip_parts[3] >= 20:
                ip_parts[2] += 1
                ip_parts[3] = 1
            else:
                ip_parts[3] += 1
                
            cur_ip = '.'.join(str(x) for x in ip_parts)
            
        return found_switches

    def listen_for_broadcasts(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.config.LISTEN_PORT))
        
        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(6000)
                device = self._parse_broadcast(data, addr)
                if device:
                    self._update_device_list(device)
            except Exception as e:
                print(f"Error receiving broadcast: {e}")
                sleep(0.1)
                
    def _parse_broadcast(self, data: bytes, addr: tuple) -> Optional[Device]:
        try:
            decoded = data.decode('cp1252')
            mac_match = re.search(r'TR-.+_(f0:23:..:..:..:..).+', decoded)
            name_match = re.search(r'(TR-.*)', decoded[150:162])
            
            if mac_match:
                mac = mac_match.group(1)
                return Device(
                    ip=addr[0],
                    mac=mac,
                    name=name_match.group(1) if name_match else None
                )
        except Exception as e:
            print(f"Error parsing broadcast: {e}")
        return None
        
    def _update_device_list(self, device: Device):
        for existing in self.found_devices:
            if existing.mac == device.mac:
                existing.ip = device.ip
                existing.name = device.name or existing.name
                return
        self.found_devices.append(device)

# device_manager.py
import telnetlib
import requests
from threading import Thread

class DeviceManager:
    def __init__(self, config: NetworkConfig):
        self.config = config
        
    def change_ip(self, device: Device, new_ip: str) -> bool:
        try:
            payload = self._build_ip_change_payload(device, new_ip)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            for _ in range(3):
                sock.sendto(payload, ("255.255.255.255", self.config.BROADCAST_PORT))
            return True
        except Exception as e:
            print(f"Error changing IP: {e}")
            return False
            
    def change_name(self, device: Device, new_name: str) -> bool:
        try:
            url = f"http://{self.config.DEFAULT_AUTH}@{device.ip}/action"
            
            # Get current config
            response = requests.get(f"{url}/get?subject=devpara")
            if response.status_code != 200:
                return False
                
            # Update config with new name
            config = response.text
            new_config = re.sub(r'<name>.*</name>', f'<name>{new_name}</name>', config)
            
            # Apply new config
            response = requests.post(
                f"{url}/set",
                params={"subject": "devpara"},
                headers={"Content-Type": "text/xml"},
                data=new_config
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Error changing name: {e}")
            return False
            
    def _build_ip_change_payload(self, device: Device, new_ip: str) -> bytes:
        # Implementation of the payload building logic
        # This would contain the complex logic from the original code
        pass

# gui.py
import tkinter as tk
from tkinter import ttk

class NetworkManagerGUI:
    def __init__(self, config: NetworkConfig, device_manager: DeviceManager):
        self.config = config
        self.device_manager = device_manager
        self.root = tk.Tk()
        self.setup_gui()
        
    def setup_gui(self):
        self.root.title("Network Device Manager")
        
        # Setup frames
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # IP Table
        self.ip_frame = self._create_table_frame("IP Addresses")
        self.ip_table = self._create_table(
            self.ip_frame, 
            ["IP", "MAC"], 
            ["ip", "mac"]
        )
        
        # Name Table
        self.name_frame = self._create_table_frame("Device Names")
        self.name_table = self._create_table(
            self.name_frame,
            ["IP", "Name"],
            ["ip", "name"]
        )
        
        # Controls
        self.controls_frame = ttk.Frame(self.main_frame, padding="5")
        self.controls_frame.grid(row=2, column=0, columnspan=2)
        
        self._create_controls()
        
    def _create_table_frame(self, title: str) -> ttk.Frame:
        frame = ttk.LabelFrame(self.main_frame, text=title, padding="5")
        frame.grid(sticky=(tk.W, tk.E, tk.N, tk.S))
        return frame
        
    def _create_table(self, parent: ttk.Frame, headers: List[str], columns: List[str]) -> ttk.Treeview:
        table = ttk.Treeview(parent, columns=columns, show="headings")
        
        for header, col in zip(headers, columns):
            table.heading(col, text=header)
            table.column(col, width=100)
            
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        
        table.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        return table
        
    def _create_controls(self):
        # Create input fields and buttons
        self.username_var = tk.StringVar(value=self.config.auth_credentials[0])
        self.password_var = tk.StringVar(value=self.config.auth_credentials[1])
        
        ttk.Label(self.controls_frame, text="Username:").grid(row=0, column=0)
        ttk.Entry(self.controls_frame, textvariable=self.username_var).grid(row=0, column=1)
        
        ttk.Label(self.controls_frame, text="Password:").grid(row=1, column=0)
        ttk.Entry(self.controls_frame, textvariable=self.password_var, show="*").grid(row=1, column=1)
        
        ttk.Button(self.controls_frame, text="Change IP", command=self._change_ip).grid(row=2, column=0)
        ttk.Button(self.controls_frame, text="Change Name", command=self._change_name).grid(row=2, column=1)
        
    def _change_ip(self):
        selected = self.ip_table.selection()
        if not selected:
            return
            
        item = self.ip_table.item(selected[0])
        device = Device(ip=item['values'][0], mac=item['values'][1])
        
        # Show dialog for new IP
        dialog = self._create_input_dialog("Enter new IP")
        if dialog.result:
            self.device_manager.change_ip(device, dialog.result)
            
    def _change_name(self):
        selected = self.name_table.selection()
        if not selected:
            return
            
        item = self.name_table.item(selected[0])
        device = Device(ip=item['values'][0], mac=None, name=item['values'][1])
        
        # Show dialog for new name
        dialog = self._create_input_dialog("Enter new name")
        if dialog.result:
            self.device_manager.change_name(device, dialog.result)
            
    def run(self):
        self.root.mainloop()

# main.py
def main():
    config = NetworkConfig()
    scanner = NetworkScanner(config)
    device_manager = DeviceManager(config)
    gui = NetworkManagerGUI(config, device_manager)
    
    # Start background tasks
    Thread(target=scanner.scan_range, daemon=True).start()
    Thread(target=scanner.listen_for_broadcasts, daemon=True).start()
    
    # Run GUI
    gui.run()

if __name__ == "__main__":
    main()