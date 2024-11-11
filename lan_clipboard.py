import tkinter as tk
from tkinter import ttk, filedialog
import socket
import threading
import json
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import pyperclip
import os
import struct
import ctypes
import sys
import atexit

class LANClipboard:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("LAN Clipboard")
        self.window.geometry("800x600")
        
        # Add window close handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        try:
            self.window.iconbitmap("clipboard.ico")
        except Exception as e:
            print(f"Icon file not found: {e}")
        
        style = ttk.Style()
        
        style.configure('Custom.TButton', 
            padding=10,
            font=('Segoe UI', 10)
        )
        
        style.configure('Custom.TFrame',
            background="#f5f6fa"
        )
        
        style.configure('Custom.TLabel',
            background="#f5f6fa",
            font=('Segoe UI', 10),
            padding=5
        )
        
        style.configure('TLabelframe', 
            background="#f5f6fa"
        )
        
        style.configure('TLabelframe.Label', 
            background="#f5f6fa",
            font=('Segoe UI', 10, 'bold')
        )
        
        self.window.configure(bg="#f5f6fa")
        self.window.resizable(True, True)
        
        self.main_frame = ttk.Frame(self.window, style='Custom.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        title_label = ttk.Label(
            self.main_frame,
            text="LAN Clipboard",
            style='Custom.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        title_label.pack(pady=(0, 20))
        
        self.left_panel = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.right_panel = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.connection_frame = ttk.LabelFrame(self.left_panel, text="Connection", style='Custom.TFrame')
        self.connection_frame.pack(fill=tk.X, pady=(0, 10), padx=5)

        connection_status_frame = ttk.Frame(self.connection_frame, style='Custom.TFrame')
        connection_status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.connection_indicator = ttk.Label(
            connection_status_frame,
            text="●",
            style='Custom.TLabel',
            font=('Segoe UI', 14)
        )
        self.connection_indicator.pack(side=tk.LEFT, padx=5)

        self.connection_status = ttk.Label(
            connection_status_frame,
            text="Not Connected",
            style='Custom.TLabel'
        )
        self.connection_status.pack(side=tk.LEFT, padx=5)

        devices_frame = ttk.Frame(self.connection_frame, style='Custom.TFrame')
        devices_frame.pack(fill=tk.X, padx=5, pady=5)

        self.devices_label = ttk.Label(
            devices_frame,
            text="Available Devices:",
            style='Custom.TLabel'
        )
        self.devices_label.pack(side=tk.LEFT, padx=5)

        self.devices_combo = ttk.Combobox(
            devices_frame,
            width=30,
            state='readonly'
        )
        self.devices_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        self.refresh_button = ttk.Button(
            devices_frame,
            text="🔄 Refresh",
            command=self.start_scan,
            style='Custom.TButton'
        )
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        key_frame = ttk.LabelFrame(self.left_panel, text="Encryption", style='Custom.TFrame')
        key_frame.pack(fill=tk.X, pady=(0, 10), padx=5)

        self.key_entry = ttk.Entry(key_frame, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)

        key_buttons_frame = ttk.Frame(key_frame, style='Custom.TFrame')
        key_buttons_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(
            key_buttons_frame,
            text="Set Key",
            command=self.update_encryption_key,
            style='Custom.TButton'
        ).pack(side=tk.LEFT, padx=2)

        ttk.Button(
            key_buttons_frame,
            text="Generate Key",
            command=self.generate_new_key,
            style='Custom.TButton'
        ).pack(side=tk.LEFT, padx=2)

        text_frame = ttk.LabelFrame(self.right_panel, text="Content", style='Custom.TFrame')
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5)

        self.text_area = tk.Text(
            text_frame,
            height=8,
            width=40,
            font=('Segoe UI', 10),
            relief="solid",
            borderwidth=1,
            padx=10,
            pady=10
        )
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_area.configure(
            bg="white",
            fg="black",
            selectbackground="#2980b9",
            selectforeground="white"
        )

        clipboard_frame = ttk.Frame(text_frame, style='Custom.TFrame')
        clipboard_frame.pack(fill=tk.X, padx=5, pady=5)

        self.copy_button = ttk.Button(
            clipboard_frame,
            text="📝 Copy",
            command=self.copy_to_clipboard,
            style='Custom.TButton'
        )
        self.copy_button.pack(side=tk.LEFT, padx=2)

        self.paste_button = ttk.Button(
            clipboard_frame,
            text="📥 Paste",
            command=self.paste_from_clipboard,
            style='Custom.TButton'
        )
        self.paste_button.pack(side=tk.LEFT, padx=2)

        self.clear_button = ttk.Button(
            clipboard_frame,
            text="🗑️ Clear",
            command=self.clear_text,
            style='Custom.TButton'
        )
        self.clear_button.pack(side=tk.LEFT, padx=2)

        share_frame = ttk.Frame(text_frame, style='Custom.TFrame')
        share_frame.pack(fill=tk.X, padx=5, pady=5)

        self.send_button = ttk.Button(
            share_frame,
            text="📤 Share Text",
            command=self.share_text,
            style='Custom.TButton'
        )
        self.send_button.pack(side=tk.LEFT, padx=2)

        self.file_button = ttk.Button(
            share_frame,
            text="📁 Share File",
            command=self.share_file,
            style='Custom.TButton'
        )
        self.file_button.pack(side=tk.LEFT, padx=2)

        history_frame = ttk.LabelFrame(self.right_panel, text="History", style='Custom.TFrame')
        history_frame.pack(fill=tk.X, padx=5, pady=(10, 0))

        self.history_combo = ttk.Combobox(
            history_frame,
            width=40,
            state='readonly'
        )
        self.history_combo.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill=tk.X)
        self.history_combo.bind('<<ComboboxSelected>>', self.load_history)

        bottom_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        bottom_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_label = ttk.Label(
            bottom_frame,
            text="Ready to share",
            style='Custom.TLabel'
        )
        self.status_label.pack(side=tk.LEFT, padx=5)

        controls_frame = ttk.Frame(bottom_frame, style='Custom.TFrame')
        controls_frame.pack(side=tk.RIGHT, padx=5)

        self.settings_button = ttk.Button(
            controls_frame,
            text="⚙️ Settings",
            command=self.open_settings,
            style='Custom.TButton'
        )
        self.settings_button.pack(side=tk.LEFT, padx=2)

        self.help_button = ttk.Button(
            controls_frame,
            text="❓ Help",
            command=self.show_help,
            style='Custom.TButton'
        )
        self.help_button.pack(side=tk.LEFT, padx=2)

        self.MCAST_GRP = '224.1.1.1'
        self.MCAST_PORT = 5007
        
        self.local_ip = self.get_local_ip()
        try:
            self.network = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
        except Exception as e:
            print(f"Network setup error: {e}")
            self.network = ipaddress.IPv4Network("192.168.1.0/24")
        
        self.active_devices = []
        
        # Initialize network components
        self.HOST = '0.0.0.0'
        self.PORT = 5000
        self.server_socket = None
        self.listen_thread = None
        self.scan_thread = None
        self.discovery_thread = None
        self.cipher_suite = None

        self.setup_encryption()
        self.setup_network()

        self.history = []
        self.max_history = 10
        
        self.history_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.history_frame.pack(fill=tk.X, pady=5)
        
        self.history_combo = ttk.Combobox(
            self.history_frame,
            width=40,
            state='readonly'
        )
        self.history_combo.pack(side=tk.LEFT, padx=5)
        self.history_combo.bind('<<ComboboxSelected>>', self.load_history)

        self.scanning = False

        atexit.register(self.cleanup_resources)
        
        self.running = True
        self.threads = []

    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return '127.0.0.1'

    def scan_network(self):
        """Scan the network for active devices with improved error handling"""
        try:
            self.refresh_button.config(state='disabled')
            self.devices_combo.config(state='disabled')
            self.status_label.config(text="Scanning network...")
            self.window.update()
            
            self.active_devices = []
            self.active_devices.append(("This PC", self.local_ip))
            
            try:
                ip_parts = self.local_ip.split('.')
                subnet = '.'.join(ip_parts[:3])
            except Exception as e:
                print(f"Network parsing error: {e}")
                subnet = "192.168.1"
                
            try:
                batch_size = 10
                ips_to_scan = [
                    f"{subnet}.{i}" for i in range(1, 255) 
                    if f"{subnet}.{i}" != self.local_ip
                ]
                ip_batches = [
                    ips_to_scan[i:i + batch_size] 
                    for i in range(0, len(ips_to_scan), batch_size)
                ]
            except Exception as e:
                print(f"Batch creation error: {e}")
                self.handle_scan_error("Error creating scan batches")
                return

            scan_timeout = threading.Timer(10.0, self.handle_scan_timeout)
            scan_timeout.start()
            
            try:
                with ThreadPoolExecutor(max_workers=25) as executor:
                    for batch in ip_batches:
                        if not hasattr(self, 'scanning') or not self.scanning:
                            break
                            
                        future_to_ip = {
                            executor.submit(self.check_host, ip): ip 
                            for ip in batch
                        }
                        
                        for future in as_completed(future_to_ip, timeout=5):
                            ip = future_to_ip[future]
                            try:
                                result = future.result(timeout=1)
                                if result:
                                    self.add_discovered_device(ip)
                            except (TimeoutError, Exception) as e:
                                print(f"Error scanning {ip}: {e}")
                                continue
                                
            except Exception as e:
                print(f"Scanning error: {e}")
            finally:
                scan_timeout.cancel()
                self.cleanup_scan()
                
        except Exception as e:
            print(f"Fatal scan error: {e}")
            self.handle_scan_error("Scanning failed")

    def add_discovered_device(self, ip):
        """Safely add discovered device to the list"""
        try:
            socket.setdefaulttimeout(1)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = f"Device ({ip})"
                
            self.active_devices.append((hostname, ip))
            
            self.window.after(0, self.update_device_list)
        except Exception as e:
            print(f"Error adding device {ip}: {e}")

    def update_device_list(self):
        """Update the devices combo box safely"""
        try:
            values = [f"{name} - {ip}" for name, ip in self.active_devices]
            self.devices_combo['values'] = values
            if values and not self.devices_combo.get():
                self.devices_combo.set(values[0])
        except Exception as e:
            print(f"Error updating device list: {e}")

    def check_host(self, ip):
        """Check if host is available with improved error handling"""
        try:
            common_ports = [self.PORT, 80, 443, 22]
            for port in common_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.2)
                        if sock.connect_ex((ip, port)) == 0:
                            return True
                except socket.error:
                    continue
                
            try:
                if platform.system().lower() == "windows":
                    ping_cmd = ["ping", "-n", "1", "-w", "200", ip]
                else:
                    ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
                
                result = subprocess.run(
                    ping_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                return False
                
        except Exception as e:
            print(f"Host check error for {ip}: {e}")
            return False

    def handle_scan_error(self, message):
        """Handle scanning errors gracefully"""
        self.status_label.config(text=message)
        self.cleanup_scan()

    def handle_scan_timeout(self):
        """Handle scan timeout"""
        self.scanning = False
        self.window.after(0, lambda: self.status_label.config(text="Scan timed out"))
        self.cleanup_scan()

    def cleanup_scan(self):
        """Clean up after scanning"""
        self.scanning = False
        self.refresh_button.config(state='normal')
        self.devices_combo.config(state='readonly')
        
        if not self.active_devices:
            self.status_label.config(text="No devices found")
        else:
            self.status_label.config(text=f"Found {len(self.active_devices)} devices")

    def start_scan(self):
        """Start network scan with proper initialization"""
        self.scanning = True
        self.scan_network()

    def setup_encryption(self):
        """Setup encryption with a default keyword"""
        try:
            default_keyword = "LANClipboard2024"
            key = self.keyword_to_key(default_keyword)
            self.cipher_suite = Fernet(key)
        except Exception as e:
            print(f"Encryption setup error: {e}")
            self.status_label.config(text="Encryption setup failed")

    def keyword_to_key(self, keyword):
        """Convert a keyword into a valid Fernet key"""
        keyword = keyword.encode('utf-8')
        keyword = keyword * (32 // len(keyword) + 1)
        return b64encode(keyword[:32])

    def setup_network(self):
        """Setup network services with better thread management"""
        try:
            self.HOST = '0.0.0.0'
            self.PORT = 5000
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.HOST, self.PORT))
            self.server_socket.listen()
            self.server_socket.settimeout(1)  # Add timeout for clean shutdown

            # Create and track threads
            self.threads.extend([
                threading.Thread(target=self.listen_for_connections, daemon=True),
                threading.Thread(target=self.scan_network, daemon=True),
                threading.Thread(target=self.run_discovery_service, daemon=True)
            ])
            
            # Start threads
            for thread in self.threads:
                thread.start()

        except Exception as e:
            print(f"Network setup error: {e}")
            self.status_label.config(text="Network setup failed")

    def listen_for_connections(self):
        """Listen for incoming connections with clean shutdown support"""
        while self.running:
            try:
                try:
                    client_socket, address = self.server_socket.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if not shutting down
                        print(f"Accept error: {e}")
                    continue

                client_socket.settimeout(10)
                self.handle_client_connection(client_socket, address)

            except Exception as e:
                if self.running:
                    print(f"Listen error: {str(e)}")

    def copy_to_clipboard(self):
        text = self.text_area.get("1.0", tk.END).strip()
        if text:
            pyperclip.copy(text)
            self.status_label.config(text="Copied to clipboard")

    def paste_from_clipboard(self):
        text = pyperclip.paste()
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert("1.0", text)
        self.status_label.config(text="Pasted from clipboard")

    def share_file(self):
        """Share a file with the selected device"""
        if not self.devices_combo.get():
            self.status_label.config(text="Please select a device")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                selected = self.devices_combo.get()
                target_ip = selected.split(' - ')[-1]

                self.connection_indicator.config(foreground='orange')
                self.connection_status.config(text="Sending file...")
                self.window.update()

                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(10)
                client_socket.connect((target_ip, self.PORT))

                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    file_name = os.path.basename(file_path)

                    data_packet = {
                        "type": "file",
                        "name": file_name,
                        "data": b64encode(file_data).decode()
                    }

                    encrypted_data = self.cipher_suite.encrypt(json.dumps(data_packet).encode())
                    client_socket.send(encrypted_data)

                client_socket.close()
                self.status_label.config(text=f"File shared with {selected}")
                self.update_status(connected=True)

            except Exception as e:
                self.status_label.config(text=f"Error sharing file: {str(e)}")
                self.update_status(connected=False)
                print(f"File share error: {str(e)}")

    def add_to_history(self, text):
        if text not in self.history:
            self.history.insert(0, text)
            if len(self.history) > self.max_history:
                self.history.pop()
            self.history_combo['values'] = self.history
            
    def load_history(self, event):
        selected = self.history_combo.get()
        if selected:
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", selected)

    def run_discovery_service(self):
        """Run discovery service with clean shutdown support"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)  # Add timeout for clean shutdown
            
            try:
                sock.bind(('', self.MCAST_PORT))
                mreq = struct.pack("4sl", socket.inet_aton(self.MCAST_GRP), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                
                while self.running:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data == b"DISCOVER":
                            sock.sendto(b"AVAILABLE", addr)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            print(f"Discovery receive error: {e}")
                        continue
                        
            except Exception as e:
                print(f"Discovery bind error: {e}")
                
        except Exception as e:
            print(f"Discovery service error: {e}")
        finally:
            sock.close()

    def update_encryption_key(self):
        try:
            keyword = self.key_entry.get()
            if not keyword:
                self.status_label.config(text="Please enter a keyword")
                return
                
            key = self.keyword_to_key(keyword)
            self.cipher_suite = Fernet(key)
            self.status_label.config(text="Encryption key updated successfully")
            self.key_entry.delete(0, tk.END)
        except Exception as e:
            self.status_label.config(text="Invalid keyword format")
            print(f"Key update error: {e}")

    def generate_new_key(self):
        """Generate a new Fernet key and insert it into the key entry"""
        try:
            new_key = Fernet.generate_key()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, new_key.decode())
            self.status_label.config(text="New key generated")
        except Exception as e:
            self.status_label.config(text="Error generating key")
            print(f"Key generation error: {e}")

    def run(self):
        try:
            self.window.mainloop()
        finally:
            self.cleanup_resources()

    def open_settings(self):
        """Open settings dialog"""
        settings = SettingsDialog(self.window)
        self.window.wait_window(settings.dialog)

    def clear_text(self):
        """Clear the text area"""
        self.text_area.delete("1.0", tk.END)
        self.status_label.config(text="Text cleared")

    def show_help(self):
        """Show help dialog"""
        help_text = """
LAN Clipboard Help:
• Select a device from the dropdown
• Type or paste text in the text area
• Click 'Share Text' to send
• Use 'Share File' to send files
• Copy/Paste buttons for clipboard
• History shows recent shared texts
"""
        help_dialog = tk.Toplevel(self.window)
        help_dialog.title("Help")
        help_dialog.geometry("300x250")
        
        help_label = ttk.Label(
            help_dialog,
            text=help_text,
            style='Custom.TLabel',
            justify=tk.LEFT
        )
        help_label.pack(padx=20, pady=20)

    def check_connections(self):
        """Periodically check connection status with selected device"""
        try:
            if not self.devices_combo.get():
                self.update_status(connected=False)
            else:
                selected = self.devices_combo.get()
                target_ip = selected.split(' - ')[-1]
                
                if target_ip == self.local_ip:
                    self.update_status(connected=True, local=True)
                else:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1)
                    result = test_socket.connect_ex((target_ip, self.PORT))
                    test_socket.close()
                    
                    self.update_status(connected=(result == 0))
        except Exception as e:
            print(f"Connection check error: {e}")
            self.update_status(connected=False)
        
        self.window.after(5000, self.check_connections)

    def update_status(self, connected=False, local=False):
        """Update the connection status indicators"""
        if local:
            self.connection_indicator.config(foreground='blue')
            self.connection_status.config(text="Local Machine")
        elif connected:
            self.connection_indicator.config(foreground='green')
            self.connection_status.config(text="Connected")
        else:
            self.connection_indicator.config(foreground='red')
            self.connection_status.config(text="Not Connected")

    def share_text(self):
        if not self.devices_combo.get():
            self.status_label.config(text="Please select a device")
            return
            
        text = self.text_area.get("1.0", tk.END).strip()
        if text:
            try:
                selected = self.devices_combo.get()
                target_ip = selected.split(' - ')[-1]
                
                self.connection_indicator.config(foreground='orange')
                self.connection_status.config(text="Sending...")
                self.window.update()
                
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(5)
                client_socket.connect((target_ip, self.PORT))
                
                encrypted_data = self.cipher_suite.encrypt(json.dumps({
                    "text": text
                }).encode())
                print(encrypted_data)
                client_socket.send(encrypted_data)
                client_socket.close()
                
                self.status_label.config(text=f"Text shared with {selected}")
                self.update_status(connected=True)
            except Exception as e:
                self.status_label.config(text="Error sharing text: Connection failed")
                self.update_status(connected=False)
                print(f"Share error: {str(e)}")

    def cleanup_resources(self):
        """Clean up resources before exit"""
        print("Cleaning up resources...")
        self.running = False
        
        # Close server socket
        if hasattr(self, 'server_socket'):
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {e}")

        # Wait for threads to finish
        for thread in self.threads:
            try:
                thread.join(timeout=2)
            except Exception as e:
                print(f"Error joining thread: {e}")

    def on_closing(self):
        """Handle window closing event"""
        self.cleanup_resources()
        self.window.destroy()

class SettingsDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Settings")
        self.dialog.geometry("300x200")
        
        ttk.Label(self.dialog, text="Max History Items:").pack(pady=5)
        self.history_var = tk.StringVar(value="10")
        ttk.Entry(self.dialog, textvariable=self.history_var).pack()
        
        ttk.Label(self.dialog, text="Auto-Clear After Send:").pack(pady=5)
        self.auto_clear = tk.BooleanVar()
        ttk.Checkbutton(self.dialog, variable=self.auto_clear).pack()
        
        ttk.Button(self.dialog, text="Save", command=self.save_settings).pack(pady=10)

    def save_settings(self):
        self.dialog.destroy() 
        
if __name__ == "__main__":
    app = LANClipboard()
    app.run()