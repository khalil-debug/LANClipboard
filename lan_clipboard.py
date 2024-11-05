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

class LANClipboard:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("LAN Clipboard")
        # Increase initial window size
        self.window.geometry("800x600")  # Changed from "600x400"
        
        # Set window icon
        try:
            self.window.iconbitmap("clipboard.ico")
        except Exception as e:
            print(f"Icon file not found: {e}")
        
        # Enhanced style configuration
        style = ttk.Style()
        
        # Configure styles
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
        
        # Set window background and properties
        self.window.configure(bg="#f5f6fa")
        self.window.resizable(True, True)
        
        # Main container with padding
        self.main_frame = ttk.Frame(self.window, style='Custom.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title label
        title_label = ttk.Label(
            self.main_frame,
            text="LAN Clipboard",
            style='Custom.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        title_label.pack(pady=(0, 20))
        
        # Replace key frames with device selection
        self.devices_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.devices_frame.pack(pady=5, fill=tk.X)
        
        self.devices_label = ttk.Label(
            self.devices_frame,
            text="Available Devices:",
            style='Custom.TLabel'
        )
        self.devices_label.pack(padx=5)
        
        self.devices_combo = ttk.Combobox(
            self.devices_frame,
            width=30,
            state='readonly'
        )
        self.devices_combo.pack(padx=5, fill=tk.X, expand=True)
        
        self.refresh_button = ttk.Button(
            self.devices_frame,
            text="🔄 Refresh",
            command=self.scan_network,
            style='Custom.TButton'
        )
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # Status label with better visibility
        self.status_label = ttk.Label(
            self.main_frame,
            text="Ready to share",
            style='Custom.TLabel'
        )
        self.status_label.pack(side=tk.TOP, pady=5)
        
        # Setup multicast for auto-discovery
        self.MCAST_GRP = '224.1.1.1'
        self.MCAST_PORT = 5007
        
        self.local_ip = self.get_local_ip()
        try:
            # Get network from local IP (assuming /24 subnet)
            self.network = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
        except Exception as e:
            print(f"Network setup error: {e}")
            self.network = ipaddress.IPv4Network("192.168.1.0/24")
        
        self.active_devices = []

        # Fix encryption key setup
        self.setup_encryption()

        # Start network services after UI setup
        self.setup_network()

        # Text area with better styling
        self.text_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.text_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.text_area = tk.Text(
            self.text_frame,
            height=8,
            width=40,
            font=('Segoe UI', 10),
            relief="solid",
            borderwidth=1,
            padx=10,
            pady=10
        )
        self.text_area.pack(fill=tk.BOTH, side=tk.TOP, expand=True, padx=5)
        
        # Configure text area colors
        self.text_area.configure(
            bg="white",
            fg="black",
            selectbackground="#2980b9",
            selectforeground="white"
        )

        # Button frame for better layout
        self.button_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.button_frame.pack(pady=5, fill=tk.X)

        # Share button with improved styling
        self.send_button = ttk.Button(
            self.button_frame,
            text="📝 Share",
            command=self.share_text,
            style='Custom.TButton'
        )
        self.send_button.pack(pady=2)

        # Add clipboard buttons
        self.clipboard_frame = ttk.Frame(self.button_frame, style='Custom.TFrame')
        self.clipboard_frame.pack(fill=tk.X, pady=5)
        
        self.copy_button = ttk.Button(
            self.clipboard_frame,
            text="📝 Copy",
            command=self.copy_to_clipboard,
            style='Custom.TButton'
        )
        self.copy_button.pack(side=tk.LEFT, padx=5)
        
        self.paste_button = ttk.Button(
            self.clipboard_frame,
            text="📥 Paste",
            command=self.paste_from_clipboard,
            style='Custom.TButton'
        )
        self.paste_button.pack(side=tk.LEFT, padx=5)

        # Add the controls frame right after the file_button
        self.file_button = ttk.Button(
            self.button_frame,
            text="Share File",
            command=self.share_file,
            style='Custom.TButton'
        )
        self.file_button.pack(pady=2)  # Reduced pady from 5 to 2

        # Add controls frame HERE, immediately after file_button
        self.controls_frame = ttk.Frame(self.button_frame, style='Custom.TFrame')
        self.controls_frame.pack(fill=tk.X, pady=2)  # Reduced pady from 5 to 2

        # Settings button
        self.settings_button = ttk.Button(
            self.controls_frame,
            text="⚙️ Settings",
            command=self.open_settings,
            style='Custom.TButton',
            width=10
        )
        self.settings_button.pack(side=tk.LEFT, padx=5, expand=True)

        # Clear button
        self.clear_button = ttk.Button(
            self.controls_frame,
            text="🗑️ Clear",
            command=self.clear_text,
            style='Custom.TButton',
            width=10
        )
        self.clear_button.pack(side=tk.LEFT, padx=5, expand=True)

        # Help button
        self.help_button = ttk.Button(
            self.controls_frame,
            text="❓ Help",
            command=self.show_help,
            style='Custom.TButton',
            width=10
        )
        self.help_button.pack(side=tk.LEFT, padx=5, expand=True)

        # Move the controls_frame placement to be after the history_frame and before the key_frame
        # Add history tracking and dropdown (existing code)
        self.history = []
        self.max_history = 10
        
        # Add history dropdown
        self.history_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.history_frame.pack(fill=tk.X, pady=5)
        
        self.history_combo = ttk.Combobox(
            self.history_frame,
            width=40,
            state='readonly'
        )
        self.history_combo.pack(side=tk.LEFT, padx=5)
        self.history_combo.bind('<<ComboboxSelected>>', self.load_history)

        # Add key management
        self.key_frame = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.key_frame.pack(fill=tk.X, pady=5)

        self.key_entry = ttk.Entry(self.key_frame, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        ttk.Button(
            self.key_frame,
            text="Set Key",
            command=self.update_encryption_key,
            style='Custom.TButton'
        ).pack(side=tk.LEFT, padx=2)

        # Add Generate Key button
        ttk.Button(
            self.key_frame,
            text="Generate Key",
            command=self.generate_new_key,
            style='Custom.TButton'
        ).pack(side=tk.LEFT, padx=2)

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
        """Scan the network for active devices using optimized scanning"""
        try:
            self.status_label.config(text="Scanning network...")
            self.active_devices = []  # Reset the list
            
            # Add local machine
            self.active_devices.append(("This PC", self.local_ip))
            
            # Get subnet from local IP
            ip_parts = self.local_ip.split('.')
            subnet = '.'.join(ip_parts[:3])
            
            # Scan only common device IPs to reduce load
            common_ports = [80, 443, 8080, 5000]  # Common ports to check
            ips_to_scan = [f"{subnet}.{i}" for i in range(1, 255) if f"{subnet}.{i}" != self.local_ip]
            
            # Use ThreadPoolExecutor with limited workers
            with ThreadPoolExecutor(max_workers=20) as executor:  # Reduced from 50
                future_to_ip = {
                    executor.submit(self.check_host, ip, common_ports): ip 
                    for ip in ips_to_scan
                }
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                            except Exception:
                                hostname = f"Device ({ip})"
                            self.active_devices.append((hostname, ip))
                    except Exception:
                        continue
            
            # Update combobox
            self.devices_combo['values'] = [f"{name} - {ip}" for name, ip in self.active_devices]
            if self.devices_combo['values']:
                self.devices_combo.set(self.devices_combo['values'][0])
            
            self.status_label.config(text="Network scan complete")
        except Exception as e:
            print(f"Scan error: {str(e)}")
            self.status_label.config(text="Scan failed")

    def check_host(self, ip, ports):
        """Check if host is available by attempting to connect to common ports"""
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)  # 500ms timeout
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return True
            except:
                continue
        return False

    def setup_encryption(self):
        """Setup encryption with proper key generation"""
        try:
            self.cipher_suite = Fernet(Fernet.generate_key())
        except Exception as e:
            print(f"Encryption setup error: {e}")
            self.status_label.config(text="Encryption setup failed")
            
    def setup_network(self):
        """Setup network services"""
        try:
            # Network setup
            self.HOST = '0.0.0.0'
            self.PORT = 5000
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.HOST, self.PORT))
            self.server_socket.listen()

            # Start threads
            self.listen_thread = threading.Thread(target=self.listen_for_connections, daemon=True)
            self.listen_thread.start()

            self.scan_thread = threading.Thread(target=self.scan_network, daemon=True)
            self.scan_thread.start()

            # Start discovery service
            self.discovery_thread = threading.Thread(target=self.run_discovery_service, daemon=True)
            self.discovery_thread.start()

        except Exception as e:
            print(f"Network setup error: {e}")
            self.status_label.config(text="Network setup failed")

    def listen_for_connections(self):
        """Listen for incoming connections and handle received data"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(10)  # 10 second timeout

                # Update status to receiving
                self.window.after(0, lambda: self.connection_indicator.config(foreground='orange'))
                self.window.after(0, lambda: self.connection_status.config(text="Receiving..."))

                # Receive data
                data = b""
                while True:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        break
                    data += chunk

                if data:
                    try:
                        decrypted_data = self.cipher_suite.decrypt(data)
                        received_data = json.loads(decrypted_data.decode())

                        if received_data.get("type") == "file":
                            # Handle received file
                            file_data = b64decode(received_data["data"])
                            file_name = received_data["name"]
                            save_path = filedialog.asksaveasfilename(
                                defaultextension=os.path.splitext(file_name)[1],
                                initialfile=file_name
                            )
                            if save_path:
                                with open(save_path, 'wb') as f:
                                    f.write(file_data)
                                self.window.after(0, lambda: self.status_label.config(
                                    text=f"Received file from {address[0]}"
                                ))
                        else:
                            # Handle received text
                            self.window.after(0, lambda: self.text_area.delete("1.0", tk.END))
                            self.window.after(0, lambda: self.text_area.insert("1.0", received_data["text"]))
                            self.window.after(0, lambda: self.add_to_history(received_data["text"]))
                            self.window.after(0, lambda: self.status_label.config(
                                text=f"Received text from {address[0]}"
                            ))

                        self.window.after(0, lambda: self.update_status(connected=True))
                    except Exception as e:
                        self.window.after(0, lambda e=e: self.status_label.config(text=f"Decryption failed: {str(e)}"))
                        self.window.after(0, lambda: self.update_status(connected=False))

                client_socket.close()

            except Exception as e:
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

                # Update status
                self.connection_indicator.config(foreground='orange')
                self.connection_status.config(text="Sending file...")
                self.window.update()

                # Create connection
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(10)  # Longer timeout for files
                client_socket.connect((target_ip, self.PORT))

                # Read and send file
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    file_name = os.path.basename(file_path)

                    # Prepare data packet
                    data_packet = {
                        "type": "file",
                        "name": file_name,
                        "data": b64encode(file_data).decode()
                    }

                    # Encrypt and send
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
        """Run network discovery service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                sock.bind(('', self.MCAST_PORT))
                mreq = struct.pack("4sl", socket.inet_aton(self.MCAST_GRP), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                
                while True:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data == b"DISCOVER":
                            sock.sendto(b"AVAILABLE", addr)
                    except Exception as e:
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
            new_key = self.key_entry.get().encode()
            # Ensure key is valid Fernet key (32 url-safe base64-encoded bytes)
            padded_key = new_key + b'=' * (-len(new_key) % 4)  # Add padding if needed
            self.cipher_suite = Fernet(padded_key)
            self.status_label.config(text="Encryption key updated successfully")
            self.key_entry.delete(0, tk.END)  # Clear the entry field
        except Exception as e:
            self.status_label.config(text="Invalid encryption key format")
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
        self.window.mainloop()

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
                
                # Skip check if it's the local machine
                if target_ip == self.local_ip:
                    self.update_status(connected=True, local=True)
                else:
                    # Try to establish a test connection
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(1)
                    result = test_socket.connect_ex((target_ip, self.PORT))
                    test_socket.close()
                    
                    self.update_status(connected=(result == 0))
        except Exception as e:
            print(f"Connection check error: {e}")
            self.update_status(connected=False)
        
        # Schedule next check
        self.window.after(5000, self.check_connections)  # Check every 5 seconds

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
                # Get selected device IP
                selected = self.devices_combo.get()
                target_ip = selected.split(' - ')[-1]
                
                # Update status to sending
                self.connection_indicator.config(foreground='orange')
                self.connection_status.config(text="Sending...")
                self.window.update()
                
                # Create connection
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(5)
                client_socket.connect((target_ip, self.PORT))
                
                # Encrypt and send data
                encrypted_data = self.cipher_suite.encrypt(json.dumps({
                    "text": text
                }).encode())
                print(encrypted_data)
                client_socket.send(encrypted_data)
                client_socket.close()
                
                self.status_label.config(text=f"Text shared with {selected}")
                # Update status back to connected
                self.update_status(connected=True)
            except Exception as e:
                self.status_label.config(text="Error sharing text: Connection failed")
                self.update_status(connected=False)
                print(f"Share error: {str(e)}")

class SettingsDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Settings")
        self.dialog.geometry("300x200")
        
        # Add settings options
        ttk.Label(self.dialog, text="Max History Items:").pack(pady=5)
        self.history_var = tk.StringVar(value="10")
        ttk.Entry(self.dialog, textvariable=self.history_var).pack()
        
        ttk.Label(self.dialog, text="Auto-Clear After Send:").pack(pady=5)
        self.auto_clear = tk.BooleanVar()
        ttk.Checkbutton(self.dialog, variable=self.auto_clear).pack()
        
        ttk.Button(self.dialog, text="Save", command=self.save_settings).pack(pady=10)

    def save_settings(self):
        # Implement settings save logic
        self.dialog.destroy() 
        
if __name__ == "__main__":
    app = LANClipboard()
    app.run()