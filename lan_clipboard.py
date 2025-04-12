import tkinter as tk
from tkinter import ttk, filedialog
import socket
import threading
import json
from cryptography.fernet import Fernet, InvalidToken
from base64 import b64encode, b64decode
import ipaddress
import pyperclip
import os
import struct
import sys
import atexit
import time
import sv_ttk
from zeroconf import ServiceInfo, ServiceBrowser, Zeroconf, IPVersion

class ZeroconfListener:
    def __init__(self, app_instance):
        self.app = app_instance

    def remove_service(self, zeroconf, type, name):
        if not self.app.running:
            return
            
        print(f"Service {name} removed")
        info = zeroconf.get_service_info(type, name)
        ip_address = None
        if info and info.addresses:
            ip_address = socket.inet_ntoa(info.addresses[0])
            
        if ip_address:
            self.app.remove_discovered_device(name, ip_address)
        else:
            self.app.remove_discovered_device_by_name(name)

    def add_service(self, zeroconf, type, name):
        if not self.app.running:
            return
            
        info = zeroconf.get_service_info(type, name)
        print(f"Service {name} added, service info: {info}")
        if info:
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            ip_address = None
            for addr in addresses:
                try:
                    if ipaddress.ip_address(addr) in self.app.network:
                        ip_address = addr
                        break
                except:
                    continue
            
            if not ip_address and addresses:
                 ip_address = addresses[0]

            if ip_address and ip_address != self.app.local_ip:
                hostname = info.properties.get(b'hostname', name.split('.')[0]).decode('utf-8')
                self.app.add_discovered_device(hostname, ip_address, name)
                
    def update_service(self, zeroconf, type, name):
        self.add_service(zeroconf, type, name)

class LANClipboard:
    DEFAULT_KEYWORD = "LANClipboard2024"

    def __init__(self):
        self.window = tk.Tk()
        self.window.title("LAN Clipboard")
        self.window.geometry("800x600")
        
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            theme_path = os.path.join(sys._MEIPASS, 'sv_ttk')
            self.window.tk.call('lappend', 'auto_path', theme_path)
        
        sv_ttk.set_theme("light")
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        try:
            self.window.iconbitmap("clipboard.ico")
        except Exception as e:
            print(f"Icon file not found: {e}")
        
        self.window.resizable(True, True)
        
        self.main_frame = ttk.Frame(self.window, padding=(20, 20))
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(
            self.main_frame,
            text="LAN Clipboard",
            font=('Segoe UI', 14, 'bold')
        )
        title_label.pack(pady=(0, 20))
        
        content_area = ttk.Frame(self.main_frame)
        content_area.pack(fill=tk.BOTH, expand=True)

        self.left_panel = ttk.Frame(content_area, padding=(0, 0, 10, 0))
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.right_panel = ttk.Frame(content_area)
        self.right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.connection_frame = ttk.LabelFrame(self.left_panel, text="Connection", padding=(10, 5))
        self.connection_frame.pack(fill=tk.X, pady=(0, 10))

        connection_status_frame = ttk.Frame(self.connection_frame)
        connection_status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.connection_indicator = ttk.Label(
            connection_status_frame,
            text="●",
            font=('Segoe UI', 14)
        )
        self.connection_indicator.pack(side=tk.LEFT, padx=(0, 5))

        self.connection_status = ttk.Label(
            connection_status_frame,
            text="Not Connected"
        )
        self.connection_status.pack(side=tk.LEFT, padx=5)

        devices_frame = ttk.Frame(self.connection_frame)
        devices_frame.pack(fill=tk.X, padx=5, pady=(10, 5))

        self.devices_label = ttk.Label(
            devices_frame,
            text="Available Devices:"
        )
        self.devices_label.pack(side=tk.LEFT, padx=(0, 5))

        self.devices_combo = ttk.Combobox(
            devices_frame,
            state='readonly'
        )
        self.devices_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.devices_combo.bind('<<ComboboxSelected>>', self.on_device_select)

        key_frame = ttk.LabelFrame(self.left_panel, text="Encryption", padding=(10, 5))
        key_frame.pack(fill=tk.X, pady=(0, 10))

        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.pack(fill=tk.X, padx=5, pady=(5, 0))

        self.key_entry = ttk.Entry(key_entry_frame, show="*")
        self.key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        key_buttons_frame = ttk.Frame(key_entry_frame)
        key_buttons_frame.pack(side=tk.LEFT, padx=(5, 0))

        ttk.Button(
            key_buttons_frame, 
            text="Set Key",
            command=self.update_encryption_key
        ).pack(side=tk.LEFT, padx=(0,2))

        self.generate_key_button = ttk.Button(
            key_buttons_frame,
            text="Generate Key",
            command=self.handle_generate_or_share_key_button
        )
        self.generate_key_button.pack(side=tk.LEFT, padx=2)
        
        self.key_prompt_label = ttk.Label(
             key_frame, 
             text="⚠️ Set a unique key to prevent others using this application from sending unwanted data", 
             foreground="orange", 
             font=('Segoe UI', 8)
        )

        ttk.Frame(self.left_panel).pack(fill=tk.BOTH, expand=True) 

        text_frame = ttk.LabelFrame(self.right_panel, text="Content", padding=(10, 5))
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_area_frame = ttk.Frame(text_frame)
        text_area_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_area = tk.Text(
            text_area_frame,
            height=10,
            width=40,
            font=('Segoe UI', 10),
            relief="flat",
            borderwidth=1,
            padx=5,
            pady=5,
            wrap=tk.WORD
        )
        text_scrollbar = ttk.Scrollbar(text_area_frame, orient=tk.VERTICAL, command=self.text_area.yview)
        self.text_area.configure(yscrollcommand=text_scrollbar.set)
        
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        clipboard_frame = ttk.Frame(text_frame)
        clipboard_frame.pack(fill=tk.X, padx=5, pady=5)

        self.copy_button = ttk.Button(
            clipboard_frame,
            text="📝 Copy",
            command=self.copy_to_clipboard
        )
        self.copy_button.pack(side=tk.LEFT, padx=2)

        self.paste_button = ttk.Button(
            clipboard_frame,
            text="📥 Paste",
            command=self.paste_from_clipboard
        )
        self.paste_button.pack(side=tk.LEFT, padx=2)

        self.clear_button = ttk.Button(
            clipboard_frame,
            text="🗑️ Clear",
            command=self.clear_text
        )
        self.clear_button.pack(side=tk.LEFT, padx=2)
        
        ttk.Frame(clipboard_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        share_frame = ttk.Frame(text_frame)
        share_frame.pack(fill=tk.X, padx=5, pady=5)

        self.send_button = ttk.Button(
            share_frame,
            text="📤 Share Text",
            command=self.share_text
        )
        self.send_button.pack(side=tk.LEFT, padx=2)

        self.file_button = ttk.Button(
            share_frame,
            text="📁 Share File",
            command=self.share_file
        )
        self.file_button.pack(side=tk.LEFT, padx=2)
        
        ttk.Frame(share_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        history_outer_frame = ttk.LabelFrame(self.right_panel, text="History", padding=(10, 5))
        history_outer_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.history_combo = ttk.Combobox(
            history_outer_frame,
            state='readonly'
        )
        self.history_combo.pack(padx=5, pady=5, expand=True, fill=tk.X)
        self.history_combo.bind('<<ComboboxSelected>>', self.load_history)

        bottom_frame = ttk.Frame(self.main_frame, padding=(0, 10, 0, 0))
        bottom_frame.pack(fill=tk.X)

        status_progress_frame = ttk.Frame(bottom_frame)
        status_progress_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.status_label = ttk.Label(
            status_progress_frame,
            text="Ready",
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)

        self.progress_bar = ttk.Progressbar(
            status_progress_frame,
            orient='horizontal',
            mode='determinate'
        )

        controls_frame = ttk.Frame(bottom_frame)
        controls_frame.pack(side=tk.RIGHT, padx=5)

        self.settings_button = ttk.Button(
            controls_frame,
            text="⚙️ Settings",
            command=self.open_settings
        )
        self.settings_button.pack(side=tk.LEFT, padx=2)

        self.help_button = ttk.Button(
            controls_frame,
            text="❓ Help",
            command=self.show_help
        )
        self.help_button.pack(side=tk.LEFT, padx=2)

        self.local_ip = self.get_local_ip()
        self.hostname = socket.gethostname()
        try:
            self.network = ipaddress.ip_network(f"{self.local_ip}/255.255.255.0", strict=False)
        except Exception as e:
            print(f"Error determining network: {e}. Using default 192.168.1.0/24")
            self.network = ipaddress.ip_network("192.168.1.0/24")
        
        self.active_devices = {}
        
        self.HOST = '0.0.0.0'
        self.PORT = 5000
        self.server_socket = None
        self.listen_thread = None
        self.cipher_suite = None
        self.using_default_key = True
        self.is_key_generated_for_sharing = False

        self.running = True
        self.threads = []

        self.zeroconf = None
        self.service_browser = None
        self.service_info = None
        self.SERVICE_TYPE = "_lanclipboard._tcp.local."
        self.service_name = f"{self.hostname}.{self.SERVICE_TYPE}"

        self.setup_encryption()
        self.setup_network()
        self.setup_zeroconf()

        self.history = []
        self.max_history = 10
        
        self.add_discovered_device(self.hostname, self.local_ip, self.service_name, is_self=True)
        self.devices_combo.set(f"{self.hostname} (This PC) - {self.local_ip}")
        self.update_status(local=True)

        atexit.register(self.cleanup_resources)

        if self.using_default_key:
            self.key_prompt_label.pack(fill=tk.X, padx=5, pady=(0, 5))

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

    def setup_encryption(self):
        """Setup encryption with a default keyword"""
        try:
            key = self.keyword_to_key(self.DEFAULT_KEYWORD)
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
        """Setup network services with better resource management"""
        try:
            self.HOST = '0.0.0.0'
            self.PORT = 5000
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.HOST, self.PORT))
            self.server_socket.listen()
            self.server_socket.settimeout(1)

            self.listen_thread = threading.Thread(target=self.listen_for_connections, name="TCPListener", daemon=True)
            self.threads = [self.listen_thread]
            self.listen_thread.start()

        except Exception as e:
            print(f"Network setup error: {e}")
            self.status_label.config(text="Network setup failed")

    def listen_for_connections(self):
        """Listen for incoming connections with improved efficiency and safer attribute access"""
        if not hasattr(self, 'running') or not self.running:
            print("Listen thread not starting due to running flag")
            return
            
        connection_errors = 0
        max_errors = 5
        
        while hasattr(self, 'running') and self.running:
            try:
                try:
                    client_socket, address = self.server_socket.accept()
                    connection_errors = 0
                except socket.timeout:
                    time.sleep(0.01)
                    continue
                except Exception as e:
                    connection_errors += 1
                    if hasattr(self, 'running') and self.running and connection_errors < max_errors:
                        print(f"Accept error: {e}")
                    if connection_errors >= max_errors:
                        time.sleep(1)
                    continue

                client_socket.settimeout(10)
                
                client_thread = threading.Thread(
                    target=self.handle_client_connection,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()

            except Exception as e:
                if hasattr(self, 'running') and self.running:
                    print(f"Listen error: {str(e)}")
                    time.sleep(0.5)
                    
    def handle_client_connection(self, client_socket, address):
        """Handle incoming connections, supporting text and chunked file transfers."""
        
        transfer_state = {
            'file_name': None,
            'file_size': 0,
            'chunk_size': 0,
            'received_chunks': 0,
            'total_chunks': 0,
            'file_data': [],
            'output_path': None,
            'cancelled': False
        }
        success = False
        is_file_transfer = False

        try:
            while hasattr(self, 'running') and self.running:
            
                if is_file_transfer and transfer_state['cancelled']:
                    print(f"User cancelled save for {transfer_state['file_name']}, closing connection.")
                    break
                    
                # 1. Read packet length (4 bytes)
                length_prefix = client_socket.recv(4)
                if not length_prefix or len(length_prefix) < 4:
                    if is_file_transfer and transfer_state['received_chunks'] < transfer_state['total_chunks']:
                        print(f"Connection closed prematurely during file transfer from {address[0]}")
                        self.update_ui(lambda: self.status_label.config(text="Error: Transfer interrupted"))
                    elif not is_file_transfer and len(length_prefix) > 0:
                        print(f"Received incomplete length prefix from {address[0]}")
                    break

                packet_length = struct.unpack("!I", length_prefix)[0]
                print(f"Expecting packet of size {packet_length} from {address[0]}")
                
                # 2. Read the actual packet data
                packet_data = b""
                bytes_received = 0
                while bytes_received < packet_length:
                    bytes_to_read = min(65536, packet_length - bytes_received)
                    chunk = client_socket.recv(bytes_to_read)
                    if not chunk:
                        raise ConnectionAbortedError(f"Connection closed while reading packet body from {address[0]}")
                    packet_data += chunk
                    bytes_received += len(chunk)
                
                if bytes_received != packet_length:
                     raise IOError(f"Packet size mismatch: Expected {packet_length}, got {bytes_received}")

                # 3. Decrypt and Decode JSON
                try:
                    decrypted_data = self.cipher_suite.decrypt(packet_data)
                    json_data = json.loads(decrypted_data.decode())
                except InvalidToken:
                    print(f"Decryption failed (Invalid Token/Key) from {address[0]}")
                    self.update_ui(lambda: self.status_label.config(text="Error: Decryption failed (check key)."))
                    break
                except json.JSONDecodeError:
                    print(f"Invalid JSON received from {address[0]}")
                    self.update_ui(lambda: self.status_label.config(text="Error: Invalid data format."))
                    break
                except Exception as e:
                    print(f"Error decrypting/decoding packet: {e}")
                    self.update_ui(lambda: self.status_label.config(text="Error: Could not process packet."))
                    break

                # 4. Process Packet based on Type
                packet_type = json_data.get("type")

                if packet_type == "text":
                    if is_file_transfer:
                        print("Warning: Received text packet during file transfer. Ignoring.")
                        continue
                    text = json_data.get("text", "")
                    self.update_ui(lambda: self.display_received_text(text))
                    success = True
                    break 

                elif packet_type == "file_start":
                    is_file_transfer = True
                    transfer_state['file_name'] = json_data.get("name", "unknown_file")
                    transfer_state['file_size'] = json_data.get("size", 0)
                    transfer_state['chunk_size'] = json_data.get("chunk_size", 512 * 1024)
                    transfer_state['total_chunks'] = (transfer_state['file_size'] + transfer_state['chunk_size'] - 1) // transfer_state['chunk_size']
                    transfer_state['received_chunks'] = 0
                    transfer_state['file_data'] = []
                    transfer_state['cancelled'] = False
                    transfer_state['output_path'] = None
                    print(f"Received file_start: {transfer_state['file_name']} ({transfer_state['file_size']} bytes, {transfer_state['total_chunks']} chunks)")
                    
                    dialog_done_event = threading.Event()
                    
                    self.update_ui(lambda: self.prompt_save_location(transfer_state, dialog_done_event)) 
                    
                    print("Waiting for save dialog...")
                    dialog_completed = dialog_done_event.wait(timeout=300.0)
                    print(f"Save dialog wait finished. Completed: {dialog_completed}")
                    
                    if not dialog_completed:
                         print("Save dialog timed out. Assuming cancellation.")
                         transfer_state['cancelled'] = True
                         
                    if transfer_state['cancelled']:
                         print("Save prompt cancelled or timed out, stopping receiver.")
                         self.update_ui(lambda: self.status_label.config(text="File receive cancelled/timed out."))
                         self.update_ui(self.hide_progress_bar)
                         break
                         
                    self.update_ui(lambda: self.status_label.config(text=f"Receiving: {transfer_state['file_name']}..."))
                    self.update_ui(self.show_progress_bar)
                    self.update_ui(lambda: self.progress_bar.config(maximum=transfer_state['total_chunks'], value=0))

                elif packet_type == "file_chunk":
                    if not is_file_transfer:
                         print("Warning: Received file_chunk without file_start. Ignoring.")
                         continue
                         
                    seq = json_data.get("seq", -1)
                    chunk_b64 = json_data.get("data", "")
                    
                    if seq != transfer_state['received_chunks'] + 1:
                         print(f"Warning: Out-of-order chunk received. Expected {transfer_state['received_chunks']+1}, got {seq}. Discarding.")
                         continue 
                         
                    try:
                        chunk_data = b64decode(chunk_b64)
                        transfer_state['file_data'].append(chunk_data)
                        transfer_state['received_chunks'] = seq
                        
                        progress = transfer_state['received_chunks']
                        total = transfer_state['total_chunks']
                        self.update_ui(lambda: self.progress_bar.config(value=progress))
                        self.update_ui(lambda: self.status_label.config(
                            text=f"Receiving chunk {progress}/{total} of {transfer_state['file_name']}"))
                    except Exception as e:
                        print(f"Error decoding/appending chunk {seq}: {e}")
                        break
                        
                elif packet_type == "file_end":
                    if not is_file_transfer:
                         print("Warning: Received file_end without file_start. Ignoring.")
                         continue
                         
                    end_seq = json_data.get("seq", -1)
                    if end_seq == transfer_state['received_chunks'] and end_seq == transfer_state['total_chunks']:
                        print(f"Received file_end for {transfer_state['file_name']}. Total chunks: {end_seq}")
                        if transfer_state['output_path']:
                             self.update_ui(lambda: self.assemble_and_save_file(transfer_state))
                             success = True
                        else:
                            print("File receive complete but no save path selected.")
                            self.update_ui(lambda: self.status_label.config(text="Save cancelled."))
                        break
                    else:
                        print(f"Error: file_end sequence mismatch. Expected {transfer_state['received_chunks']}, got {end_seq}")
                        self.update_ui(lambda: self.status_label.config(text="Error: File transfer incomplete."))
                        break
                        
                elif packet_type == "file_error":
                     error_msg = json_data.get("message", "Unknown error from sender")
                     print(f"Received file_error from {address[0]}: {error_msg}")
                     self.update_ui(lambda: self.status_label.config(text=f"Error from sender: {error_msg}"))
                     break
                     
                else:
                    print(f"Received unknown packet type: {packet_type}")
                    if "text" in json_data:
                         self.update_ui(lambda: self.display_received_text(json_data["text"]))
                         success = True
                    break
                    
        except ConnectionAbortedError as e:
             print(f"Client connection aborted: {e}")
             if is_file_transfer:
                  self.update_ui(lambda: self.status_label.config(text="Error: Transfer interrupted"))
        except socket.error as e:
            print(f"Socket error during receive loop from {address[0]}: {e}")
            if is_file_transfer:
                 self.update_ui(lambda: self.status_label.config(text="Error: Network error during transfer"))
        except Exception as e:
            print(f"Unexpected error in connection handler from {address[0]}: {e}")
            import traceback
            traceback.print_exc()
            if is_file_transfer:
                 self.update_ui(lambda: self.status_label.config(text="Error: Unexpected error during transfer"))
        finally:
            if is_file_transfer:
                self.update_ui(self.hide_progress_bar)
                if not success and "Error" in self.status_label.cget("text"):
                     self.update_ui(lambda: self.window.after(3000, lambda: self.status_label.config(text="Ready"))) 
            try:
                client_socket.close()
            except:
                pass

    def prompt_save_location(self, transfer_state, done_event):
        """Ask the user where to save the incoming file (runs on UI thread) and signals completion."""
        file_name = transfer_state['file_name']
        save_path = None
        try:
            save_path = filedialog.asksaveasfilename(
                parent=self.window,
                title=f"Save Incoming File: {file_name}",
                defaultextension=os.path.splitext(file_name)[1] or ".*",
                initialfile=file_name
            )
            if save_path:
                transfer_state['output_path'] = save_path
                transfer_state['cancelled'] = False
                print(f"User chose save path: {save_path}")
            else:
                transfer_state['output_path'] = None
                transfer_state['cancelled'] = True
                print("User cancelled save prompt.")
                self.status_label.config(text="File receive cancelled.")
                self.hide_progress_bar()
        except Exception as e:
             print(f"Error during save dialog: {e}")
             transfer_state['output_path'] = None
             transfer_state['cancelled'] = True
             self.status_label.config(text="Error showing save dialog.")
             self.hide_progress_bar()
        finally:
            print("Signalling dialog completion.")
            done_event.set() 

    def assemble_and_save_file(self, transfer_state):
        """Assemble file chunks and save to the chosen path (runs on UI thread)."""
        file_name = transfer_state['file_name']
        save_path = transfer_state['output_path']
        file_data_chunks = transfer_state['file_data']
        
        if not save_path:
            print("Save cancelled, not assembling file.")
            return

        try:
            self.status_label.config(text=f"Assembling {file_name}...")
            self.window.update_idletasks()
            
            print(f"Assembling {len(file_data_chunks)} chunks for {file_name}")
            full_data = b"".join(file_data_chunks)
            
            if transfer_state['file_size'] > 0 and len(full_data) != transfer_state['file_size']:
                 print(f"Warning: Assembled size mismatch! Expected {transfer_state['file_size']}, got {len(full_data)}")
                 self.status_label.config(text=f"Warning: Size mismatch for {file_name}")
                 self.window.after(2000, lambda: self.status_label.config(text=f"Saving {os.path.basename(save_path)}..."))
            else:
                 self.status_label.config(text=f"Saving {os.path.basename(save_path)}...")
                 
            self.window.update_idletasks()

            print(f"Saving assembled file ({len(full_data)} bytes) to {save_path}")
            with open(save_path, 'wb') as f:
                f.write(full_data)
                
            print(f"File saved successfully: {save_path}")
            self.status_label.config(text=f"File '{os.path.basename(save_path)}' received successfully")

        except Exception as e:
            error_msg = f"Error saving assembled file '{file_name}': {str(e)}"
            print(error_msg)
            self.status_label.config(text=f"Error saving {os.path.basename(save_path)}")
        finally:
            self.hide_progress_bar()

    def display_received_text(self, text):
        """Display received text in the UI thread"""
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert("1.0", text)
        self.add_to_history(text)
        self.status_label.config(text="Received text successfully")
        
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
        """Initiates sharing a file with the selected device using chunked transfer."""
        if not self.devices_combo.get():
            self.status_label.config(text="Please select a device")
            return

        selected = self.devices_combo.get()
        try:
            target_ip = selected.split(' - ')[-1]
            ipaddress.ip_address(target_ip)
        except (IndexError, ValueError) as e:
            print(f"Error extracting IP from selection '{selected}': {e}")
            self.status_label.config(text="Invalid device selected")
            return
            
        if target_ip == self.local_ip:
             self.status_label.config(text="Cannot share file with yourself")
             return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.set_share_buttons_state(tk.DISABLED)
        self.show_progress_bar()

        transfer_thread = threading.Thread(
            target=self._share_file_chunked,
            args=(file_path, target_ip, selected.split(' - ')[0]),
            daemon=True,
            name="FileTransferSend"
        )
        transfer_thread.start()
        
    def _share_file_chunked(self, file_path, target_ip, target_hostname):
        """Handles the actual chunked file sending logic in a background thread."""
        CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
        client_socket = None
        file_size = 0
        file_name = ""
        success = False

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            self.update_ui(lambda: self.status_label.config(text=f"Connecting to {target_hostname}..."))
            self.update_ui(lambda: self.progress_bar.config(maximum=total_chunks, value=0))
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((target_ip, self.PORT))
            print(f"Connected to {target_ip} for chunked file transfer.")

            # 1. Send Start Packet
            start_packet = {
                "type": "file_start",
                "name": file_name,
                "size": file_size,
                "chunk_size": CHUNK_SIZE
            }
            self.send_packet(client_socket, start_packet)
            print("Sent file_start packet")
            self.update_ui(lambda: self.status_label.config(text=f"Starting send: {file_name}..."))

            # 2. Send Data Chunks
            sent_chunks = 0
            with open(file_path, 'rb') as f:
                while True:
                    chunk_data = f.read(CHUNK_SIZE)
                    if not chunk_data:
                        break
                    
                    sent_chunks += 1
                    chunk_packet = {
                        "type": "file_chunk",
                        "seq": sent_chunks,
                        "data": b64encode(chunk_data).decode()
                    }
                    self.send_packet(client_socket, chunk_packet)
                    
                    progress = sent_chunks
                    self.update_ui(lambda: self.progress_bar.config(value=progress))
                    self.update_ui(lambda: self.status_label.config(
                        text=f"Sending chunk {progress}/{total_chunks} of {file_name}"))
            
            # 3. Send End Packet
            if not success and sent_chunks == total_chunks:
                end_packet = {"type": "file_end", "seq": total_chunks}
                self.send_packet(client_socket, end_packet)
                print(f"Sent file_end packet for {file_name}")
                self.update_ui(lambda: self.status_label.config(text=f"File '{file_name}' sent successfully"))
                success = True
            elif not success:
                 raise IOError(f"Chunk count mismatch: Sent {sent_chunks}, Expected {total_chunks}")

        except FileNotFoundError:
            self.update_ui(lambda: self.status_label.config(text="Error: File not found."))
            print(f"File share error: File not found at {file_path}")
        except socket.timeout:
            self.update_ui(lambda: self.status_label.config(text="Error: Connection timed out."))
            print(f"File share error: Connection to {target_ip} timed out")
        except (socket.error, ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            self.update_ui(lambda: self.status_label.config(text=f"Connection Error: Receiver likely cancelled or disconnected."))
            print(f"File share error: Socket error - {e}")
        except Exception as e:
            self.update_ui(lambda: self.status_label.config(text=f"Error sharing file: {type(e).__name__}"))
            print(f"File share error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if client_socket:
                try:
                    client_socket.close()
                    print("Chunked file transfer socket closed.")
                except Exception as e:
                    print(f"Error closing client socket: {e}")
            
            self.update_ui(lambda: self.set_share_buttons_state(tk.NORMAL))
            self.update_ui(self.hide_progress_bar)
            if not success:
                self.update_ui(lambda: self.window.after(3000, lambda: self.status_label.config(text="Ready"))) 
                
    def send_packet(self, sock, packet_data):
        """Helper to encrypt and send a JSON packet."""
        try:
            json_string = json.dumps(packet_data)
            encrypted_data = self.cipher_suite.encrypt(json_string.encode())
            length_prefix = struct.pack("!I", len(encrypted_data))
            sock.sendall(length_prefix + encrypted_data)
        except Exception as e:
             print(f"Error in send_packet: {e}")
             raise
             
    def update_ui(self, callback):
        """Safely schedule a UI update from a background thread."""
        try:
             self.window.after(0, callback)
        except tk.TclError:
             print("UI update failed, window might be closing.")
             
    def set_share_buttons_state(self, state):
        """Enable/disable sharing buttons."""
        self.send_button.config(state=state)
        self.file_button.config(state=state)
        
    def show_progress_bar(self):
        """Make the progress bar visible."""
        self.progress_bar.pack(fill=tk.X, pady=(5, 0)) 
        self.progress_bar['value'] = 0
        
    def hide_progress_bar(self):
        """Hide the progress bar."""
        self.progress_bar.pack_forget()

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

    def update_encryption_key(self):
        try:
            keyword = self.key_entry.get()
            if not keyword:
                self.status_label.config(text="Please enter a keyword")
                return
            
            if self.is_key_generated_for_sharing:
                self.generate_key_button.config(text="Generate Key")
                self.is_key_generated_for_sharing = False
            
            if keyword == self.DEFAULT_KEYWORD:
                 self.status_label.config(text="⚠️ Using default key. Set a unique one!")
                 if not self.using_default_key:
                     self.using_default_key = True
                     self.key_prompt_label.pack(fill=tk.X, padx=5, pady=(0, 5))
            else:
                 if self.using_default_key:
                      self.using_default_key = False
                      self.key_prompt_label.pack_forget()
                 self.status_label.config(text="Encryption key updated successfully")
            
            key = self.keyword_to_key(keyword)
            self.cipher_suite = Fernet(key)
            self.key_entry.delete(0, tk.END)
        except Exception as e:
            self.status_label.config(text="Invalid keyword format")
            print(f"Key update error: {e}")

    def handle_generate_or_share_key_button(self):
        """Handles clicks on the Generate/Share Key button based on state."""
        if self.is_key_generated_for_sharing:
            self.share_generated_key_via_content()
        else:
            self.generate_new_key()
            
    def generate_new_key(self):
        """Generate a new Fernet key, insert it, and change button state."""
        try:
            new_key = Fernet.generate_key()
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, new_key.decode())
            self.status_label.config(text="Key generated. Click 'Share Key' to send.")
            self.generate_key_button.config(text="Share Key")
            self.is_key_generated_for_sharing = True
        except Exception as e:
            self.status_label.config(text="Error generating key")
            print(f"Key generation error: {e}")
            
    def share_generated_key_via_content(self):
        """Sends the key currently in the key_entry field as text content."""
        key_to_share = self.key_entry.get()
        if not key_to_share:
            self.status_label.config(text="No key in field to share.")
            return

        if not self.devices_combo.get():
            self.status_label.config(text="Please select a device to share the key with")
            return
            
        target_ip = ""
        selected = ""
        try:
            selected = self.devices_combo.get()
            target_ip = selected.split(' - ')[-1]
            ipaddress.ip_address(target_ip)
        except (IndexError, ValueError) as e:
            print(f"Error extracting IP from selection '{selected}': {e}")
            self.status_label.config(text="Invalid device selected")
            return
            
        if target_ip == self.local_ip:
             self.status_label.config(text="Cannot share key with yourself")
             return
             
        share_thread = threading.Thread(
            target=self._send_key_text_thread,
            args=(key_to_share, target_ip, selected.split(' - ')[0]),
            daemon=True
        )
        share_thread.start()

    def _send_key_text_thread(self, key_text, target_ip, target_hostname):
        """Background thread function to send the key as text."""
        client_socket = None
        success = False
        self.update_ui(lambda: self.connection_indicator.config(foreground='orange'))
        self.update_ui(lambda: self.connection_status.config(text="Sending Key..."))
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)
            client_socket.connect((target_ip, self.PORT))
            
            text_packet = {"type": "text", "text": key_text}
            self.send_packet(client_socket, text_packet)
            print(f"Sent key as text packet to {target_ip}")
            success = True
            
        except socket.timeout:
            error_msg = "Error: Connection timed out while sending key."
            print(f"Share key error: Connection to {target_ip} timed out")
            self.update_ui(lambda: self.status_label.config(text=error_msg))
            self.update_ui(lambda: self.update_status(connected=False))
        except socket.error as e:
             error_msg = f"Error: Connection failed ({e.strerror})"
             print(f"Share key error: Socket error - {e}")
             self.update_ui(lambda: self.status_label.config(text=error_msg))
             self.update_ui(lambda: self.update_status(connected=False))
        except Exception as e:
            error_msg = "Error sharing key"
            print(f"Share key error: {str(e)}")
            self.update_ui(lambda: self.status_label.config(text=error_msg))
            self.update_ui(lambda: self.update_status(connected=False))
        finally:
            if client_socket:
                  try: client_socket.close() 
                  except: pass
            self.update_ui(lambda: self.generate_key_button.config(text="Generate Key"))
            self.is_key_generated_for_sharing = False
            if success:
                 success_msg = f"Key sent to {target_hostname}. They must set it manually."
                 self.update_ui(lambda: self.status_label.config(text=success_msg))
                 self.update_ui(lambda: self.update_status(connected=True))
            else:
                 self.update_ui(lambda: self.window.after(3000, lambda: self.check_connections()))

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
        """Show a structured help dialog."""
        help_dialog = tk.Toplevel(self.window)
        help_dialog.title("Help - LAN Clipboard")
        help_dialog.resizable(False, False)
        
        help_frame = ttk.Frame(help_dialog, padding=20)
        help_frame.pack(fill=tk.BOTH, expand=True)

        # --- Help Sections --- 
        sections = [
            ("Connection", 
             "• Select a device from the 'Available Devices' dropdown.\n"
             "• Status: ● (Green: Connected), ● (Red: Not Connected), ● (Blue: Local).\n"
             "• Devices are discovered automatically on your LAN."),
            
            ("Sharing",
             "• Type or paste into the 'Content' area.\n"
             "• Click 'Share Text' to send text to the selected device.\n"
             "• Click 'Share File' to send a file.\n"
             "• Requires the same encryption key on both devices."),

            ("Clipboard & History",
             "• '📝 Copy': Copies text area content to system clipboard.\n"
             "• '📥 Paste': Pastes from system clipboard into text area.\n"
             "• '🗑️ Clear': Empties the text area.\n"
             "• 'History': Dropdown of recent text snippets."),
             
            ("Encryption",
             "• ⚠️ IMPORTANT: Set a unique key using 'Set Key' or 'Generate Key'!\n"
             "• Using the default key is insecure.\n"
             "• Both sender and receiver MUST use the exact same key keyword.\n"
             "• Use 'Generate Key', then 'Share Key' to send the new key via text to the other device. The recipient must copy the received key and use 'Set Key'.\n"
             "• If you forget your key, you can always generate and share a new one.")
        ]

        for title, text in sections:
            title_label = ttk.Label(help_frame, text=title, font=('Segoe UI', 10, 'bold'))
            title_label.pack(fill=tk.X, pady=(10, 2))
            
            if title == "Connection":
                status_frame = ttk.Frame(help_frame)
                status_frame.pack(fill=tk.X)
                
                line1, line2, line3 = text.split('\n')
                ttk.Label(status_frame, text=line1, justify=tk.LEFT).pack(anchor=tk.W)
                
                status_line_frame = ttk.Frame(status_frame)
                status_line_frame.pack(fill=tk.X)
                ttk.Label(status_line_frame, text="• Status: ").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text="●", foreground="green").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text=" (Connected), ").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text="●", foreground="red").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text=" (Not Connected), ").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text="●", foreground="blue").pack(side=tk.LEFT)
                ttk.Label(status_line_frame, text=" (Local).").pack(side=tk.LEFT)
                
                ttk.Label(status_frame, text=line3, justify=tk.LEFT).pack(anchor=tk.W)
            else:
                content_label = ttk.Label(
                    help_frame,
                    text=text,
                    justify=tk.LEFT,
                    wraplength=360
                )
                content_label.pack(fill=tk.X, padx=5)
            
        # --- Separator and OK Button --- 
        ttk.Separator(help_frame, orient='horizontal').pack(fill=tk.X, pady=(15, 10))
        
        ok_button = ttk.Button(help_frame, text="OK", command=help_dialog.destroy, style='Accent.TButton')
        ok_button.pack(pady=(5, 0))

        help_dialog.transient(self.window)
        help_dialog.grab_set()
        self.window.wait_window(help_dialog)

    def check_connections(self):
        """Check connection status with the currently selected device."""
        if not self.devices_combo.get():
            self.update_status(connected=False)
            return
            
        try:
            selected = self.devices_combo.get()
            target_ip = selected.split(' - ')[-1]
            
            if target_ip == self.local_ip:
                self.update_status(connected=True, local=True)
            else:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(0.5)
                result = test_socket.connect_ex((target_ip, self.PORT))
                test_socket.close()
                self.update_status(connected=(result == 0))
                
        except Exception as e:
            print(f"Connection check error: {e}")
            self.update_status(connected=False)

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
        if not text:
            return
            
        client_socket = None
        try:
            selected = self.devices_combo.get()
            try:
                target_ip = selected.split(' - ')[-1]
                ipaddress.ip_address(target_ip)
            except (IndexError, ValueError) as e:
                print(f"Error extracting IP from selection '{selected}': {e}")
                self.status_label.config(text="Invalid device selected")
                return
            
            if target_ip == self.local_ip:
                 self.status_label.config(text="Cannot share text with yourself")
                 return

            self.connection_indicator.config(foreground='orange')
            self.connection_status.config(text="Sending...")
            self.window.update_idletasks()
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)
            client_socket.connect((target_ip, self.PORT))
            
            text_packet = {"type": "text", "text": text}
            
            self.send_packet(client_socket, text_packet)
            print(f"Sent text packet to {target_ip}")
            
            client_socket.close()
            client_socket = None
            
            self.status_label.config(text=f"Text shared with {selected.split(' - ')[0]}")
            self.update_status(connected=True)
            self.add_to_history(text)
            
        except socket.timeout:
            self.status_label.config(text="Error: Connection timed out.")
            self.update_status(connected=False)
            print(f"Share text error: Connection to {target_ip} timed out")
        except socket.error as e:
             self.status_label.config(text=f"Error: Connection failed ({e.strerror})")
             self.update_status(connected=False)
             print(f"Share text error: Socket error - {e}")
        except Exception as e:
            self.status_label.config(text="Error sharing text")
            self.update_status(connected=False)
            print(f"Share error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
             if client_socket:
                  try: client_socket.close() 
                  except: pass
             if "Error" in self.status_label.cget("text") or "failed" in self.status_label.cget("text"):
                  self.window.after(3000, lambda: self.check_connections())

    def cleanup_resources(self):
        """Clean up resources before exit, including Zeroconf."""
        print("Cleaning up resources...")
        
        if hasattr(self, 'running'):
            self.running = False
        
        # --- Zeroconf Cleanup --- 
        if hasattr(self, 'zeroconf') and self.zeroconf:
            print("Closing Zeroconf...")
            try:
                if self.service_info:
                    print("Unregistering service...")
                    self.zeroconf.unregister_service(self.service_info)
            except Exception as e:
                 print(f"Error unregistering Zeroconf service: {e}")
                 
            try:
                 self.zeroconf.close()
                 print("Zeroconf closed.")
            except Exception as e:
                print(f"Error closing Zeroconf: {e}")
        # ------------------------

        if hasattr(self, 'server_socket') and self.server_socket:
            try:
                self.server_socket.close()
                print("Server socket closed")
            except Exception as e:
                print(f"Error closing server socket: {e}")

        if hasattr(self, 'listen_thread') and self.listen_thread:
            try:
                if self.listen_thread.is_alive():
                    print(f"Waiting for thread {self.listen_thread.name} to finish...")
                    self.listen_thread.join(timeout=1)
            except Exception as e:
                print(f"Error joining thread {self.listen_thread.name}: {e}")
                    
        print("Cleanup completed")

    def on_closing(self):
        """Handle window closing event"""
        self.cleanup_resources()
        self.window.destroy()

    def setup_zeroconf(self):
        """Initialize Zeroconf, start browsing and advertising services."""
        try:
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
            
            properties = {
                'hostname': self.hostname.encode('utf-8')
            }
            self.service_info = ServiceInfo(
                self.SERVICE_TYPE,
                self.service_name,
                addresses=[socket.inet_aton(self.local_ip)],
                port=self.PORT,
                properties=properties,
            )
            print(f"Registering service: {self.service_info}")
            self.zeroconf.register_service(self.service_info)
            
            listener = ZeroconfListener(self)
            self.service_browser = ServiceBrowser(self.zeroconf, self.SERVICE_TYPE, listener)
            print("Started Zeroconf browser")
            self.status_label.config(text="Ready (Zeroconf Active)")
        except Exception as e:
            print(f"!!! Zeroconf Error: {e}")
            self.status_label.config(text="Error: Zeroconf failed to start")
            if self.zeroconf:
                self.zeroconf.close()
            self.zeroconf = None

    def add_discovered_device(self, hostname, ip, service_name, is_self=False):
        """Safely add discovered device to the dictionary."""
        if service_name in self.active_devices:
            if self.active_devices[service_name][1] != ip:
                print(f"Updating IP for {hostname}: {ip}")
                self.active_devices[service_name] = (hostname, ip)
                self.window.after(0, self.update_device_list)
            return
            
        print(f"Adding device: {hostname} ({ip}) - Service: {service_name}")
        self.active_devices[service_name] = (hostname, ip)
        self.window.after(0, self.update_device_list)

    def remove_discovered_device(self, service_name, ip):
        """Safely remove a discovered device by service name and IP."""
        if service_name in self.active_devices and self.active_devices[service_name][1] == ip:
            print(f"Removing device (IP match): {self.active_devices[service_name][0]} ({ip}) - Service: {service_name}")
            del self.active_devices[service_name]
            self.window.after(0, self.update_device_list)
            
    def remove_discovered_device_by_name(self, service_name):
        """Safely remove a discovered device by service name only (fallback)."""
        if service_name in self.active_devices:
            hostname, ip = self.active_devices[service_name]
            print(f"Removing device (Name match): {hostname} ({ip}) - Service: {service_name}")
            del self.active_devices[service_name]
            self.window.after(0, self.update_device_list)

    def update_device_list(self):
        """Update the devices combo box from the active_devices dictionary."""
        try:
            current_selection = self.devices_combo.get()
            current_values = self.devices_combo['values']
            
            values = []
            for service_name, (hostname, ip) in self.active_devices.items():
                if ip == self.local_ip:
                    values.append(f"{hostname} (This PC) - {ip}")
                else:
                    values.append(f"{hostname} - {ip}")
            
            values.sort(key=lambda x: " (This PC)" not in x)
            
            self.devices_combo['values'] = values
            
            if current_selection in values:
                self.devices_combo.set(current_selection)
            elif f"{self.hostname} (This PC) - {self.local_ip}" in values:
                 self.devices_combo.set(f"{self.hostname} (This PC) - {self.local_ip}")
                 self.update_status(local=True)
            elif values:
                self.devices_combo.set(values[0])
                self.on_device_select(None)
            else:
                 self.devices_combo.set("")
                 self.update_status(connected=False)
                 
            if self.devices_combo.get() != current_selection and current_selection in current_values:
                 self.on_device_select(None)
                 
        except Exception as e:
            print(f"Error updating device list: {e}")
            try:
                self.devices_combo['values'] = []
                self.devices_combo.set("")
            except: pass

    def on_device_select(self, event):
        """Handle device selection changes in the combobox."""
        self.check_connections()

class SettingsDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Settings")
        self.dialog.geometry("300x200")
        self.dialog.resizable(False, False)
        
        try:
            sv_ttk.set_theme("light")
        except:
            pass
            
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        history_frame = ttk.Frame(main_frame)
        history_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(history_frame, text="Max History Items:").pack(side=tk.LEFT)
        self.history_var = tk.StringVar(value="10")
        ttk.Entry(history_frame, textvariable=self.history_var, width=5).pack(side=tk.LEFT, padx=5)
        
        clear_frame = ttk.Frame(main_frame)
        clear_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(clear_frame, text="Auto-Clear After Send:").pack(side=tk.LEFT)
        self.auto_clear = tk.BooleanVar()
        ttk.Checkbutton(clear_frame, variable=self.auto_clear).pack(side=tk.LEFT, padx=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Frame(button_frame).pack(side=tk.LEFT, expand=True)
        
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT)

    def save_settings(self):
        print(f"Max History: {self.history_var.get()}")
        print(f"Auto Clear: {self.auto_clear.get()}")
        self.dialog.destroy() 
        
if __name__ == "__main__":
    app = LANClipboard()
    app.run()