import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import threading
import hmac, hashlib
import time

# Shared secrets (same as client)
SHARED_KEY = b'12345678'       # 8 bytes for DES
HMAC_KEY = b'secret_hmac_key'  # same for both sides

# Store active clients: {id: conn}
clients = {}
lock = threading.Lock()


def encrypt(message):
    """Encrypt message with DES-CBC and add HMAC"""
    cipher = DES.new(SHARED_KEY, DES.MODE_CBC)
    padded_message = pad(message.encode('utf-8'), DES.block_size)
    encrypted_data = cipher.encrypt(padded_message)

    # Create HMAC tag (integrity protection)
    tag = hmac.new(HMAC_KEY, cipher.iv + encrypted_data, hashlib.sha256).digest()
    return cipher.iv + encrypted_data + tag  # IV + ciphertext + HMAC


def decrypt(data):
    """Decrypt message and verify HMAC"""
    try:
        iv = data[:8]
        tag = data[-32:]
        ciphertext = data[8:-32]

        calc_tag = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, calc_tag):
            return "[ERROR] HMAC verification failed!"

        cipher = DES.new(SHARED_KEY, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, DES.block_size).decode('utf-8')
    except Exception as e:
        return f"[ERROR] Decryption failed: {e}"



def receive_messages(conn, addr):
    """Handle incoming messages from a specific client"""
    client_id = addr[1]
    while True:
        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                print(f"[INFO] Client {client_id} disconnected.")
                with lock:
                    if client_id in clients:
                        del clients[client_id]
                break

            decrypted_message = decrypt(encrypted_data)
            print(f"\n[FROM {client_id}] {decrypted_message}")
        except Exception as e:
            print(f"[ERROR] Receiving from {client_id}: {e}")
            break


def handle_client(conn, addr):
    """Start receive thread when a new client connects"""
    client_id = addr[1]  # use port as ID
    with lock:
        clients[client_id] = conn
    print(f"\n✅ New client connected: ID={client_id}, Addr={addr}")

    threading.Thread(target=receive_messages, args=(conn, addr), daemon=True).start()


def send_to_selected_client():
    """Allow server operator to choose target client and send messages"""
    while True:
        try:
            with lock:
                print("\nConnected clients:")
                for cid in clients.keys():
                    print(f"  - ID: {cid}")

            target_id = input("\nEnter device ID (or 'quit' to exit): ").strip()
            if target_id.lower() == 'quit':
                print("[INFO] Shutting down server...")
                with lock:
                    for conn in clients.values():
                        conn.close()
                    clients.clear()
                break

            if not target_id.isdigit() or int(target_id) not in clients:
                print("[WARN] Invalid ID.")
                continue

            target_id = int(target_id)
            message = input(f"Enter message for {target_id}: ")

            encrypted_message = encrypt(f"[SERVER to {target_id}]: {message}")
            with lock:
                conn = clients.get(target_id)
                if conn:
                    conn.sendall(encrypted_message)
                    print(f"[SENT] To {target_id}: {message}")
                else:
                    print(f"[WARN] Client {target_id} not found (disconnected).")

        except Exception as e:
            print(f"[ERROR] Sending: {e}")
            time.sleep(1)


# ==============================
# 🚀 Main server loop
# ==============================
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)

    print("="*60)
    print("🔐 SERVER - Multi-Client DES + HMAC Chat")
    print("="*60)
    print(f"Shared Key: {SHARED_KEY.decode()}")
    print("Listening on port 12345...")
    print("="*60)

    # Start input thread
    threading.Thread(target=send_to_selected_client, daemon=True).start()

    # Accept clients forever
    while True:
        conn, addr = server_socket.accept()
        handle_client(conn, addr)


if __name__ == "__main__":
    main()
