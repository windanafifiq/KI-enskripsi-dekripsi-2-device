import socket
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import threading
import hmac, hashlib
import time

# Store active clients: {id: {'conn': conn, 'des_key': key, 'hmac_key': key}}
clients = {}
lock = threading.Lock()


def encrypt(message, des_key, hmac_key):
    """Encrypt message with DES-CBC and add HMAC (using session keys)"""
    try:
        cipher = DES.new(des_key, DES.MODE_CBC)
        padded_message = pad(message.encode('utf-8'), DES.block_size)
        encrypted_data = cipher.encrypt(padded_message)
        tag = hmac.new(hmac_key, cipher.iv + encrypted_data, hashlib.sha256).digest()
        return cipher.iv + encrypted_data + tag
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None


def decrypt(data, des_key, hmac_key):
    """Decrypt message and verify HMAC (using session keys)"""
    try:
        iv = data[:8]
        tag = data[-32:]
        ciphertext = data[8:-32]

        calc_tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, calc_tag):
            return "[ERROR] HMAC verification failed!"

        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, DES.block_size).decode('utf-8')
    except Exception as e:
        return f"[ERROR] Decryption failed: {e}"


def handle_client_message(client_id, conn, des_key, hmac_key, decrypted_message):
    """
    Handles the logic for a decrypted message.
    Either relay to another client, send a list, or return an error.
    """
    global clients
    global lock

    # 1. Handle 'list' command
    if decrypted_message.lower() == 'list':
        with lock:
            all_ids = [str(cid) for cid in clients.keys()]
            id_list = ", ".join(all_ids)
            response = f"[SERVER] Connected IDs: {id_list}"
        
        # Send the list back to the sender
        encrypted_response = encrypt(response, des_key, hmac_key)
        conn.sendall(encrypted_response)
        print(f"[LOG] Client {client_id} requested list.")

    # 2. Handle client-to-client message (format: [ID]:[message])
    elif ":" in decrypted_message:
        try:
            target_id_str, message_body = decrypted_message.split(":", 1)
            target_id = int(target_id_str)

            if target_id == client_id:
                response = "[SERVER] Error: Cannot send message to yourself."
                encrypted_response = encrypt(response, des_key, hmac_key)
                conn.sendall(encrypted_response)
                return

            # Format message to be relayed
            relay_message = f"[FROM {client_id}]: {message_body}"
            
            # Find target client and their keys
            target_conn = None
            target_des = None
            target_hmac = None
            
            with lock:
                target_data = clients.get(target_id)
                if target_data:
                    target_conn = target_data['conn']
                    target_des = target_data['des_key']
                    target_hmac = target_data['hmac_key']
            
            # If target exists, encrypt with *their* keys and send
            if target_conn:
                encrypted_relay = encrypt(relay_message, target_des, target_hmac)
                target_conn.sendall(encrypted_relay)
                print(f"[LOG] Relayed message from {client_id} to {target_id}")
            else:
                # Target not found, send error back to sender
                response = f"[SERVER] Error: Client {target_id} not found."
                encrypted_response = encrypt(response, des_key, hmac_key)
                conn.sendall(encrypted_response)
                print(f"[LOG] Client {client_id} tried to reach non-existent {target_id}")

        except Exception as e:
            # Bad format, send error back to sender
            response = f"[SERVER] Error: Invalid message format. {e}"
            encrypted_response = encrypt(response, des_key, hmac_key)
            conn.sendall(encrypted_response)
            
    # 3. Handle invalid format
    else:
        response = "[SERVER] Invalid command. Use 'list' or '[ID]:[message]'."
        encrypted_response = encrypt(response, des_key, hmac_key)
        conn.sendall(encrypted_response)


def receive_messages(client_id, conn, des_key, hmac_key):
    """Handle incoming messages from a specific client"""
    while True:
        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                print(f"[INFO] Client {client_id} disconnected.")
                with lock:
                    if client_id in clients:
                        del clients[client_id]
                break

            decrypted_message = decrypt(encrypted_data, des_key, hmac_key)
            if "ERROR" in decrypted_message:
                print(f"[WARN] Decryption error from {client_id}: {decrypted_message}")
                continue

            # Server tidak lagi 'print' pesan, tapi memprosesnya
            # print(f"\n[FROM {client_id}] {decrypted_message}") <-- DIHAPUS
            
            # Serahkan ke fungsi relay
            handle_client_message(client_id, conn, des_key, hmac_key, decrypted_message)

        except Exception as e:
            print(f"[ERROR] Receiving from {client_id}: {e}")
            with lock:
                if client_id in clients:
                    del clients[client_id]
            break


def handle_client(conn, addr, rsa_key_pair):
    """
    Handle new client:
    1. Send RSA Public Key
    2. Receive encrypted session keys
    3. Decrypt session keys
    4. Store keys and start receive thread
    """
    client_id = addr[1]
    print(f"\n[INFO] New connection attempt from {addr}")

    try:
        # 1. Kirim Kunci Public RSA
        public_key = rsa_key_pair.publickey().export_key()
        conn.sendall(public_key)

        # 2. Terima bundel kunci sesi terenkripsi
        encrypted_session_keys = conn.recv(256)
        if not encrypted_session_keys:
            print(f"[WARN] Client {client_id} disconnected before key exchange.")
            conn.close()
            return
            
        # 3. Dekripsi bundel kunci sesi
        cipher_rsa = PKCS1_OAEP.new(rsa_key_pair)
        session_keys = cipher_rsa.decrypt(encrypted_session_keys)
        
        session_des_key = session_keys[:8]
        session_hmac_key = session_keys[8:]
        
        # 4. Simpan koneksi dan kunci sesi klien
        with lock:
            clients[client_id] = {
                'conn': conn,
                'des_key': session_des_key,
                'hmac_key': session_hmac_key
            }
        
        print(f"✅ Client {client_id} connected. Session keys established securely.")

        # Mulai thread untuk menerima pesan dari klien ini
        threading.Thread(target=receive_messages, 
                         args=(client_id, conn, session_des_key, session_hmac_key), 
                         daemon=True).start()

    except Exception as e:
        print(f"[ERROR] Key exchange failed for {client_id}: {e}")
        conn.close()


# ==============================
# 🚀 Main server loop
# ==============================
def main():
    print("Generating RSA key pair (2048 bits)...")
    rsa_key_pair = RSA.generate(2048)
    print("✅ RSA key pair generated.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)

    print("="*60)
    print("🔐 SERVER - Client-to-Client Relay (via RSA Key Exchange)")
    print("="*60)
    print("Listening on port 12345... (Server is a silent bridge)")
    print("="*60)

    # FUNGSI send_to_selected_client() DIHAPUS. Server tidak bisa memulai chat.
    # threading.Thread(target=send_to_selected_client, daemon=True).start() <-- DIHAPUS

    try:
        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr, rsa_key_pair)
    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()