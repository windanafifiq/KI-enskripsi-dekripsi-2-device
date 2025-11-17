import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import threading
import hmac, hashlib
import random

# ==========================================
# 🧠 IMPLEMENTASI RSA DARI NOL (MANUAL)
# ==========================================

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
        
    if temp_phi == 1:
        return d + phi

def is_prime(num):
    if num < 2: return False
    if num == 2: return True
    if num % 2 == 0: return False
    # Tes sederhana (untuk production gunakan Miller-Rabin)
    for i in range(3, int(num**0.5) + 1, 2):
        if num % i == 0:
            return False
    return True

def generate_keypair(p, q):
    if p == q: raise ValueError("p and q cannot be equal")
        
    n = p * q
    phi = (p - 1) * (q - 1)

    # Pilih e
    e = 65537 # Standar umum
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Hitung d
    d = multiplicative_inverse(e, phi)
    
    # Return ((Public Key), (Private Key))
    return ((e, n), (d, n))

def decrypt_rsa_manual(ciphertext_int, private_key):
    d, n = private_key
    # Decryption: M = C^d mod n
    return pow(ciphertext_int, d, n)

# ==========================================
# 🌐 LOGIKA SERVER
# ==========================================

clients = {}
lock = threading.Lock()

# Fungsi Enkripsi/Dekripsi DES (Sama seperti sebelumnya)
def encrypt_des(message, des_key, hmac_key):
    try:
        cipher = DES.new(des_key, DES.MODE_CBC)
        padded_message = pad(message.encode('utf-8'), DES.block_size)
        encrypted_data = cipher.encrypt(padded_message)
        tag = hmac.new(hmac_key, cipher.iv + encrypted_data, hashlib.sha256).digest()
        return cipher.iv + encrypted_data + tag
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None

def decrypt_des(data, des_key, hmac_key):
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
    # ... (Bagian ini SAMA PERSIS dengan kode aslimu, tidak berubah) ...
    global clients
    global lock

    if decrypted_message.lower() == 'list':
        with lock:
            all_ids = [str(cid) for cid in clients.keys()]
            id_list = ", ".join(all_ids)
            response = f"[SERVER] Connected IDs: {id_list}"
        encrypted_response = encrypt_des(response, des_key, hmac_key)
        conn.sendall(encrypted_response)
        print(f"[LOG] Client {client_id} requested list.")

    elif ":" in decrypted_message:
        try:
            target_id_str, message_body = decrypted_message.split(":", 1)
            target_id = int(target_id_str)
            if target_id == client_id:
                response = "[SERVER] Error: Cannot send message to yourself."
                conn.sendall(encrypt_des(response, des_key, hmac_key))
                return
            
            relay_message = f"[FROM {client_id}]: {message_body}"
            target_conn = None
            target_des = None
            target_hmac = None
            with lock:
                target_data = clients.get(target_id)
                if target_data:
                    target_conn = target_data['conn']
                    target_des = target_data['des_key']
                    target_hmac = target_data['hmac_key']
            
            if target_conn:
                target_conn.sendall(encrypt_des(relay_message, target_des, target_hmac))
                print(f"[LOG] Relayed message from {client_id} to {target_id}")
            else:
                response = f"[SERVER] Error: Client {target_id} not found."
                conn.sendall(encrypt_des(response, des_key, hmac_key))
                print(f"[LOG] Client {client_id} tried to reach non-existent {target_id}")

        except Exception as e:
            response = f"[SERVER] Error: Invalid message format. {e}"
            conn.sendall(encrypt_des(response, des_key, hmac_key))
    else:
        response = "[SERVER] Invalid command. Use 'list' or '[ID]:[message]'."
        conn.sendall(encrypt_des(response, des_key, hmac_key))


def receive_messages(client_id, conn, des_key, hmac_key):
    while True:
        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                print(f"[INFO] Client {client_id} disconnected.")
                with lock:
                    if client_id in clients: del clients[client_id]
                break
            decrypted_message = decrypt_des(encrypted_data, des_key, hmac_key)
            if "ERROR" in decrypted_message:
                continue
            handle_client_message(client_id, conn, des_key, hmac_key, decrypted_message)
        except Exception as e:
            print(f"[ERROR] Receiving from {client_id}: {e}")
            with lock:
                if client_id in clients: del clients[client_id]
            break

def handle_client(conn, addr, public_key, private_key):
    client_id = addr[1]
    print(f"\n[INFO] New connection attempt from {addr}")

    try:
        # 1. Kirim Kunci Public RSA Manual (e, n) sebagai string
        # Format: "e,n"
        e, n = public_key
        pub_key_str = f"{e},{n}"
        conn.sendall(pub_key_str.encode('utf-8'))

        # 2. Terima Ciphertext RSA (Key Bundle) sebagai bytes string angka
        encrypted_session_keys_str = conn.recv(4096).decode('utf-8')
        if not encrypted_session_keys_str:
            conn.close()
            return
        
        encrypted_int = int(encrypted_session_keys_str)

        # 3. Dekripsi RSA Manual
        # Hasilnya adalah integer besar, kita ubah kembali ke bytes
        decrypted_int = decrypt_rsa_manual(encrypted_int, private_key)
        
        # Panjang kunci: 8 byte DES + 16 byte HMAC = 24 bytes
        # Kita convert int kembali ke 24 bytes
        session_keys = decrypted_int.to_bytes(24, 'big')
        
        session_des_key = session_keys[:8]
        session_hmac_key = session_keys[8:]
        
        # 4. Simpan koneksi
        with lock:
            clients[client_id] = {
                'conn': conn,
                'des_key': session_des_key,
                'hmac_key': session_hmac_key
            }
        
        print(f"✅ Client {client_id} connected. RSA Manual Handshake complete.")
        threading.Thread(target=receive_messages, 
                         args=(client_id, conn, session_des_key, session_hmac_key), 
                         daemon=True).start()

    except Exception as e:
        print(f"[ERROR] Key exchange failed for {client_id}: {e}")
        conn.close()

def main():
    # Generate RSA Keys Manual
    # Catatan: Ini adalah bilangan prima kecil untuk demo agar cepat.
    # Untuk keamanan nyata, gunakan library generate prime besar.
    print("Generating RSA key pair (Manual)...")
    # Prime number dummy agak besar (di dunia nyata harus random 1024-bit)
    # Contoh prime: 61, 53 (terlalu kecil untuk 24 bytes data). 
    # Kita butuh n > 2^(24*8) ~ 2^192.
    # Disini saya hardcode prime agak besar agar cukup menampung 24 bytes key
    # (Anda bisa ganti dengan generator prime jika mau full logic)
    p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    q = 115792089237316195423570985008687907853269984665640564039457584007913129639579
    
    public_key, private_key = generate_keypair(p, q)
    print(f"✅ RSA Key Generated. Modulus n size: {public_key[1].bit_length()} bits")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)

    print("="*60)
    print("🔐 SERVER - RSA MANUAL IMPLEMENTATION")
    print("="*60)

    try:
        while True:
            conn, addr = server_socket.accept()
            # Pass public & private key ke handler
            handle_client(conn, addr, public_key, private_key)
    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()