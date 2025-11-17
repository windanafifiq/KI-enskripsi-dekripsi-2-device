import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import threading
import hmac, hashlib
import os

# Kunci sesi global
SESSION_DES_KEY = None
SESSION_HMAC_KEY = None

# ==========================================
# 🧠 IMPLEMENTASI RSA MANUAL (ENKRIPSI)
# ==========================================

def encrypt_rsa_manual(message_int, public_key):
    e, n = public_key
    # Encryption: C = M^e mod n
    return pow(message_int, e, n)

# ==========================================
# 🌐 LOGIKA CLIENT
# ==========================================

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

def receive_messages(client_socket):
    print("\n[THREAD] Started receiving from server")
    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                print("\n[INFO] Connection closed by server")
                os._exit(0) # Force exit agar prompt tidak nyangkut
            
            decrypted_message = decrypt_des(encrypted_data, SESSION_DES_KEY, SESSION_HMAC_KEY)
            print(f"\n{decrypted_message}")
            print(f"[CLIENT] Enter 'list' or '[ID]:[message]' ('quit'): ", end="")
            
        except Exception as e:
            print(f"\n[ERROR] Connection lost: {e}")
            break

def send_messages(client_socket):
    while True:
        try:
            message = input("\n[CLIENT] Enter 'list' or '[ID]:[message]' ('quit'): ")
            if message.lower() == 'quit':
                break
            if not message: continue

            encrypted_message = encrypt_des(message, SESSION_DES_KEY, SESSION_HMAC_KEY)
            if encrypted_message:
                client_socket.sendall(encrypted_message)
        except Exception as e:
            print(f"\n[ERROR] Sending failed: {e}")
            break
    client_socket.close()

def main():
    global SESSION_DES_KEY, SESSION_HMAC_KEY
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to server...")
    try:
        client_socket.connect(('127.0.0.1', 12345))
        print("✅ Connected!")

        # --- RSA KEY EXCHANGE (MANUAL) ---
        
        # 1. Terima Public Key (e, n) string
        server_pub_str = client_socket.recv(1024).decode('utf-8')
        e_str, n_str = server_pub_str.split(',')
        server_public_key = (int(e_str), int(n_str))
        print(f"[KEY-EX] ✅ Server public key received: (e={e_str}, n=...truncated...)")

        # 2. Generate Session Keys
        SESSION_DES_KEY = os.urandom(8)
        SESSION_HMAC_KEY = os.urandom(16)
        
        # Gabungkan key menjadi satu bundle bytes
        session_keys_bundle = SESSION_DES_KEY + SESSION_HMAC_KEY
        
        # 3. Ubah Bytes ke Integer agar bisa dihitung RSA
        message_int = int.from_bytes(session_keys_bundle, 'big')
        
        # Pastikan message_int < n (Syarat RSA)
        if message_int >= server_public_key[1]:
            raise ValueError("Key bundle too large for RSA modulus size!")

        # 4. Enkripsi RSA Manual: C = M^e mod n
        encrypted_int = encrypt_rsa_manual(message_int, server_public_key)
        
        # Kirim sebagai string angka (sederhana)
        client_socket.sendall(str(encrypted_int).encode('utf-8'))
        
        print("[KEY-EX] ✅ Encrypted session keys sent.")
        print("="*60)
        
        # --- END EXCHANGE ---

        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
        send_thread = threading.Thread(target=send_messages, args=(client_socket,), daemon=False)
        
        receive_thread.start()
        send_thread.start()
        send_thread.join()
        
    except Exception as e:
        print(f"\n[ERROR] Connection failed: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()