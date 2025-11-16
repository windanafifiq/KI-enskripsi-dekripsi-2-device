import socket
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import threading
import hmac, hashlib
import os

# Kunci sesi global untuk client ini, akan diisi setelah key exchange
SESSION_DES_KEY = None
SESSION_HMAC_KEY = None


def encrypt(message, des_key, hmac_key):
    """Enkripsi pesan menggunakan DES-CBC (using session keys)"""
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
    """Dekripsi pesan menggunakan DES-CBC (using session keys)"""
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
    """Thread untuk menerima pesan dari server"""
    print("\n[THREAD] Started receiving from server")
    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                print("\n[INFO] Connection closed by server")
                break
            
            # Gunakan session keys untuk dekripsi
            decrypted_message = decrypt(encrypted_data, SESSION_DES_KEY, SESSION_HMAC_KEY)
            
            # Tampilkan pesan dari server/klien lain
            print(f"\n{decrypted_message}")
            # Tampilkan ulang prompt input
            print(f"[CLIENT] Enter 'list' or '[ID]:[message]' ('quit'): ", end="")
            
        except Exception as e:
            print(f"\n[ERROR] Connection lost: {e}")
            print("Please type 'quit' to exit.")
            break
            
    print("[THREAD] Receive thread stopped.")


def send_messages(client_socket):
    """Thread untuk mengirim pesan ke server"""
    print("\n[THREAD] Started sending thread")
    while True:
        try:
            # Ubah prompt input
            message = input("\n[CLIENT] Enter 'list' or '[ID]:[message]' ('quit'): ")
            
            if message.lower() == 'quit':
                print("[INFO] Closing connection...")
                break
            
            if not message:
                continue

            # Gunakan session keys untuk enkripsi
            encrypted_message = encrypt(message, SESSION_DES_KEY, SESSION_HMAC_KEY)
            if encrypted_message:
                client_socket.sendall(encrypted_message)

        except Exception as e:
            print(f"\n[ERROR] Sending failed: {e}")
            print("Connection may be lost. Please type 'quit' to exit.")
            break
            
    print("[THREAD] Send thread stopped.")
    client_socket.close()

def main():
    global SESSION_DES_KEY, SESSION_HMAC_KEY
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("="*60)
    print("🔐 CLIENT - Client-to-Client Chat (via RSA Key Exchange)")
    print("="*60)
    print("Connecting to server at 127.0.0.1:12345...")
    
    try:
        client_socket.connect(('127.0.0.1', 12345))
        print("✅ Connected to server!")
        print("="*60)

        # --- RSA KEY EXCHANGE ---
        print("[KEY-EX] Receiving server's public RSA key...")
        server_public_key_data = client_socket.recv(1024)
        server_public_key = RSA.import_key(server_public_key_data)
        print("[KEY-EX] ✅ Server public key received.")

        print("[KEY-EX] Generating session keys (DES+HMAC)...")
        SESSION_DES_KEY = os.urandom(8)
        SESSION_HMAC_KEY = os.urandom(16)
        print("[KEY-EX] ✅ Session keys generated.")
        
        session_keys_bundle = SESSION_DES_KEY + SESSION_HMAC_KEY

        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        encrypted_session_keys = cipher_rsa.encrypt(session_keys_bundle)

        print("[KEY-EX] Sending encrypted session keys...")
        client_socket.sendall(encrypted_session_keys)
        print("[KEY-EX] ✅ Key exchange complete. Secure channel established.")
        print("="*60)
        print("Ketik 'list' untuk melihat klien lain.")
        print("Ketik '[ID]:[PESAN]' untuk mengirim pesan.")
        print("="*60)
        
        # --- END OF KEY EXCHANGE ---

        receive_thread = threading.Thread(target=receive_messages, 
                                          args=(client_socket,), 
                                          daemon=True)
        send_thread = threading.Thread(target=send_messages, 
                                       args=(client_socket,),
                                       daemon=False)
        
        receive_thread.start()
        send_thread.start()
        
        send_thread.join()
        
    except Exception as e:
        print(f"\n[ERROR] Connection failed: {e}")
    finally:
        client_socket.close()
        print("\n[INFO] Client stopped.")

if __name__ == "__main__":
    main()