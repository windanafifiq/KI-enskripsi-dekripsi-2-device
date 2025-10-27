import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import threading

# Key yang sama untuk server dan client (8 byte untuk DES)
SHARED_KEY = b'12345678'

def encrypt(message):
    """Enkripsi pesan menggunakan DES-CBC"""
    cipher = DES.new(SHARED_KEY, DES.MODE_CBC)
    padded_message = pad(message.encode('utf-8'), DES.block_size)
    encrypted_data = cipher.encrypt(padded_message)
    return cipher.iv + encrypted_data  # IV + ciphertext

def decrypt(data):
    """Dekripsi pesan menggunakan DES-CBC"""
    try:
        iv = data[:8]  # 8 byte pertama adalah IV
        ciphertext = data[8:]  # Sisanya adalah ciphertext
        cipher = DES.new(SHARED_KEY, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, DES.block_size).decode('utf-8')
    except ValueError as e:
        return f"[ERROR] Padding incorrect: {e}"
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
            
            print(f"\n[RECEIVED] Encrypted data from server:")
            print(f"  Hex: {encrypted_data.hex()}")
            
            decrypted_message = decrypt(encrypted_data)
            print(f"[DECRYPTED] Message: {decrypted_message}")
            
        except Exception as e:
            print(f"\n[ERROR] Receiving: {e}")
            break

def send_messages(client_socket):
    """Thread untuk mengirim pesan ke server"""
    print("\n[THREAD] Started sending thread")
    while True:
        try:
            message = input("\n[CLIENT] Enter message to send (or 'quit' to exit): ")
            if message.lower() == 'quit':
                print("[INFO] Closing connection...")
                break
            
            encrypted_message = encrypt(message)
            client_socket.sendall(encrypted_message)
            print(f"[SENT] Encrypted message:")
            print(f"  Hex: {encrypted_message.hex()}")
            
        except Exception as e:
            print(f"\n[ERROR] Sending: {e}")
            break

def main():
    # Setup socket client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print("="*60)
    print("🔐 CLIENT - DES Encrypted Communication (2-Way)")
    print("="*60)
    print(f"Shared Key: {SHARED_KEY.decode()}")
    print("Connecting to server at 127.0.0.1:12345...")
    print("="*60)
    
    try:
        client_socket.connect(('127.0.0.1', 12345))
        print("\n✅ Connected to server!")
        print("="*60)
        
        # Buat thread untuk receive dan send
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
        send_thread = threading.Thread(target=send_messages, args=(client_socket,), daemon=True)
        
        receive_thread.start()
        send_thread.start()
        
        # Tunggu thread send selesai (ketika user ketik 'quit')
        send_thread.join()
        
    except Exception as e:
        print(f"\n[ERROR] Connection failed: {e}")
    finally:
        # Tutup koneksi
        client_socket.close()
        print("\n[INFO] Client stopped.")

if __name__ == "__main__":
    main()