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

def receive_messages(conn, addr):
    """Thread untuk menerima pesan dari client"""
    print(f"\n[THREAD] Started receiving from {addr}")
    while True:
        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                print(f"\n[INFO] Connection closed by {addr}")
                break
            
            print(f"\n[RECEIVED] Encrypted data from {addr}:")
            print(f"  Hex: {encrypted_data.hex()}")
            
            decrypted_message = decrypt(encrypted_data)
            print(f"[DECRYPTED] Message: {decrypted_message}")
            
        except Exception as e:
            print(f"\n[ERROR] Receiving: {e}")
            break

def send_messages(conn):
    """Thread untuk mengirim pesan ke client"""
    print("\n[THREAD] Started sending thread")
    while True:
        try:
            message = input("\n[SERVER] Enter message to send (or 'quit' to exit): ")
            if message.lower() == 'quit':
                print("[INFO] Closing connection...")
                break
            
            encrypted_message = encrypt(message)
            conn.sendall(encrypted_message)
            print(f"[SENT] Encrypted message:")
            print(f"  Hex: {encrypted_message.hex()}")
            
        except Exception as e:
            print(f"\n[ERROR] Sending: {e}")
            break

def main():
    # Setup socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)
    
    print("="*60)
    print("🔐 SERVER - DES Encrypted Communication (2-Way)")
    print("="*60)
    print(f"Shared Key: {SHARED_KEY.decode()}")
    print("Listening on port 12345...")
    print("="*60)
    
    # Terima koneksi dari client
    conn, addr = server_socket.accept()
    print(f"\n✅ Connected by {addr}")
    print("="*60)
    
    # Buat thread untuk receive dan send
    receive_thread = threading.Thread(target=receive_messages, args=(conn, addr), daemon=True)
    send_thread = threading.Thread(target=send_messages, args=(conn,), daemon=True)
    
    receive_thread.start()
    send_thread.start()
    
    # Tunggu thread send selesai (ketika user ketik 'quit')
    send_thread.join()
    
    # Tutup koneksi
    conn.close()
    server_socket.close()
    print("\n[INFO] Server stopped.")

if __name__ == "__main__":
    main()