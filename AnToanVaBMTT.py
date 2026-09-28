# 1. THUẬT TOÁN MÃ HÓA HIỆN ĐẠI: DES & AES
# - DES (Data Encryption Standard): Sử dụng khối 64-bit, khóa 56-bit. Hiện không còn an toàn.
# - AES (Advanced Encryption Standard): Sử dụng khối 128-bit, khóa 128/192/256-bit. Chuẩn mã hóa hiện đại, an toàn cao.
# Quy trình AES: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.

# Cài đặt mẫu thuật toán AES (sử dụng thư viện pycryptodome)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, time, os

def test_aes():
    key = os.urandom(16) # Khóa 128-bit
    cipher = AES.new(key, AES.MODE_CBC)
    data = b"Thong tin can bao mat voi AES"
    
    start = time.time()
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    aes_time = time.time() - start
    
    print(f"[AES] Encrypted: {ct} (Thời gian: {aes_time:.6f}s)")

# 2. THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA
# - Nguyên lý sinh cặp khóa:
#   + Chọn 2 số nguyên tố lớn p, q. Tính n = p * q và phi(n) = (p-1)*(q-1).
#   + Chọn e sao cho gcd(e, phi(n)) = 1 (Khóa công khai: (e, n)).
#   + Tính d sao cho (d * e) % phi(n) = 1 (Khóa bí mật: (d, n)).

# 3. MÔ HÌNH ỨNG DỤNG RSA VÀ SO SÁNH
# - Xác thực người gửi (Chữ ký số): Mã hóa hash bằng Private Key của người gửi.
# - Xác thực người nhận (Bảo mật): Mã hóa dữ liệu bằng Public Key của người nhận.
# - Kết hợp cả hai: Mã hóa hash bằng Private Key (Sender) + Mã hóa gói bằng Public Key (Receiver).
# - So sánh RSA vs AES: RSA tốn nhiều thời gian và tài nguyên hơn AES rất nhiều.
# - Ứng dụng kết hợp (Hybrid Encryption): Dùng RSA để trao đổi khóa AES an toàn, sau đó dùng AES để mã hóa toàn bộ dữ liệu truyền tải thực tế (như SSL/TLS, HTTPS).

if __name__ == "__main__":
    test_aes()