import os
import sys
import json
import time
import getpass
import hashlib
import random
import shutil
import argparse
import secrets
import base64
from datetime import datetime

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[!] Thiếu thư viện cryptography. Cài đặt bằng lệnh:")
    print("    pip install cryptography")
    sys.exit(1)

################################################################################
# KHU VỰC BIẾN TOÀN CỤC (để giữ trạng thái login)
################################################################################

session_is_logged_in = False
myfs_instance = None  # Sẽ lưu object MyFS sau khi login
CODE_INTEGRITY_CHECKED = False  # Đảm bảo kiểm tra code integrity chỉ 1 lần

################################################################################
# CẤU HÌNH / HẰNG SỐ
################################################################################

MYFS_DATA_PATH   = "MyFS.dat"
MYFS_META_PATH   = "MyFS_meta.dat"
THIS_FILE_BACKUP = "myfs_code_backup.py"
CODE_HASH_PATH   = "code_hash.txt"

OTP_TIME_LIMIT   = 20
OTP_MAX_ATTEMPTS = 3

MAX_FILES                = 99
MAX_FILE_SIZE            = 4 * 1024 * 1024 * 1024  # 4GB
IMPORTANT_FILE_THRESHOLD = 100 * 1024 * 1024      # 100MB

BACKUP_DIR = "backup"  # Thư mục backup MyFS.dat

################################################################################
# CÁC HÀM TIỆN ÍCH
################################################################################

def compute_file_hash(filepath: str, block_size=65536) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha.update(block)
    return sha.hexdigest()

def compute_string_hash(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def generate_key() -> bytes:
    return Fernet.generate_key()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(encrypted_data)

def get_machine_id() -> str:
    try:
        return os.uname().nodename  # Linux/mac
    except AttributeError:
        import platform
        return platform.node()      # Windows

def base64_urlsafe_32bytes(raw_32: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw_32)

def derive_key_from_password(file_password: str) -> bytes:
    """
    Dùng SHA256 + 1 salt cứng (demo) -> ra 32 bytes -> base64 => Fernet key.
    """
    salt = b"fixed_salt_for_demo_"  # DEMO
    h = hashlib.sha256(file_password.encode('utf-8') + salt).digest()
    return base64.urlsafe_b64encode(h)

################################################################################
# LỚP CODE INTEGRITY CHECKER
################################################################################

class CodeIntegrityChecker:
    def __init__(self, current_file_path: str, backup_file_path: str, hash_file_path: str):
        self.current_file_path = current_file_path
        self.backup_file_path = backup_file_path
        self.hash_file_path = hash_file_path

    def compute_hash(self) -> str:
        return compute_file_hash(self.current_file_path)

    def create_backup(self):
        try:
            shutil.copy2(self.current_file_path, self.backup_file_path)
            print(f"[CodeIntegrity] Tạo backup code tại '{self.backup_file_path}' thành công.")
        except Exception as e:
            print("[CodeIntegrity] Lỗi khi tạo backup code:", e)
            sys.exit("Dừng chương trình do không tạo được backup.")

    def save_hash(self, hash_value: str):
        try:
            with open(self.hash_file_path, "w") as fh:
                fh.write(hash_value)
            print(f"[CodeIntegrity] Đã lưu hash code vào '{self.hash_file_path}'.")
        except Exception as e:
            print("[CodeIntegrity] Lỗi khi lưu hash code:", e)
            sys.exit("Dừng chương trình do không lưu được hash.")

    def load_hash(self) -> str:
        with open(self.hash_file_path, "r") as fh:
            return fh.read().strip()

    def restore_backup(self):
        if os.path.exists(self.backup_file_path):
            print("[CodeIntegrity] Phát hiện code bị thay đổi, đang khôi phục từ backup...")
            try:
                shutil.copy2(self.backup_file_path, self.current_file_path)
                print("[CodeIntegrity] Khôi phục code thành công. Vui lòng chạy lại chương trình.")
            except Exception as e:
                print("[CodeIntegrity] Lỗi khôi phục code:", e)
            finally:
                sys.exit(1)
        else:
            print("[CodeIntegrity] Không tìm thấy file backup để khôi phục.")
            sys.exit("Dừng chương trình.")

    def check_integrity(self):
        if not os.path.exists(self.current_file_path):
            print("[CodeIntegrity] Không tìm thấy file code để kiểm tra!")
            sys.exit(1)

        if not os.path.exists(self.hash_file_path):
            # Lần đầu
            current_hash = self.compute_hash()
            self.save_hash(current_hash)
            print("[CodeIntegrity] Thiết lập hash code lần đầu tiên.")
            self.create_backup()
        else:
            expected_hash = self.load_hash()
            current_hash = self.compute_hash()

            if current_hash != expected_hash:
                print("[CodeIntegrity] PHÁT HIỆN BẤT THƯỜNG: Code bị thay đổi so với hash gốc!")
                self.restore_backup()
            else:
                print("[CodeIntegrity] Code vẫn nguyên vẹn.")

################################################################################
# LỚP OTP HANDLER
################################################################################

class OTPHandler:
    def __init__(self, time_limit=OTP_TIME_LIMIT, max_attempts=OTP_MAX_ATTEMPTS):
        self.time_limit = time_limit
        self.max_attempts = max_attempts
        self.secret_salt = secrets.token_hex(8)

    def generate_x(self) -> str:
        return f"{random.randint(0, 9999):04d}"

    def generate_y(self, x: str) -> str:
        random_part = secrets.randbits(32)  # random 32 bit
        raw = f"{x}-{random_part}-{self.secret_salt}-{time.time()}"
        h = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        y_int = int(h, 16) % 10_0000_0000
        print(f"[OTP] (DEBUG) Y tính ra từ X={x}: {y_int:08d}")
        return f"{y_int:08d}"

    def prompt_otp(self):
        x = self.generate_x()
        y_actual = self.generate_y(x)

        print("\n==========  OTP SECURITY  ==========")
        print(f"Đã sinh ra mã X = {x} (4 chữ số).")
        print("Giả định một CT make_smartOTP ở máy khác nhận X và sinh Y (8 chữ số).")
        print("Hãy nhập Y (8 chữ số) tương ứng.")
        print("====================================\n")

        start_time = time.time()
        attempts = 0
        while attempts < self.max_attempts:
            y_input = input("Nhập Y (8 chữ số): ").strip()

            if (time.time() - start_time) > self.time_limit:
                print("[OTP] Quá thời gian nhập OTP!")
                sys.exit("[OTP] Tự huỷ do OTP không hợp lệ.")

            if y_input == y_actual:
                print("[OTP] Xác thực OTP thành công.")
                return
            else:
                print("[OTP] Sai OTP.")
                attempts += 1

        print("[OTP] Sai OTP quá 3 lần. Tự huỷ.")
        sys.exit(1)

################################################################################
# CLASS MyFS
################################################################################

class MyFS:
    def __init__(self, fs_path=MYFS_DATA_PATH, meta_path=MYFS_META_PATH):
        self.fs_path = fs_path
        self.meta_path = meta_path

        self.is_formatted = False
        self.machine_id = ""
        self.fs_password_hash = ""
        self.files = []
        self.trash = []
        self.encryption_key = None

        if os.path.exists(self.fs_path) and os.path.exists(self.meta_path):
            self.load_fs()

    def load_fs(self):
        try:
            with open(self.meta_path, "rb") as fm:
                self.encryption_key = fm.read().strip()

            with open(self.fs_path, "rb") as f:
                encrypted_content = f.read()

            decrypted_json = decrypt_data(encrypted_content, self.encryption_key).decode('utf-8')
            data = json.loads(decrypted_json)

            self.machine_id       = data.get("machine_id", "")
            self.fs_password_hash = data.get("fs_password_hash", "")
            self.files            = data.get("files", [])
            self.trash            = data.get("trash", [])
            self.is_formatted     = True

        except Exception as e:
            print(f"[MyFS] Lỗi load MyFS: {e}")

    def save_fs(self):
        if not self.encryption_key:
            print("[MyFS] Chưa có encryption_key, không thể lưu.")
            return

        data = {
            "machine_id": self.machine_id,
            "fs_password_hash": self.fs_password_hash,
            "files": self.files,
            "trash": self.trash
        }

        json_str = json.dumps(data)
        encrypted_content = encrypt_data(json_str.encode('utf-8'), self.encryption_key)

        with open(self.fs_path, "wb") as f:
            f.write(encrypted_content)

    def format_fs(self):
        if self.is_formatted:
            print("[MyFS] Đã format trước đây. Nếu muốn format lại, hãy xoá file cũ.")
            return

        self.encryption_key = generate_key()
        with open(self.meta_path, "wb") as fm:
            fm.write(self.encryption_key)

        self.machine_id       = get_machine_id()
        self.fs_password_hash = ""
        self.files            = []
        self.trash            = []
        self.is_formatted     = True

        self.save_fs()
        print("[MyFS] Tạo MyFS.dat thành công.")
        print(f"[MyFS] machine_id = {self.machine_id}")

    def check_same_machine(self) -> bool:
        if not self.is_formatted:
            return True
        return get_machine_id() == self.machine_id

    def set_fs_password(self):
        if not self.is_formatted:
            print("[MyFS] Volume chưa format.")
            return

        pw1 = getpass.getpass("Nhập mật khẩu MyFS mới: ")
        pw2 = getpass.getpass("Xác nhận mật khẩu MyFS: ")
        if pw1 != pw2:
            print("[MyFS] Mật khẩu không khớp.")
            return

        self.fs_password_hash = compute_string_hash(pw1)
        self.save_fs()
        print("[MyFS] Đặt/đổi mật khẩu MyFS thành công.")

    def verify_fs_password(self) -> bool:
        """
        Hỏi user nhập pass MyFS, so sánh với self.fs_password_hash.
        Trả về True/False.
        """
        if not self.is_formatted:
            print("[MyFS] Chưa format => ko có mật khẩu MyFS.")
            return True

        if not self.fs_password_hash:
            # MyFS chưa có mật khẩu
            return True

        pw = getpass.getpass("Nhập mật khẩu MyFS: ")
        if compute_string_hash(pw) == self.fs_password_hash:
            return True
        else:
            print("[MyFS] Sai mật khẩu MyFS.")
            return False

    def check_pw_is_set(self) -> bool:
        """
        Kiểm tra MyFS đã có password hay chưa (chỉ cho mục đích hiển thị).
        """
        return bool(self.fs_password_hash)

    # -------------------------
    # Chức năng thao tác
    # -------------------------

    def list_files(self):
        if not self.files:
            print("[MyFS] Danh sách file trống.")
            return
        print("\n----- Danh sách file trong MyFS -----")
        for i, fobj in enumerate(self.files, 1):
            fname = fobj.get('filename', 'unknown')
            size_ = fobj.get('size', 0)
            imp   = fobj.get('important', False)
            orig  = fobj.get('path_origin', '')
            print(f"{i}. {fname} | size={size_} | important={imp} | origin={orig}")
        print("-------------------------------------")

    def import_file(self, source_path: str):
        try:
            if not os.path.isfile(source_path):
                print(f"[MyFS] File '{source_path}' không hợp lệ hoặc không tồn tại.")
                return

            if len(self.files) >= MAX_FILES:
                print("[MyFS] Số file trong MyFS đã đạt giới hạn.")
                return

            size_ = os.path.getsize(source_path)
            if size_ > MAX_FILE_SIZE:
                print("[MyFS] File quá lớn (>4GB), không thể import.")
                return

            filename = os.path.basename(source_path)
            if any(f['filename'] == filename for f in self.files):
                print(f"[MyFS] Đã tồn tại file tên '{filename}' trong MyFS.")
                return

            important = (size_ <= IMPORTANT_FILE_THRESHOLD)

            with open(source_path, "rb") as f:
                raw = f.read()

            if important:
                enc = encrypt_data(raw, self.encryption_key)
            else:
                enc = raw

            file_obj = {
                "filename": filename,
                "path_origin": os.path.abspath(source_path),
                "size": size_,
                "important": important,
                "content": enc.hex(),
                "file_password_hash": "",
                "created_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.files.append(file_obj)
            self.save_fs()
            print(f"[MyFS] Đã import file '{filename}' thành công.")
        except Exception as e:
            print(f"[MyFS] Lỗi khi import file: {e}")

    def export_file(self, filename: str, dest_path: str = None):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] Không tìm thấy file '{filename}'.")
                return

            content_enc = bytes.fromhex(fobj['content'])
            important   = fobj.get('important', False)
            file_pw_hash= fobj.get('file_password_hash', '')

            if important:
                # File quan trọng => Giải mã = password file (nếu có) hoặc key chung
                if file_pw_hash:
                    old_pw = getpass.getpass(f"Nhập password file '{filename}': ")
                    if compute_string_hash(old_pw) != file_pw_hash:
                        print("[MyFS] Sai mật khẩu file.")
                        return
                    fkey = derive_key_from_password(old_pw)
                    try:
                        raw_data = decrypt_data(content_enc, fkey)
                    except Exception as e:
                        print(f"[MyFS] Giải mã thất bại (bằng password file): {e}")
                        return
                else:
                    try:
                        raw_data = decrypt_data(content_enc, self.encryption_key)
                    except Exception as e:
                        print(f"[MyFS] Giải mã bằng key chung thất bại: {e}")
                        return
            else:
                raw_data = content_enc

            if not dest_path:
                dest_path = fobj.get('path_origin', '')
                if not dest_path or not os.path.isdir(os.path.dirname(dest_path)):
                    print(f"[MyFS] Đường dẫn gốc '{dest_path}' không khả dụng.")
                    dest_path = input("Nhập thư mục đích (path) để export file: ").strip()
                    if not os.path.isdir(dest_path):
                        print("[MyFS] Thư mục đích không hợp lệ, hủy export.")
                        return
                else:
                    dest_path = os.path.dirname(dest_path)

            if os.path.isdir(dest_path):
                out_file = os.path.join(dest_path, filename)
            else:
                out_file = dest_path

            with open(out_file, "wb") as fo:
                fo.write(raw_data)
            print(f"[MyFS] Đã export file '{filename}' tới '{out_file}'.")
        except Exception as e:
            print(f"[MyFS] Lỗi khi export file: {e}")

    def delete_file(self, filename: str):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] Không tìm thấy file '{filename}'.")
                return

            confirm = input(f"Bạn có chắc muốn xoá file '{filename}'? (y/n): ").lower()
            if confirm != 'y':
                print("[MyFS] Đã huỷ thao tác xoá.")
                return

            fobj['deleted_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.trash.append(fobj)
            del self.files[idx]
            self.save_fs()
            print(f"[MyFS] Đã chuyển file '{filename}' vào thùng rác.")
        except Exception as e:
            print(f"[MyFS] Lỗi khi xóa file: {e}")

    def list_trash(self):
        if not self.trash:
            print("[MyFS] Thùng rác trống.")
            return
        print("\n----- Danh sách file trong Thùng Rác -----")
        for i, fobj in enumerate(self.trash, 1):
            fname = fobj.get('filename', 'unknown')
            dtime = fobj.get('deleted_time', 'unknown')
            print(f"{i}. {fname} | Đã xóa lúc: {dtime}")
        print("-----------------------------------------")

    def restore_file(self, filename: str):
        try:
            idx, fobj = self._find_file_in_trash(filename)
            if fobj is None:
                print(f"[MyFS] Không tìm thấy file '{filename}' trong thùng rác.")
                return

            del fobj['deleted_time']
            self.files.append(fobj)
            del self.trash[idx]
            self.save_fs()
            print(f"[MyFS] Khôi phục file '{filename}' từ thùng rác thành công.")
        except Exception as e:
            print(f"[MyFS] Lỗi khi khôi phục file: {e}")

    def set_file_password(self, filename: str):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] Không tìm thấy file '{filename}'.")
                return

            important = fobj.get('important', False)
            if not important:
                print("[MyFS] File này KHÔNG quan trọng => không mã hoá nội dung bằng password riêng.")
                new_pw1 = getpass.getpass("Nhập password file mới: ")
                new_pw2 = getpass.getpass("Xác nhận password file: ")
                if new_pw1 != new_pw2:
                    print("[MyFS] Mật khẩu file không khớp.")
                    return
                fobj['file_password_hash'] = compute_string_hash(new_pw1)
                self.files[idx] = fobj
                self.save_fs()
                print(f"[MyFS] Đã lưu password cho file '{filename}' (không mã hoá nội dung).")
                return

            # File quan trọng => Mã hoá lại nếu đã có password cũ
            old_pw_hash = fobj.get('file_password_hash', '')
            old_enc     = bytes.fromhex(fobj['content'])

            # B1: Giải mã
            if old_pw_hash:
                old_pw_input = getpass.getpass("Nhập password file cũ: ")
                if compute_string_hash(old_pw_input) != old_pw_hash:
                    print("[MyFS] Sai password file cũ, không giải mã được.")
                    return
                old_key = derive_key_from_password(old_pw_input)
                try:
                    raw_data = decrypt_data(old_enc, old_key)
                except Exception as e:
                    print("[MyFS] Giải mã thất bại (password cũ sai?).", e)
                    return
            else:
                # Chưa có password file => đang mã hoá bằng key chung
                try:
                    raw_data = decrypt_data(old_enc, self.encryption_key)
                except Exception as e:
                    print("[MyFS] Giải mã bằng key chung thất bại.", e)
                    return

            # B2: Hỏi password mới
            new_pw1 = getpass.getpass("Nhập password file mới: ")
            new_pw2 = getpass.getpass("Xác nhận password file mới: ")
            if new_pw1 != new_pw2:
                print("[MyFS] Mật khẩu file mới không khớp.")
                return

            new_key = derive_key_from_password(new_pw1)
            new_enc = encrypt_data(raw_data, new_key)

            fobj['file_password_hash'] = compute_string_hash(new_pw1)
            fobj['content'] = new_enc.hex()
            self.files[idx] = fobj
            self.save_fs()
            print(f"[MyFS] Đã mã hoá lại file '{filename}' với mật khẩu mới.")
        except Exception as e:
            print(f"[MyFS] Lỗi khi đặt/đổi mật khẩu file: {e}")

    def backup_fs(self):
        try:
            if not os.path.exists(BACKUP_DIR):
                os.makedirs(BACKUP_DIR)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(BACKUP_DIR, f"MyFS_backup_{ts}.dat")
            shutil.copy2(self.fs_path, backup_file)
            print(f"[MyFS] Đã tạo backup MyFS.dat tại '{backup_file}'.")
        except Exception as e:
            print("[MyFS] Lỗi backup:", e)

    def restore_backup_file(self, backup_file: str):
        try:
            if not os.path.isfile(backup_file):
                print(f"[MyFS] Không tìm thấy file backup '{backup_file}'.")
                return
            shutil.copy2(backup_file, self.fs_path)
            self.load_fs()
            print(f"[MyFS] Đã khôi phục MyFS.dat từ '{backup_file}'. (Cẩn thận dữ liệu cũ!)")
        except Exception as e:
            print(f"[MyFS] Lỗi khôi phục backup: {e}")

    # -------- PRIVATE
    def _find_file(self, filename: str):
        for i, f in enumerate(self.files):
            if f['filename'] == filename:
                return i, f
        return None, None

    def _find_file_in_trash(self, filename: str):
        for i, f in enumerate(self.trash):
            if f['filename'] == filename:
                return i, f
        return None, None

################################################################################
# HÀM XỬ LÝ LOGIN / LOGOUT
################################################################################

def do_login():
    """
    Thực hiện mọi việc cần làm trước khi vào dùng MyFS:
      1) Kiểm tra code integrity (chỉ 1 lần duy nhất)
      2) OTP
      3) Kiểm tra MyFS (nếu có format => hỏi mật khẩu)
    """
    global session_is_logged_in, myfs_instance, CODE_INTEGRITY_CHECKED

    if session_is_logged_in:
        print("[MyFS] Bạn đã đăng nhập rồi, không cần login lại.")
        return

    # 1) Kiểm tra code integrity (chỉ làm 1 lần)
    if not CODE_INTEGRITY_CHECKED:
        current_file_path = os.path.abspath(__file__)
        backup_file_path  = os.path.join(os.path.dirname(current_file_path), THIS_FILE_BACKUP)
        hash_file_path    = os.path.join(os.path.dirname(current_file_path), CODE_HASH_PATH)
        checker = CodeIntegrityChecker(current_file_path, backup_file_path, hash_file_path)
        checker.check_integrity()
        CODE_INTEGRITY_CHECKED = True

    # 2) OTP
    otp = OTPHandler()
    otp.prompt_otp()

    # 3) Tạo 1 instance MyFS
    myfs = MyFS()
    # Nếu MyFS đã được format => kiểm tra máy => kiểm tra mật khẩu
    if myfs.is_formatted:
        if not myfs.check_same_machine():
            print("[MyFS] Máy hiện tại KHÔNG phải máy đã tạo MyFS! Từ chối truy cập.")
            sys.exit(1)

        if not myfs.verify_fs_password():
            print("[MyFS] Mật khẩu MyFS không đúng. Kết thúc.")
            sys.exit(1)

    # Nếu tới đây => ok
    session_is_logged_in = True
    myfs_instance = myfs
    print("\n[MyFS] Đăng nhập thành công!")
    if myfs.is_formatted:
        if myfs.check_pw_is_set():
            print("  - MyFS đã có mật khẩu.")
        else:
            print("  - MyFS chưa đặt mật khẩu.")

def do_logout():
    global session_is_logged_in, myfs_instance
    if session_is_logged_in:
        session_is_logged_in = False
        myfs_instance = None
        print("[MyFS] Bạn đã logout khỏi MyFS.")
    else:
        print("[MyFS] Bạn chưa đăng nhập, không cần logout.")

################################################################################
# HÀM GIAO DIỆN DÒNG LỆNH (INTERACTIVE SHELL) SAU KHI LOGIN
################################################################################

def interactive_shell():
    """
    Giao diện CLI để user gõ các lệnh MyFS mà không cần chạy lại python myfs.py.
    Gõ 'logout' hoặc nhấn Ctrl+C/Ctrl+D để thoát.
    """
    global session_is_logged_in, myfs_instance

    print("""
[HƯỚNG DẪN] Bạn có thể gõ các lệnh sau:
  set-pw                -> Đặt/đổi mật khẩu MyFS
  list                  -> Liệt kê file
  import <file_path>    -> Import file
  export <filename>     -> Export file (sẽ hỏi thêm đường dẫn)
  delete <filename>     -> Xoá (chuyển vào thùng rác)
  list-trash            -> Liệt kê thùng rác
  restore <filename>    -> Khôi phục file từ thùng rác
  set-file-pw <filename>-> Đặt/đổi mật khẩu riêng cho file quan trọng
  backup                -> Tạo backup MyFS.dat
  restore-backup <file> -> Khôi phục MyFS.dat từ file backup
  logout                -> Thoát khỏi phiên đăng nhập (chương trình dừng)
""")

    while session_is_logged_in:
        try:
            cmd = input("myfs> ").strip()
        except (EOFError, KeyboardInterrupt):
            # Nếu nhấn Ctrl+C/Ctrl+D => tự động logout
            print("\n[MyFS] Thoát shell tương tác.")
            do_logout()
            break

        if not cmd:
            continue

        parts = cmd.split()
        command = parts[0].lower()

        if command == 'logout':
            do_logout()
            break

        elif command == 'set-pw':
            myfs_instance.set_fs_password()

        elif command == 'list':
            myfs_instance.list_files()

        elif command == 'import':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: import <path_to_file>")
                continue
            src = " ".join(parts[1:])  # đề phòng đường dẫn có khoảng trắng
            myfs_instance.import_file(src)

        elif command == 'export':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: export <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.export_file(filename)

        elif command == 'delete':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: delete <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.delete_file(filename)

        elif command == 'list-trash':
            myfs_instance.list_trash()

        elif command == 'restore':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: restore <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.restore_file(filename)

        elif command == 'set-file-pw':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: set-file-pw <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.set_file_password(filename)

        elif command == 'backup':
            myfs_instance.backup_fs()

        elif command == 'restore-backup':
            if len(parts) < 2:
                print("[MyFS] Cú pháp: restore-backup <backup_file>")
                continue
            backup_file = " ".join(parts[1:])
            myfs_instance.restore_backup_file(backup_file)

        else:
            print("[MyFS] Lệnh không hợp lệ. Gõ 'logout' để thoát hoặc xem hướng dẫn ở trên.")

    print("[MyFS] Kết thúc phiên shell.")

################################################################################
# MAIN
################################################################################

def main():
    parser = argparse.ArgumentParser(description="MyFS - Hệ thống quản lý tập tin (Phiên bản tương tác).")
    subparsers = parser.add_subparsers(dest='command', help='Các lệnh chính')

    # Lệnh create (chỉ để tạo MyFS.dat, ko yêu cầu login)
    sp_create = subparsers.add_parser('create', help='Tạo/định dạng MyFS.dat lần đầu')

    # Lệnh login => Sau khi login xong thì vào interactive shell
    sp_login = subparsers.add_parser('login',  help='Đăng nhập và vào shell MyFS')

    args = parser.parse_args()

    if args.command == 'create':
        tmp_fs = MyFS()
        tmp_fs.format_fs()

    elif args.command == 'login':
        do_login()
        if session_is_logged_in:
            interactive_shell()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
