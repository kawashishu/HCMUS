"""
================================================================================
MYFS DAT - LOGIN / LOGOUT & INTERACTIVE SHELL
--------------------------------------------------------------------------------
1/ Run "python myfs.py create" to initialize/format MyFS.dat (only once).
2/ Run "python myfs.py login" to log in to MyFS:
   - Perform code integrity check
   - Perform dynamic OTP verification
   - Verify MyFS password (if MyFS is password-protected)
   => If successful, the program enters the interactive shell interface.
3/ In this shell interface, commands will operate without re-entering the MyFS password:
   - set-pw, list, import, export, delete,
     list-trash, restore, set-file-pw, backup, restore-backup
4/ Type "logout" (or Ctrl+C, or Ctrl+D) to exit the login session.
5/ The program stops automatically. To log in again, you need to run "python myfs.py login" again.
================================================================================
"""

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
    print("[!] Missing cryptography library. Install with:")
    print("    pip install cryptography")
    sys.exit(1)

################################################################################
# GLOBAL VARIABLES (to maintain login state)
################################################################################

session_is_logged_in = False
myfs_instance = None  # Will hold MyFS object after login
CODE_INTEGRITY_CHECKED = False  # Ensure code integrity check only runs once

################################################################################
# CONFIGURATIONS / CONSTANTS
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

BACKUP_DIR = "backup"  # Backup directory for MyFS.dat

#################################################################################
# UTILITY FUNCTIONS
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
# CLASS CODE INTEGRITY CHECKER
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
            print(f"[CodeIntegrity] Backup created at '{self.backup_file_path}' successfully.")
        except Exception as e:
            print("[CodeIntegrity] Error creating code backup:", e)
            sys.exit("Stopping program as backup creation failed.")

    def save_hash(self, hash_value: str):
        try:
            with open(self.hash_file_path, "w") as fh:
                fh.write(hash_value)
            print(f"[CodeIntegrity] Hash saved to '{self.hash_file_path}'.")
        except Exception as e:
            print("[CodeIntegrity] Error saving code hash:", e)
            sys.exit("Stopping program as hash saving failed.")

    def load_hash(self) -> str:
        with open(self.hash_file_path, "r") as fh:
            return fh.read().strip()

    def restore_backup(self):
        if os.path.exists(self.backup_file_path):
            print("[CodeIntegrity] Code modified. Restoring from backup...")
            try:
                shutil.copy2(self.backup_file_path, self.current_file_path)
                print("[CodeIntegrity] Code restored successfully. Please re-run the program.")
            except Exception as e:
                print("[CodeIntegrity] Error restoring code:", e)
            finally:
                sys.exit(1)
        else:
            print("[CodeIntegrity] No backup file found to restore.")
            sys.exit("Stopping program.")

    def check_integrity(self):
        if not os.path.exists(self.current_file_path):
            print("[CodeIntegrity] Code file not found for verification!")
            sys.exit(1)

        if not os.path.exists(self.hash_file_path):
            # First time setup
            current_hash = self.compute_hash()
            self.save_hash(current_hash)
            print("[CodeIntegrity] Initial code hash established.")
            self.create_backup()
        else:
            expected_hash = self.load_hash()
            current_hash = self.compute_hash()

            if current_hash != expected_hash:
                print("[CodeIntegrity] ALERT: Code modified from the original hash!")
                self.restore_backup()
            else:
                print("[CodeIntegrity] Code is intact.")

################################################################################
# CLASS OTP HANDLER
################################################################################

class OTPHandler:
    def __init__(self, time_limit=OTP_TIME_LIMIT, max_attempts=OTP_MAX_ATTEMPTS):
        self.time_limit = time_limit
        self.max_attempts = max_attempts
        self.secret_salt = secrets.token_hex(8)

    def generate_x(self) -> str:
        return f"{random.randint(0, 9999):04d}"

    def generate_y(self, x: str) -> str:
        random_part = secrets.randbits(32)  # random 32 bits
        raw = f"{x}-{random_part}-{self.secret_salt}-{time.time()}"
        h = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        y_int = int(h, 16) % 10_0000_0000
        return f"{y_int:08d}"

    def prompt_otp(self):
        x = self.generate_x()
        y_actual = self.generate_y(x)

        print("\n==========  OTP SECURITY  ==========")
        print(f"Generated X = {x} (4 digits).")
        print(f"Assume a make_smartOTP at another machine generates Y: {y_actual}")
        print("Enter Y (8 digits) accordingly.")
        print("====================================\n")

        start_time = time.time()
        attempts = 0
        while attempts < self.max_attempts:
            y_input = input("Enter Y (8 digits): ").strip()

            if (time.time() - start_time) > self.time_limit:
                print("[OTP] OTP entry timed out!")
                sys.exit("[OTP] Exiting as OTP is invalid.")

            if y_input == y_actual:
                print("[OTP] OTP verified successfully.")
                return
            else:
                print("[OTP] Incorrect OTP.")
                attempts += 1

        print("[OTP] OTP incorrect 3 times. Exiting.")
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
            print(f"[MyFS] Error loading MyFS: {e}")

    def save_fs(self):
        if not self.encryption_key:
            print("[MyFS] No encryption_key available, cannot save.")
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
            print("[MyFS] Already formatted. To reformat, delete the old files.")
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
        print("[MyFS] MyFS.dat created successfully.")
        print(f"[MyFS] machine_id = {self.machine_id}")

    def check_same_machine(self) -> bool:
        if not self.is_formatted:
            return True
        return get_machine_id() == self.machine_id

    def set_fs_password(self):
        if not self.is_formatted:
            print("[MyFS] Volume not formatted.")
            return

        pw1 = getpass.getpass("Enter new MyFS password: ")
        pw2 = getpass.getpass("Confirm MyFS password: ")
        if pw1 != pw2:
            print("[MyFS] Passwords do not match.")
            return

        self.fs_password_hash = compute_string_hash(pw1)
        self.save_fs()
        print("[MyFS] MyFS password set/changed successfully.")

    def verify_fs_password(self) -> bool:
        """
        Ask the user to enter MyFS password, compare with self.fs_password_hash.
        Returns True/False.
        """
        if not self.is_formatted:
            print("[MyFS] Not formatted => no MyFS password.")
            return True

        if not self.fs_password_hash:
            # MyFS does not have a password
            return True

        pw = getpass.getpass("Enter MyFS password: ")
        if compute_string_hash(pw) == self.fs_password_hash:
            return True
        else:
            print("[MyFS] Incorrect MyFS password.")
            return False

    def check_pw_is_set(self) -> bool:
        """
        Check if MyFS has a password (for display purposes only).
        """
        return bool(self.fs_password_hash)

    # -------------------------
    # File management functions
    # -------------------------

    def list_files(self):
        if not self.files:
            print("[MyFS] File list is empty.")
            return
        print("\n----- File List in MyFS -----")
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
                print(f"[MyFS] File '{source_path}' is invalid or does not exist.")
                return

            if len(self.files) >= MAX_FILES:
                print("[MyFS] Maximum number of files in MyFS reached.")
                return

            size_ = os.path.getsize(source_path)
            if size_ > MAX_FILE_SIZE:
                print("[MyFS] File too large (>4GB), cannot import.")
                return

            filename = os.path.basename(source_path)
            if any(f['filename'] == filename for f in self.files):
                print(f"[MyFS] File with name '{filename}' already exists in MyFS.")
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
            print(f"[MyFS] File '{filename}' imported successfully.")
        except Exception as e:
            print(f"[MyFS] Error importing file: {e}")

    def export_file(self, filename: str, dest_path: str = None):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] File '{filename}' not found.")
                return

            content_enc = bytes.fromhex(fobj['content'])
            important   = fobj.get('important', False)
            file_pw_hash= fobj.get('file_password_hash', '')

            if important:
                # Important file => Decrypt using file password (if set) or shared key
                if file_pw_hash:
                    old_pw = getpass.getpass(f"Enter file password for '{filename}': ")
                    if compute_string_hash(old_pw) != file_pw_hash:
                        print("[MyFS] Incorrect file password.")
                        return
                    fkey = derive_key_from_password(old_pw)
                    try:
                        raw_data = decrypt_data(content_enc, fkey)
                    except Exception as e:
                        print(f"[MyFS] Decryption failed (using file password): {e}")
                        return
                else:
                    try:
                        raw_data = decrypt_data(content_enc, self.encryption_key)
                    except Exception as e:
                        print(f"[MyFS] Decryption using shared key failed: {e}")
                        return
            else:
                raw_data = content_enc

            if not dest_path:
                dest_path = fobj.get('path_origin', '')
                if not dest_path or not os.path.isdir(os.path.dirname(dest_path)):
                    print(f"[MyFS] Original path '{dest_path}' unavailable.")
                    dest_path = input("Enter destination directory (path) to export file: ").strip()
                    if not os.path.isdir(dest_path):
                        print("[MyFS] Invalid destination directory, canceling export.")
                        return
                else:
                    dest_path = os.path.dirname(dest_path)

            if os.path.isdir(dest_path):
                out_file = os.path.join(dest_path, filename)
            else:
                out_file = dest_path

            with open(out_file, "wb") as fo:
                fo.write(raw_data)
            print(f"[MyFS] File '{filename}' exported to '{out_file}'.")
        except Exception as e:
            print(f"[MyFS] Error exporting file: {e}")

    def delete_file(self, filename: str):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] File '{filename}' not found.")
                return

            confirm = input(f"Are you sure you want to delete file '{filename}'? (y/n): ").lower()
            if confirm != 'y':
                print("[MyFS] File deletion canceled.")
                return

            fobj['deleted_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.trash.append(fobj)
            del self.files[idx]
            self.save_fs()
            print(f"[MyFS] File '{filename}' moved to trash.")
        except Exception as e:
            print(f"[MyFS] Error deleting file: {e}")

    def list_trash(self):
        if not self.trash:
            print("[MyFS] Trash is empty.")
            return
        print("\n----- File List in Trash -----")
        for i, fobj in enumerate(self.trash, 1):
            fname = fobj.get('filename', 'unknown')
            dtime = fobj.get('deleted_time', 'unknown')
            print(f"{i}. {fname} | Deleted at: {dtime}")
        print("-----------------------------------------")

    def restore_file(self, filename: str):
        try:
            idx, fobj = self._find_file_in_trash(filename)
            if fobj is None:
                print(f"[MyFS] File '{filename}' not found in trash.")
                return

            del fobj['deleted_time']
            self.files.append(fobj)
            del self.trash[idx]
            self.save_fs()
            print(f"[MyFS] File '{filename}' restored from trash successfully.")
        except Exception as e:
            print(f"[MyFS] Error restoring file: {e}")

    def set_file_password(self, filename: str):
        try:
            idx, fobj = self._find_file(filename)
            if fobj is None:
                print(f"[MyFS] File '{filename}' not found.")
                return

            important = fobj.get('important', False)
            if not important:
                print("[MyFS] This file is NOT important => content not encrypted with a separate password.")
                new_pw1 = getpass.getpass("Enter new file password: ")
                new_pw2 = getpass.getpass("Confirm file password: ")
                if new_pw1 != new_pw2:
                    print("[MyFS] File passwords do not match.")
                    return
                fobj['file_password_hash'] = compute_string_hash(new_pw1)
                self.files[idx] = fobj
                self.save_fs()
                print(f"[MyFS] Password for file '{filename}' saved (content not encrypted).")
                return

            # Important file => Re-encrypt if there is an old password
            old_pw_hash = fobj.get('file_password_hash', '')
            old_enc     = bytes.fromhex(fobj['content'])

            # Step 1: Decrypt
            if old_pw_hash:
                old_pw_input = getpass.getpass("Enter old file password: ")
                if compute_string_hash(old_pw_input) != old_pw_hash:
                    print("[MyFS] Incorrect old file password, cannot decrypt.")
                    return
                old_key = derive_key_from_password(old_pw_input)
                try:
                    raw_data = decrypt_data(old_enc, old_key)
                except Exception as e:
                    print("[MyFS] Decryption failed (old password incorrect?).", e)
                    return
            else:
                # No file password yet => currently encrypted with shared key
                try:
                    raw_data = decrypt_data(old_enc, self.encryption_key)
                except Exception as e:
                    print("[MyFS] Decryption using shared key failed.", e)
                    return

            # Step 2: Ask for a new password
            new_pw1 = getpass.getpass("Enter new file password: ")
            new_pw2 = getpass.getpass("Confirm new file password: ")
            if new_pw1 != new_pw2:
                print("[MyFS] New file passwords do not match.")
                return

            new_key = derive_key_from_password(new_pw1)
            new_enc = encrypt_data(raw_data, new_key)

            fobj['file_password_hash'] = compute_string_hash(new_pw1)
            fobj['content'] = new_enc.hex()
            self.files[idx] = fobj
            self.save_fs()
            print(f"[MyFS] File '{filename}' re-encrypted with new password.")
        except Exception as e:
            print(f"[MyFS] Error setting/changing file password: {e}")

    def backup_fs(self):
        try:
            if not os.path.exists(BACKUP_DIR):
                os.makedirs(BACKUP_DIR)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(BACKUP_DIR, f"MyFS_backup_{ts}.dat")
            shutil.copy2(self.fs_path, backup_file)
            print(f"[MyFS] Backup created for MyFS.dat at '{backup_file}'.")
        except Exception as e:
            print("[MyFS] Backup error:", e)

    def restore_backup_file(self, backup_file: str):
        try:
            if not os.path.isfile(backup_file):
                print(f"[MyFS] Backup file '{backup_file}' not found.")
                return
            shutil.copy2(backup_file, self.fs_path)
            self.load_fs()
            print(f"[MyFS] MyFS.dat restored from '{backup_file}'. (Be cautious of old data!)")
        except Exception as e:
            print(f"[MyFS] Error restoring backup: {e}")

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
# LOGIN / LOGOUT HANDLING FUNCTIONS
################################################################################

def do_login():
    """
    Perform all necessary steps before accessing MyFS:
      1) Check code integrity (only once)
      2) OTP verification
      3) Check MyFS (if formatted => ask for password)
    """
    global session_is_logged_in, myfs_instance, CODE_INTEGRITY_CHECKED

    if session_is_logged_in:
        print("[MyFS] You are already logged in, no need to log in again.")
        return

    # 1) Check code integrity (only once)
    if not CODE_INTEGRITY_CHECKED:
        current_file_path = os.path.abspath(__file__)
        backup_file_path  = os.path.join(os.path.dirname(current_file_path), THIS_FILE_BACKUP)
        hash_file_path    = os.path.join(os.path.dirname(current_file_path), CODE_HASH_PATH)
        checker = CodeIntegrityChecker(current_file_path, backup_file_path, hash_file_path)
        checker.check_integrity()
        CODE_INTEGRITY_CHECKED = True

    # 2) OTP verification
    otp = OTPHandler()
    otp.prompt_otp()

    # 3) Create a MyFS instance
    myfs = MyFS()
    # If MyFS is formatted => check machine => check password
    if myfs.is_formatted:
        if not myfs.check_same_machine():
            print("[MyFS] Current machine is NOT the machine that created MyFS! Access denied.")
            sys.exit(1)

        if not myfs.verify_fs_password():
            print("[MyFS] Incorrect MyFS password. Exiting.")
            sys.exit(1)

    # If everything is okay
    session_is_logged_in = True
    myfs_instance = myfs
    print("\n[MyFS] Login successful!")
    if myfs.is_formatted:
        if myfs.check_pw_is_set():
            print("  - MyFS has a password.")
        else:
            print("  - MyFS does not have a password.")

def do_logout():
    global session_is_logged_in, myfs_instance
    if session_is_logged_in:
        session_is_logged_in = False
        myfs_instance = None
        print("[MyFS] You have logged out of MyFS.")
    else:
        print("[MyFS] You are not logged in, no need to log out.")

################################################################################
# INTERACTIVE SHELL FUNCTION AFTER LOGIN
################################################################################

def interactive_shell():
    """
    CLI interface for users to execute MyFS commands without restarting python myfs.py.
    Type 'logout' or press Ctrl+C/Ctrl+D to exit.
    """
    global session_is_logged_in, myfs_instance

    print("""
[GUIDE] You can type the following commands:
  set-pw                -> Set/change MyFS password
  list                  -> List files
  import <file_path>    -> Import a file
  export <filename>     -> Export a file (destination will be prompted)
  delete <filename>     -> Delete (move to trash)
  list-trash            -> List files in trash
  restore <filename>    -> Restore a file from trash
  set-file-pw <filename>-> Set/change individual password for an important file
  backup                -> Create a backup of MyFS.dat
  restore-backup <file> -> Restore MyFS.dat from a backup file
  logout                -> Log out of the session (program stops)
""")

    while session_is_logged_in:
        try:
            cmd = input("myfs> ").strip()
        except (EOFError, KeyboardInterrupt):
            # If Ctrl+C/Ctrl+D is pressed => auto logout
            print("\n[MyFS] Exiting interactive shell.")
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
                print("[MyFS] Syntax: import <path_to_file>")
                continue
            src = " ".join(parts[1:])  # Handle paths with spaces
            myfs_instance.import_file(src)

        elif command == 'export':
            if len(parts) < 2:
                print("[MyFS] Syntax: export <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.export_file(filename)

        elif command == 'delete':
            if len(parts) < 2:
                print("[MyFS] Syntax: delete <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.delete_file(filename)

        elif command == 'list-trash':
            myfs_instance.list_trash()

        elif command == 'restore':
            if len(parts) < 2:
                print("[MyFS] Syntax: restore <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.restore_file(filename)

        elif command == 'set-file-pw':
            if len(parts) < 2:
                print("[MyFS] Syntax: set-file-pw <filename>")
                continue
            filename = " ".join(parts[1:])
            myfs_instance.set_file_password(filename)

        elif command == 'backup':
            myfs_instance.backup_fs()

        elif command == 'restore-backup':
            if len(parts) < 2:
                print("[MyFS] Syntax: restore-backup <backup_file>")
                continue
            backup_file = " ".join(parts[1:])
            myfs_instance.restore_backup_file(backup_file)

        else:
            print("[MyFS] Invalid command. Type 'logout' to exit or see the guide above.")

    print("[MyFS] Interactive shell session ended.")

################################################################################
# MAIN
################################################################################

def main():
    parser = argparse.ArgumentParser(description="MyFS - File management system (interactive version).")
    subparsers = parser.add_subparsers(dest='command', help='Main commands')

    # Create command (only to create MyFS.dat, does not require login)
    sp_create = subparsers.add_parser('create', help='Create/format MyFS.dat for the first time')

    # Login command => After login, enter the interactive shell
    sp_login = subparsers.add_parser('login', help='Log in and enter MyFS shell')

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
