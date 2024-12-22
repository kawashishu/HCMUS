
# MyFS - Secure Virtual File System

## System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: Version 3.6 or higher
- **Python Libraries**:
  - `cryptography`

## Installation

1. **Install Python**

   Ensure Python is installed on the system. Download from the [official website](https://www.python.org/downloads/).

2. **Download MyFS**

   Obtain the MyFS source code from the repository or provided source.

3. **Install Required Libraries**

   Open a terminal or command prompt and execute:

   ```bash
   pip install cryptography
   ```

   If permission issues occur, append the `--user` flag:

   ```bash
   pip install cryptography --user
   ```

## Usage

### 1. Create/Format MyFS.dat

Initialize the MyFS system and create the `MyFS.dat` container by running:

```bash
python myfs.py create
```

**Note**: This command should be executed only once. To reformat MyFS, delete the existing `MyFS.dat` and `MyFS_meta.dat` files before running the command again.

### 2. Login to MyFS

Access MyFS and enter the interactive shell with:

```bash
python myfs.py login
```

The login process includes:

- **Code Integrity Check**: Verifies the integrity of the MyFS codebase.
- **OTP Authentication**: Requires a dynamic One-Time Password for enhanced security.
- **Password Verification**: Prompts for the master password if set during initialization.

Upon successful authentication, the interactive shell is launched.

### 3. Interactive Shell Commands

Within the interactive shell, execute the following commands:

- `set-pw` : Set or change the master password for MyFS.
- `list` : Display all files stored in MyFS.
- `import <file_path>` : Import a file from the host system into MyFS.
- `export <filename>` : Export a file from MyFS to the host system.
- `delete <filename>` : Delete (move to trash) a file within MyFS.
- `list-trash` : List all deleted files in the trash bin.
- `restore <filename>` : Restore a file from the trash bin back to MyFS.
- `set-file-pw <filename>` : Set or change a password for a specific important file.
- `backup` : Create a backup of `MyFS.dat`.
- `restore-backup <backup_file>` : Restore `MyFS.dat` from a specified backup file.
- `logout` : Exit the current session and terminate the program.

### 4. Logout

To terminate the current session and exit MyFS, use the `logout` command or press `Ctrl+C`/`Ctrl+D`:

```bash
myfs> logout
```

After logout, restart the login process with `python myfs.py login` to access MyFS again.

## Troubleshooting

- **Missing `cryptography` Library**: If an error indicates the absence of the `cryptography` library, install it using:

  ```bash
  pip install cryptography
  ```

- **Permission Issues**: Ensure sufficient permissions to create and modify files and directories. Running the terminal or command prompt with administrative privileges may help.

- **Incorrect Password**: If the master password is forgotten, access to MyFS will be denied. Restoring from a previously created backup may recover data, provided the backup was made before setting the password.

- **Code Integrity Errors**: If code integrity checks fail, the system will attempt to restore the original code from a backup and terminate. Ensure that backup files like `myfs_code_backup.py` are present and accessible.

---