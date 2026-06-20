# mremoteng-to-rdm

Decrypt an mRemoteNG `confCons.xml` export and convert it to a CSV file ready to import into **Remote Desktop Manager** (Devolutions).

## What it does

- Decrypts connection passwords using mRemoteNG's default master password (`mR3m`) — the password used when you never set a custom one
- Supports both AES-GCM (mRemoteNG v1.76+) and AES-CBC (older versions)
- Preserves your folder hierarchy as RDM **Groups**
- Maps mRemoteNG protocols to RDM connection types (RDP, SSH Shell, VNC, Web Browser, etc.)
- Outputs a standards-compliant CSV for RDM's **Import Generic CSV Wizard**

## Requirements

- Python 3.8+
- [`pycryptodomex`](https://pypi.org/project/pycryptodomex/) — installed automatically on first run

## Usage

1. Export your connections from mRemoteNG:  
   **File → Export Connections → Export to file** → save as `mremoteng.xml`

2. Place `mremoteng.xml` in the same folder as the script.

3. Run the script:
   ```bash
   python decrypt_mremoteng.py
   ```

4. A `connections.csv` file is created in the same folder.

5. Import into Remote Desktop Manager:  
   **File → Import → Import Generic CSV Wizard** → select `Session` as the header format → choose `connections.csv`

## If you set a custom master password

Edit line 17 in the script and replace `mR3m` with your password:

```python
PASSWORD = b'your-master-password-here'
```

## Protocol mapping

| mRemoteNG | RDM ConnectionType |
|-----------|-------------------|
| RDP | *(RDM default)* |
| SSH2 / SSH1 | SSHShell |
| VNC | VNC |
| Telnet | Telnet |
| HTTP / HTTPS / IntApp | WebBrowser |
| ICA | ICA |
| RLogin | Rlogin |
| RAW | RAW |

## Output format

```
ConnectionType,Name,Group,Host,Port,Username,Domain,Password,Description
SSHShell,Web Server,Production,192.168.1.10,22,root,,s3cr3t,
,Dev RDP,Development\Windows,10.0.0.5,3389,admin,CORP,p@ss,,
```

## Security note

The output CSV contains **plaintext passwords**. Delete it after importing into RDM and ensure it never ends up in version control.

## License

MIT
