# pip install pycryptodomex
import re
import base64
import hashlib
import os
import csv
import subprocess
import sys
import xml.etree.ElementTree as ET

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodomex'])
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad

PASSWORD = b'mR3m'  # mRemoteNG default (used when no password was set)
INPUT_FILE = os.path.join(os.path.dirname(__file__), 'mremoteng.xml')
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), 'connections.csv')

# mRemoteNG Protocol → RDM ConnectionType token; empty string = RDP (RDM default)
PROTOCOL_MAP = {
    'RDP':    '',
    'SSH2':   'SSHShell',
    'SSH1':   'SSHShell',
    'Telnet': 'Telnet',
    'VNC':    'VNC',
    'RLogin': 'Rlogin',
    'RAW':    'RAW',
    'HTTP':   'WebBrowser',
    'HTTPS':  'WebBrowser',
    'ICA':    'ICA',
    'IntApp': 'WebBrowser',
}

CSV_FIELDS = ['ConnectionType', 'Name', 'Group', 'Host', 'Port',
              'Username', 'Domain', 'Password', 'Description']


def gcm_decrypt(data, password):
    salt, nonce, ciphertext, tag = data[:16], data[16:32], data[32:-16], data[-16:]
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(salt)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print('Decryption failed — wrong password or non-default crypto settings.')
        raise


def cbc_decrypt(data, password):
    iv, ciphertext = data[:16], data[16:]
    key = hashlib.md5(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def decrypt_password(mode, encoded, master_pw):
    if not encoded:
        return ''
    try:
        raw = base64.b64decode(encoded)
        if not raw:
            return ''
        return gcm_decrypt(raw, master_pw) if mode == 'GCM' else cbc_decrypt(raw, master_pw)
    except Exception as e:
        return f'[decrypt error: {e}]'


def walk_nodes(parent, mode, master_pw, group_path=''):
    rows = []
    for child in parent:
        # Strip XML namespace prefix if present
        local = child.tag.split('}')[-1] if '}' in child.tag else child.tag
        if local != 'Node':
            continue
        node_type = child.get('Type', '')
        name = child.get('Name', '')
        if node_type == 'Container':
            new_group = f'{group_path}\\{name}' if group_path else name
            rows.extend(walk_nodes(child, mode, master_pw, new_group))
        elif node_type == 'Connection':
            protocol = child.get('Protocol', 'RDP')
            conn_type = PROTOCOL_MAP.get(protocol, protocol)
            rows.append({
                'ConnectionType': conn_type,
                'Name':           name,
                'Group':          group_path,
                'Host':           child.get('Hostname', ''),
                'Port':           child.get('Port', ''),
                'Username':       child.get('Username', ''),
                'Domain':         child.get('Domain', ''),
                'Password':       decrypt_password(mode, child.get('Password', ''), master_pw),
                'Description':    child.get('Descr', ''),
            })
    return rows


with open(INPUT_FILE, 'r', encoding='utf-8') as f:
    conf = f.read()

mode_match = re.findall('BlockCipherMode="([^"]*)"', conf)
mode = 'GCM' if mode_match and mode_match[0] == 'GCM' else 'CBC'

full_enc = re.findall('FullFileEncryption="([^"]*)"', conf)
if full_enc and full_enc[0] == 'true':
    cipher_b64 = re.findall('<.*>(.+)</mrng:Connections>', conf)[0]
    raw = base64.b64decode(cipher_b64)
    conf = gcm_decrypt(raw, PASSWORD) if mode == 'GCM' else cbc_decrypt(raw, PASSWORD)

root = ET.fromstring(conf)
rows = walk_nodes(root, mode, PASSWORD)

with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)

print(f'Exported {len(rows)} connections to {OUTPUT_FILE}')
