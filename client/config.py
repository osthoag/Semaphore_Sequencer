import sys

sys.path.append("../sequencer_version")
import params as pm
import database as db
import hashing as hs
import ecdsa
import socket
import os
from wrappers import Alias


# connection info for node
if pm.SEQUENCER_IP =="":
    SEQUENCER_IP = socket.gethostbyname("localhost")
else:
    SEQUENCER_IP = pm.SEQUENCER_IP
    
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_socket.connect((SEQUENCER_IP, pm.SEQUENCER_PORT))
client_socket.setblocking(False)

# distinguish between different clients running on the same machine
sys_id = input("id: ")
if sys_id != "":
    sys_id = "/" + sys_id
identity_processor = None

# initialize stuffs
path = f".{sys_id}/client_db"
if os.path.exists(path):
    initialized = True
else:
    initialized = False
    os.makedirs(path)
db = db.ClientDatabase(path, reset=bool(pm.RESET))

if not initialized:
    pk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    db.set_privkey(pk.to_string())
client_privkey = ecdsa.SigningKey.from_string(
    db.misc_values.get(b"privkey"), curve=ecdsa.SECP256k1
)
client_pubkey = client_privkey.get_verifying_key()

db.misc_values.put(client_pubkey.to_string(), client_privkey.to_string())  # type: ignore

if db.misc_values.get(b"alias") is not None:
    alias = Alias(db.misc_values.get(b"alias"))
else:
    alias = Alias(b'\xff\xff\xff\xff')


sequencer_pubkey = ecdsa.VerifyingKey.from_string(
    bytes.fromhex(pm.SEQUENCER_PUBKEY), curve=ecdsa.SECP256k1
)

show_messages = True
