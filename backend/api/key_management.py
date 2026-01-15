from Crypto.PublicKey import ECC
from datetime import datetime, timedelta
import json
import os

KEYS_DIR = "keys"
METADATA_FILE = f"{KEYS_DIR}/metadata.json"


def generate_keys():
    key = ECC.generate(curve="ed448")
    private_key_pem = key.export_key(format="PEM")
    public_key_pem = key.public_key().export_key(format="PEM")
    return private_key_pem, public_key_pem


def save_keys(private_key_pem, public_key_pem, timestamp):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    with open(f"{KEYS_DIR}/private_key_{timestamp}.pem", "wb") as f:
        f.write(private_key_pem.encode("utf-8"))
    with open(f"{KEYS_DIR}/public_key_{timestamp}.pem", "wb") as f:
        f.write(public_key_pem.encode("utf-8"))
    return


def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return None
    with open(METADATA_FILE, "r") as f:
        return json.load(f)


def save_metadata(metadata):
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f)


def should_rotate_key(metadata):
    last_rotation = datetime.fromisoformat(metadata["last_rotation"])
    rotation_interval = timedelta(days=metadata["rotation_interval_days"])
    return datetime.now() >= last_rotation + rotation_interval


def rotate_keys():
    private_key_pem, public_key_pem = generate_keys()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    save_keys(private_key_pem, public_key_pem, timestamp)
    metadata = {
        "active_private_key": f"private_key_{timestamp}.pem",
        "active_public_key": f"public_key_{timestamp}.pem",
        "last_rotation": datetime.now().isoformat(),
        "rotation_interval_days": 90,  # Customize this interval as needed
    }
    save_metadata(metadata)
    return


def initialize_keys():
    metadata = load_metadata()
    if metadata is None:
        rotate_keys()
        metadata = load_metadata()
    return metadata


def get_active_private_key():
    metadata = initialize_keys()
    if should_rotate_key(metadata):
        rotate_keys()
        metadata = load_metadata()
    active_private_key = metadata["active_private_key"]
    with open(f"{KEYS_DIR}/{active_private_key}", "rb") as f:
        return f.read()


def get_active_public_key():
    metadata = initialize_keys()
    active_public_key = metadata["active_public_key"]
    with open(f"{KEYS_DIR}/{active_public_key}", "rb") as f:
        return f.read()
