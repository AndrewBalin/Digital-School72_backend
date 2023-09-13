from cryptography.fernet import Fernet
from ds72.settings import SECRET_KEY, FERNET_ENCODE_KEY

def fernet_msg_encode(msg: str) -> bytes:
    fernet = Fernet(FERNET_ENCODE_KEY)
    return fernet.encrypt(msg.encode())


def fernet_msg_decode(hash: bytes) -> str:
    fernet = Fernet(FERNET_ENCODE_KEY)
    return fernet.decrypt(hash).decode()