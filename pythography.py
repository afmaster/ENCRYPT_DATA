
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_data(data, password):
    salt = b'\xc8S\x91in\xd2\xd8\xa7\xce,\xa0\xee|\xe6\x92\xab'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    encoded = data.encode()
    ff= Fernet(key)
    encrypted= ff.encrypt(encoded)
    encrypted = encrypted.decode()
    return encrypted


def decrypt_data(data, password):
    salt = b'\xc8S\x91in\xd2\xd8\xa7\xce,\xa0\xee|\xe6\x92\xab'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    encrypted = data.encode()
    decrypted = f.decrypt(encrypted)
    decrypted = decrypted.decode()
    return decrypted

def create_salt():
    import os
    new_salt = os.urandom(16)
    return new_salt


if __name__ == "__main__":
    def test_encrypt ():
        data = "usuario" + ";" + "senha"
        password_app = "1234"
        ecpt = encrypt_data(data, password_app)
        print(ecpt)

    def test_decrypt():
        data_encrypted = "gAAAAABhnSHpGWxosJ_aF70-MVX-VGXUJGHFbdDpchSBBartlzC_rQRXBzrmVvhZwl_uZkXl5zuoHD6GUGj7c2yRj1KOlWMeBw=="
        password_app = "1234"
        dcp = decrypt_data(data_encrypted, password_app)
        print(dcp)

    def test_salt():
        new_salt = create_salt()
        print(new_salt)

    test_encrypt()
    test_decrypt()
    #test_salt()



