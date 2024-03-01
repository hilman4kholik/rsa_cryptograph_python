from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key_from_file(filename, is_private=True):
    with open(filename, 'rb') as f:
        key_data = f.read()

    if is_private:
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    else:
        return serialization.load_pem_public_key(key_data, backend=default_backend())

def encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Contoh penggunaan:
private_key, public_key = generate_key_pair()

# Simpan kunci ke file
save_key_to_file(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ),
    'private_key.pem'
)

save_key_to_file(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
    'public_key.pem'
)

# Load kunci dari file
loaded_private_key = load_key_from_file('private_key.pem')
loaded_public_key = load_key_from_file('public_key.pem', is_private=False)



# Pesan untuk dienkripsi
original_message = "askjdhkfuKJHKSUADHK!@#.,dj1234ljksdfkjhxc,nmk###kjhsdfd"

# Enkripsi
ciphertext = encrypt(original_message, loaded_public_key)
print(f'Ciphertext: {ciphertext}')
save_key_to_file(
    ciphertext,
    'encrypted_msg.txt'
)

with open('encrypted_msg.txt', 'rb') as f:
    result = f.read()
# Dekripsi
decrypted_message = decrypt(result, loaded_private_key)
print(f'Decrypted Message: {decrypted_message}')
