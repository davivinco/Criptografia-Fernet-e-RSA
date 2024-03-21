from flask import Flask, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import dns.resolver

# Geração de chave simétrica
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Geração de chave assimétrica
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

app = Flask(__name__)

@app.route('/dns_lookup', methods=['GET'])
def dns_lookup():
    domain = request.args.get('domain')
    try:
        result = dns.resolver.resolve(domain, 'A')
        return {'result': str(result[0])}
    except Exception as e:
        return {'error': str(e)}

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')
    encrypted_message = cipher_suite.encrypt(message.encode())
    return {'encrypted_message': encrypted_message.decode()}

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message = data.get('encrypted_message')
    decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
    return {'decrypted_message': decrypted_message.decode()}

if __name__ == '__main__':
    app.run(debug=True)
