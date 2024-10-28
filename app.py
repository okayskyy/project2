from flask import Flask, jsonify, request
import jwt
import datetime
from datetime import timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from models import Key
from database import db, init_db
import base64

app = Flask(__name__)
init_db(app)  # Initialize database configuration

def generate_and_store_key(expired=False):
    # Generate an RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate a unique key ID (kid) based on the count of keys to avoid duplicates
    kid = f"key-{Key.query.count() + 1}"  # Ensure unique `kid`
    
    # Set expiration time (1 hour in the future, or in the past if expired=True)
    current_time = datetime.datetime.now(timezone.utc)
    exp = int((current_time - datetime.timedelta(hours=1)).timestamp()) if expired else int((current_time + datetime.timedelta(hours=1)).timestamp())
    
    # Serialize the private key to PEM format for storage
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Store the new key in the database with unique kid and expiration
    new_key = Key(kid=kid, private_key=private_key_bytes, exp=exp)
    db.session.add(new_key)
    db.session.commit()

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    # Retrieve all valid keys from the database (not expired)
    keys = Key.query.filter(Key.exp > int(datetime.datetime.now(timezone.utc).timestamp())).all()
    
    # Prepare JWKS response
    jwks = {"keys": []}
    for key in keys:
        try:
            # Load the private key from the database and obtain the public key
            public_key = serialization.load_pem_private_key(
                key.private_key.encode('utf-8'), 
                password=None, 
                backend=default_backend()
            ).public_key()
            
            # Convert the public key to JWKS format
            jwk_data = {
                "kty": "RSA",
                "kid": key.kid,
                "use": "sig",
                "n": base64.urlsafe_b64encode(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).decode('utf-8').rstrip("="),  # Remove trailing '=' for URL-safe encoding
                "e": "AQAB"  # Standard exponent for RSA
            }
            jwks["keys"].append(jwk_data)
        except Exception as e:
            print(f"Error loading public key for kid {key.kid}: {e}")
    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def auth():
    # Check if an expired key is requested via the 'expired' query parameter
    expired = request.args.get('expired', default='false', type=str).lower() == 'true'
    
    # Select an appropriate key based on the 'expired' parameter
    current_timestamp = int(datetime.datetime.now(timezone.utc).timestamp())
    key = Key.query.filter(Key.exp < current_timestamp).first() if expired else Key.query.filter(Key.exp > current_timestamp).first()
    
    # If no appropriate key is found, return a 404 error
    if key is None:
        return jsonify({"error": "No valid key found"}), 404
    
    # Generate a JWT using the private key from the database with the correct kid
    token = jwt.encode({
        "iat": datetime.datetime.now(timezone.utc),
        "exp": key.exp,
        "kid": key.kid  # Add the correct `kid` in JWT header
    }, key.private_key.encode('utf-8'), algorithm='RS256')

    return jsonify({"token": token})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables within the application context
        generate_and_store_key()  # Generate a valid key for testing
        generate_and_store_key(expired=True)  # Generate an expired key for testing
    app.run(port=8080)









