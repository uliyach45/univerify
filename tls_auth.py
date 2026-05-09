import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def compute_file_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def get_cert_fingerprint(cert_pem_bytes):
    cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    fingerprint = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fingerprint)


def sign_file_hash(file_hash_hex, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    signature = private_key.sign(
        file_hash_hex.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(file_hash_hex, signature_b64, cert_pem_bytes):
    from cryptography.exceptions import InvalidSignature
    cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    public_key = cert.public_key()
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            file_hash_hex.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def extract_cert_from_request(request):
    cert_pem = request.environ.get("SSL_CLIENT_CERT")
    if not cert_pem:
        return None, None, None
    cert_pem_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    fingerprint = get_cert_fingerprint(cert_pem_bytes)
    cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    subject_dn = cert.subject.rfc4514_string()
    return cert_pem_bytes, fingerprint, subject_dn
