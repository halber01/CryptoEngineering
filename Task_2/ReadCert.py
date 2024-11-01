# If it does not work, then you can try the command "pip install cryptography"
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization


def ReadPKfromX509Cert(certificate):
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey): # RSA format
        public_numbers = public_key.public_numbers()
        n = public_numbers.n  # Modulus
        e = public_numbers.e  # Exponent
        return f"RSA pk - (n,e) = ({hex(n)}, {hex(e)})"

    elif isinstance(public_key, ec.EllipticCurvePublicKey): # EC format
        public_numbers = public_key.public_numbers()
        x = public_numbers.x
        y = public_numbers.y
        return f"EC pk - (x,y) = ({hex(x), hex(y)})"

    else:
        try:
            public_key_der_format = public_key.public_bytes( # A generic method to read the pk in hex format
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return public_key_der_format
        except:
            return "Unknown public key format"


def ReadCert(directory): # Load the certificate from a file
    with open(directory, "rb") as cert_file:
        cert_data = cert_file.read()
    return cert_data


def main():
    # Read the cert
    directory = "certificate.pem"
    cert_data = None
    try:
        cert_data = ReadCert(directory)
    except:
        print("Fail to read a certificate. Export a certificate (in pem format) and place is in the same directory as the Python file.")
        return

    # Parse the certificate
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Parse the public key
    public_key_in_cert = ReadPKfromX509Cert(certificate)

    # Extract information from the certificate
    print("\nVersion:", certificate.version, "\n")
    print("Serial Number:", certificate.serial_number, "\n")
    print("Issuer:", certificate.issuer.rfc4514_string(), "\n")
    print("Subject:", certificate.subject.rfc4514_string(), "\n")
    print("Validity Period:")
    print("  Not Before:", certificate.not_valid_before)
    print("  Not After:", certificate.not_valid_after, "\n")
    print("Public Key:", public_key_in_cert, "\n")
    print("Signature Algorithm (used by the issuer CA):", certificate.signature_algorithm_oid._name)
    print("Signature (generated by the issuer CA):", certificate.signature.hex())

    # Extract and display extensions
    print("\nExtensions:\n")
    for ext in certificate.extensions:
        print(f"  - {ext.oid._name}: {ext.value}\n")

if __name__ == "__main__":
    main()