import json
from loguru import logger
import requests
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography import x509 
from cryptography.x509.oid import NameOID 
from cryptography.hazmat.primitives import hashes

def generate_openssl_key(bitsize):
    """
    Generate an RSA private key with the specified bit size.
    
    Args:
        bitsize (int): The bit size of the RSA key.
    
    Returns:
        bytes: The PEM-encoded private key.
        bool: False if an error occurs.
    """
    # Generate an RSA private key with the specified bit size
    try:
        logger.info(f"Generating key with {bitsize} bits")
        key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=bitsize,
        )
        pemkey = key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.TraditionalOpenSSL, 
                encryption_algorithm=serialization.NoEncryption()
        )
        return pemkey
    except Exception as e:
        logger.error("Error generating key: {e}")
        return False

def generate_csr(dnsname, pemkey):
    """
    Generate a Certificate Signing Request (CSR) for the given DNS name.
    
    Args:
        dnsname (str): The DNS name for the certificate.
        pemkey (bytes): The PEM-encoded private key.
    
    Returns:
        bytes: The PEM-encoded CSR.
        bool: False if an error occurs.
    """
    # Generate a Certificate Signing Request (CSR) for the given DNS name
    try:
        logger.info(f"Generating CSR for {dnsname}")
        key = serialization.load_pem_private_key(pemkey, password=None)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"New York"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"New York"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Rearc"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Delivery"),
            x509.NameAttribute(NameOID.COMMON_NAME, dnsname),
        ])).sign(key, hashes.SHA256())
        pemcsr = csr.public_bytes(serialization.Encoding.PEM)
        return pemcsr
    except Exception as e:
        logger.error(f"Error generating CSR for {dnsname}: {e}")
        return False

def submit_csr_to_ca(dnsname, csr):
    """
    Submit a Certificate Signing Request (CSR) to the CA and get the issued certificate and its chain.
    
    This function interacts with an EJBCA (Enterprise Java Beans Certificate Authority) server to submit a CSR and retrieve the issued certificate and its chain.
    EJBCA is an open-source PKI (Public Key Infrastructure) certificate authority software, which provides a robust and flexible solution for managing digital certificates.
    For more information, visit: https://www.ejbca.org/
    
    Args:
        dnsname (str): The DNS name for the certificate.
        csr (str): The PEM-encoded CSR.
    
    Returns:
        tuple: The issued certificate, and the certificate chain.
        bool: False if an error occurs.
    """
    
    # EJBCA REST API endpoint for certificate request
    url = 'https://<ejbca-server>/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll'

    # Data to be sent in the POST request
    data = {
        "certificate_request":csr.decode('utf-8'),
        "certificate_profile_name":"ENDUSER",
        "end_entity_profile_name":"User",
        "certificate_authority_name":"ManagementCA",
        "username":"User",
        "password":"abc123",
        "include_chain": True,
        "email": "useremail@domain.com",
        "response_format": "DER"
    }

    headers = {
        'Content-type': 'application/json',
    }
    
    try:
        logger.info(f"Submitting CSR for {dnsname}")
        response = requests.post(url, data=json.dumps(data), headers=headers)
        response.raise_for_status()
        
        # Get the certificate and chain from the response
        response_data = response.json()
        
        # Get the issued certificate
        certificate = response_data['certificate']
        
        # Get the certificate chain associated with the CA
        chain = response_data['certificate_chain']
        
        logger.success(f"Certificate issued for {dnsname}") 
        return certificate, chain
    
    except Exception as e:
        logger.error(f"Error submitting CSR for {dnsname}: {e}")
        return False
