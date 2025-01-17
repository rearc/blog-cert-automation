import boto3
from loguru import logger
from datetime import datetime, timedelta, timezone
from helpers import format_certificate

def create_aws_client(access_key, secret_key, region):
    """
    Initialize an AWS session and create an ACM client.
    
    Args:
        access_key (str): AWS access key ID.
        secret_key (str): AWS secret access key.
        region (str): AWS region name.
    
    Returns:
        boto3.client: The ACM client if successful, otherwise False.
    """
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        # Create ACM client
        acm = session.client('acm')
        logger.success(f"AWS session and ACM client initialized.")
        return acm

    except Exception as e:
        logger.error(f"Error initializing ACM client: {e}")
        return False

def get_certificates_expiring_soon(client, days=60):
    """
    Retrieve certificates that are expiring within the next specified number of days.
    
    Args:
        client (boto3.client): The ACM client.
        days (int): The number of days to check for certificate expiration. Default is 60.
    
    Returns:
        list: A list of certificates expiring soon if successful, otherwise False.
    """

    try:
        logger.info(f"Getting certificates expiring in the next {days} days")
        response = client.list_certificates(
            Includes={
                'keyTypes': [
                    'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096', 
                    'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'
                ]
            }
        )
        certificates = response['CertificateSummaryList']
        expiring_soon = []
        for cert in certificates:
            not_after = cert['NotAfter']
            is_imported = cert['Type'] == 'IMPORTED'
            if is_imported and not_after < datetime.now(timezone.utc) + timedelta(days=days):
                expiring_soon.append(cert)
        logger.success(f"Found {len(expiring_soon)} certificates expiring in the next {days} days")
        return expiring_soon
    except Exception as e:
        logger.error(f"Error getting certificates expiring soon: {e}")
        return False

def upload_cert_to_acm(client, arn, cert, chain, private_key):
    """
    Upload a certificate to ACM with private key.
    
    Args:
        client (boto3.client): The ACM client.
        arn (str): The ARN of the certificate.
        cert (str): The certificate content.
        chain (str): The certificate chain.
        private_key (str): The private key.
    
    Returns:
        bool: True if the upload and tagging are successful, otherwise False.
    """
    try:
        logger.info(f"Uploading certificate to ACM for {arn}")
        import_response = client.import_certificate(
            CertificateArn=arn,
            Certificate=format_certificate(cert),
            PrivateKey=private_key,
            CertificateChain=format_certificate(chain),
        )
        logger.success(f"Certificate uploaded to ACM for {arn}")
        return True
    except Exception as e:
        logger.error(f"Error uploading certificate to ACM: {e.with_traceback(tb=e._traceback_)}")
        return False