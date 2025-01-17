import argparse
from loguru import logger
from ca import generate_openssl_key, generate_csr, submit_csr_to_ca
from aws import create_aws_client, get_certificates_expiring_soon, upload_cert_to_acm

def main(args: argparse.Namespace):
    
    # Create an AWS boto client for ACM operations
    client = create_aws_client(args.aws_access_key_id, args.aws_secret_access_key, args.aws_region)

    # Get all certificates from ACM expiring soon
    certificates_list = get_certificates_expiring_soon(client, args.days_to_expire)
    
    for cert in certificates_list:
        logger.info(f"Now working on renewal for {cert['DomainName']}")
        
        # Generate key material
        pemkey = generate_openssl_key(args.key_bitsize)

        # Generate CSR
        csr = generate_csr(cert["DomainName"], pemkey)
        
        # Submit to CA, retrieve cert, and intermediate and root chain
        certificate, chain = submit_csr_to_ca(cert["DomainName"], csr)
        
        # Upload cert to ACM and associate with the existing certificate ARN
        upload_cert_to_acm(client, cert["CertificateArn"], certificate, chain, pemkey)
        
    logger.success("Certificate maintenance completed.")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Script to handle provisioning of private ca signed certs')
    parser.add_argument("--days-to-expire", type=int, default=60, dest="days_to_expire",
                        help="Specify the number of days before expiration to renew the certificate.")
    parser.add_argument("--key-bitsize", type=int, default=3072, dest="key_bitsize",
                        help="Specify the bitsize for the generated key material.")
    parser.add_argument("--aws-access-key-id", type=str, required=True, dest="aws_access_key_id",
                        help="AWS access key ID for authentication.")
    parser.add_argument("--aws-secret-access-key", type=str, required=True, dest="aws_secret_access_key",
                        help="AWS secret access key for authentication.")
    parser.add_argument("--aws-region", type=str, required=True, dest="aws_region", 
                        help="AWS region for ACM operations.")

                        
    cli_args = parser.parse_args()
    
    main(cli_args)