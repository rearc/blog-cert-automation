# Certificate Maintenance

This project handles the provisioning, rotation, and uploading of private CA-signed certificates to AWS ACM.

## Requirements

- Python 3.6+
- `loguru==0.7.2`
- `boto3==1.34.134`
- `cryptography==39.0.0`

Install the required packages using:
```sh
pip install -r requirements.txt
```

## Files

- `__init__.py`: Initialization file for the package.
- `aws.py`: Contains functions to interact with AWS ACM.
- `ca.py`: Contains functions to generate keys, CSRs, and interact with the CA.
- `certificate_maintenance.py`: Main script to handle certificate maintenance.
- `requirements.txt`: List of required Python packages.
- `helpers.py`: Contains utility functions used across the project.

## Usage

Run the `certificate_maintenance.py` script, optionally with the following arguments:

The script accepts the following arguments:

- `--days-to-expire`: Specify the number of days before expiration to renew the certificate. Default is 60.
- `--key-bitsize`: Specify the bitsize for the generated key material. Default is 3072.
- `--aws-access-key-id`: AWS access key ID for authentication. This parameter is required.
- `--aws-secret-access-key`: AWS secret access key for authentication. This parameter is required.
- `--aws-region`: AWS region for ACM operations. This parameter is required.

Example:
```sh
python certificate_maintenance.py --days-to-expire 30 --key-bitsize 2048 --aws-access-key-id YOUR_AWS_KEY --aws-secret-access-key YOUR_AWS_SECRET_KEY --aws-region us-west-2
```

## Functions

### aws.py

- `create_aws_client`: Initializes an AWS session and creates an ACM client.
- `get_certificates_expiring_soon`: Retrieves certificates that are expiring within the next specified number of days.
- `upload_cert_to_acm`: Uploads a certificate, private key, and chain to AWS ACM.

### ca.py

- `generate_openssl_key`: Generates an RSA private key with the specified bit size.
- `generate_csr`: Generates a Certificate Signing Request (CSR) for the given DNS name.
- `submit_csr_to_ca`: Submits a CSR to the CA and gets the issued certificate and its chain.

### certificate_maintenance.py

- `main`: Main function to handle certificate maintenance.

### helpers.py

- `format_certificate`: Formats a certificate string or a list of certificate strings to be well-formed with proper headers and footers.

## License

This project is licensed under the MIT License.
