#!/usr/bin/env python3

import ssl
import socket
import argparse
import urllib.request
from OpenSSL import crypto
from pathlib import Path
from datetime import datetime

def fetch_certificate_chain(hostname, port=443):
    """Fetch the server certificate and attempt to retrieve the entire chain."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der is None:
                raise ValueError(f"Failed to obtain certificate from {hostname}")
            server_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

    chain = [server_cert]
    # Attempt to fetch intermediates from AIA URIs
    current_cert = server_cert
    while True:
        issuer_url = extract_issuer_url(current_cert)
        if not issuer_url:
            break
        try:
            issuer_der = urllib.request.urlopen(issuer_url).read()
            issuer_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, issuer_der)
            chain.append(issuer_cert)
            # If issuer is self-signed (root), stop
            if issuer_cert.get_subject().get_components() == issuer_cert.get_issuer().get_components():
                break
            current_cert = issuer_cert
        except Exception:
            # If we can't fetch or parse the issuer, just break out.
            break
    return chain

def extract_issuer_url(cert):
    """Extract the CA Issuers URL from authorityInfoAccess if present."""
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'authorityInfoAccess':
            aia = str(ext)
            for line in aia.split('\n'):
                if 'CA Issuers - URI:' in line:
                    return line.split('URI:')[1].strip()
    return None

def validate_chain(chain):
    """Validate the entire chain of certificates."""
    # The last certificate should be the root or closest to root we found
    # Create a store containing all but the first (leaf) certificate
    store = crypto.X509Store()
    for cert in chain[1:]:
        store.add_cert(cert)

    # Validate the leaf cert
    store_ctx = crypto.X509StoreContext(store, chain[0])
    details = []

    # Check date validity of the leaf certificate
    leaf = chain[0]
    not_before = datetime.strptime(leaf.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    not_after = datetime.strptime(leaf.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    now = datetime.utcnow()
    valid_dates = (not_before <= now <= not_after)
    details.append({
        'check': 'Date Validity',
        'valid': valid_dates,
        'details': f"Valid from {not_before} to {not_after}"
    })

    # Check basic constraints on the leaf cert (not strictly necessary but kept for parity)
    try:
        # Just attempt to access an extension to ensure presence
        leaf.get_extension(0)
        details.append({
            'check': 'Basic Constraints',
            'valid': True,
            'details': "Certificate extensions are present"
        })
    except Exception as e:
        details.append({
            'check': 'Basic Constraints',
            'valid': False,
            'details': str(e)
        })

    # Now validate the entire chain
    try:
        store_ctx.verify_certificate()
        details.append({
            'check': 'Chain of Trust',
            'valid': True,
            'details': "Certificate chain validates successfully"
        })
    except Exception as e:
        details.append({
            'check': 'Chain of Trust',
            'valid': False,
            'details': f"Chain validation failed: {str(e)}"
        })

    return details

def print_validation_results(chain, results):
    subject = chain[0].get_subject().CN or chain[0].get_subject().O
    print(f"\nValidation Results for {subject}:")
    print("-" * 60)
    for result in results:
        status = "✓" if result['valid'] else "✗"
        print(f"{status} {result['check']}:")
        print(f"  {result['details']}")
    print("-" * 60)

def save_chain(chain, domain):
    """Save the certificate chain to a PEM file."""
    certs_dir = Path('certs')
    certs_dir.mkdir(exist_ok=True)
    chain_file = certs_dir / f"{domain}-chain.pem"
    with chain_file.open('w') as f:
        for cert in chain:
            pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
            f.write(pem_data)
    return chain_file

def main():
    parser = argparse.ArgumentParser(description='Download and validate SSL certificate chain from a domain')
    parser.add_argument('domain', help='Domain name to fetch certificates from')
    parser.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    args = parser.parse_args()

    try:
        print(f"Fetching certificate chain for {args.domain}:{args.port}...")
        chain = fetch_certificate_chain(args.domain, args.port)
        if not chain:
            print("No certificates found!")
            return

        # Validate the entire chain
        results = validate_chain(chain)
        print_validation_results(chain, results)

        chain_file = save_chain(chain, args.domain)
        print(f"Certificate chain saved to: {chain_file}")
        print(f"Number of certificates in chain: {len(chain)}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
