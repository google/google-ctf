#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import hmac
import hashlib
import time
import ssl
import os

from cryptography import x509
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from google.cloud import datastore
import OpenSSL.crypto


DOMAIN_PEM = '/tmp/domain.pem'
DOMAIN_KEY = '/tmp/domain.key'


ISSUER = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'hrefin'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Href Ltd.'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Default CA Deployment'),
])

def get_ca_cert():
    try:
        return open('ca.pem').read()
    except IOError:
        return None

def get_ca_key():
    try:
        return open('ca.key').read()
    except IOError:
        return None

def verifyCallback(connection, cert, errnum, errdepth, ok):
    if not ok:
        der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert.to_cryptography())

        issuer_public_key = serialization.load_pem_private_key(get_ca_key(), None, default_backend()).public_key()
        cert_to_check = x509.load_der_x509_certificate(der, default_backend())

        try:
            issuer_public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_check.signature_hash_algorithm,
            )
        except cryptography.exceptions.InvalidSignature:
            return False

        return True

    return True

def build_csr(domain):
    try:
        private_key = serialization.load_pem_private_key(DOMAIN_KEY, None, default_backend())
    except ValueError:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(DOMAIN_KEY, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.COMMON_NAME, unicode(domain)),
    ])).sign(private_key, hashes.SHA256(), default_backend())

    return csr

def setup_ca():
    ds = datastore.Client()

    if get_ca_cert():
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    builder = builder.subject_name(ISSUER)
    builder = builder.issuer_name(ISSUER)
    builder = builder.not_valid_before(datetime.datetime(2018, 1, 1))
    builder = builder.not_valid_after(datetime.datetime(2019, 1, 1))
    builder = builder.serial_number(1337)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA1(),
        backend=default_backend()
    )

    with open("ca.key", "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        ))


    with open("ca.pem", "wb") as f:
        f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))


def setup_domain(domain):
    ca_key = get_ca_key()
    assert ca_key

    ca_key = serialization.load_pem_private_key(ca_key, None, default_backend())


    csr = build_csr(domain)

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ISSUER)

    builder = builder.not_valid_before(datetime.datetime(2018, 1, 1))
    builder = builder.not_valid_after(datetime.datetime(2019, 1, 1))

    builder = builder.serial_number(31337)
    builder = builder.public_key(csr.public_key())

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    with open(DOMAIN_PEM, "wb") as f:
        f.write(certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
        ))

def setup(domain):
    if not os.path.exists("ca.key") or not os.path.exists("ca.pem"):
        setup_ca()
    if not os.path.exists(DOMAIN_KEY) or not os.path.exists(DOMAIN_PEM):
        setup_domain(domain)

def get_subject_dict(subject):
    res = {'company': 'None', 'country': 'AA'}

    for attr in subject:
        if attr.oid == NameOID.COMMON_NAME:
            res['name'] = attr.value
        if attr.oid == NameOID.ORGANIZATION_NAME:
            res['company'] = attr.value
        if attr.oid == NameOID.COUNTRY_NAME:
            res['country'] = attr.value
    return res

def parse_cert(cert, der=False):
    if der:
        cert = x509.load_der_x509_certificate(cert, default_backend())
    else:
        cert = x509.load_pem_x509_certificate(str(cert), default_backend())

    return get_subject_dict(cert.subject)

def parse_csr(csr):
    csr = x509.load_pem_x509_csr(str(csr), default_backend())

    return get_subject_dict(csr.subject)

def gen_serial():
    # changes every 20min
    seed = int(time.time()) / 60 / 20
    h = hmac.new('serialzkey!!', str(seed), hashlib.sha256).hexdigest()

    return int(h[:16], 16) | 1 << 64

def sign_csr(csr):
    csr = x509.load_pem_x509_csr(str(csr), default_backend())
    ca_key = serialization.load_pem_private_key(get_ca_key(), None, default_backend())

    if csr.public_key().key_size > 2048:
        return {'error': 'key_size'}

    if len(csr.subject.public_bytes(default_backend())) > 350:
        return {'error': 'subject_size'}

    if not csr.is_signature_valid:
        return {'error': 'invalid_signature'}

    if len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) != 1:
        return {'error': 'invalid_name'}

    for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        username = attr.value

        if username.lower() == 'admin':
            return {'error': 'invalid_name'}


    builder = x509.CertificateBuilder()

    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ISSUER)

    builder = builder.not_valid_before(datetime.datetime(2018, 1, 1))
    builder = builder.not_valid_after(datetime.datetime(2019, 1, 1))
    builder = builder.serial_number(gen_serial())
    builder = builder.public_key(csr.public_key())

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.MD5(),
        backend=default_backend()
    )

    return {'result': certificate.public_bytes(encoding=serialization.Encoding.PEM)}
