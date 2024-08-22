# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.cose import from_cryptography_eckey_obj

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from pycose.messages import Sign1Message  # type: ignore
from cryptography.hazmat.primitives import serialization

def get_cert_key_type(cert_pem: str) -> str:
    cert = serialization.load_pem_public_key(cert_pem.encode("ascii"), backend=default_backend())
    if isinstance(cert, EllipticCurvePublicKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def verify_cose_sign1(buf: bytes, cert_pem: str, detached_payload=None):
    key_type = get_cert_key_type(cert_pem)
    cert = serialization.load_pem_public_key(cert_pem.encode("ascii"), backend=default_backend())
    key = cert
    if key_type == "ec":
        cose_key = from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError("unsupported key type")
    msg = Sign1Message.decode(buf)
    msg.key = cose_key

    if detached_payload:
        msg.payload = detached_payload

    if not msg.verify_signature():
        raise ValueError("signature is invalid")
    return msg
