import cbor2
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.messages import Sign1Message  # type: ignore
from pycose.keys import CoseKey
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpCurve, EC2KpX, EC2KpY, KpAlg
from pycose.algorithms import Es256

def verify(public_key_pem: str, cose_sign: bytes, raw_detached_payload: bytes) -> bool:
    """
    Verify a COSE_Sign message with a detached payload using a provided PEM-encoded public key on SECP256R1 curve.

    :param public_key_pem: The PEM-encoded public key as a string.
    :param cose_sign: The COSE_Sign structure as bytes (CBOR encoded).
    :param raw_detached_payload: The detached payload as bytes.
    :return: True if the signature is valid, False otherwise.
    """

    # Step 1: Load the PEM-encoded public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),  # Convert string to bytes
        backend=default_backend()
    )

    # Step 2: Decode the COSE_Sign structure
    cose_message = Sign1Message.decode(cose_sign)

    # Step 3: Attach the detached payload to the COSE message
    cose_message.payload = raw_detached_payload

    # Step 4: Extract parameters from the public key
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Ensure the key is on the SECP256R1 curve (also known as P-256)
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Public key is not on the SECP256R1 curve")

        # Extract the x and y coordinates from the public key
        numbers = public_key.public_numbers()
        x_coordinate = numbers.x.to_bytes(32, byteorder='big')
        y_coordinate = numbers.y.to_bytes(32, byteorder='big')

        # Manually create the COSEKey for SECP256R1 (P-256) curve
        cose_key = CoseKey.from_dict({
            KpKty: 2,  # KtyEC2 (Elliptic Curve)
            EC2KpCurve: P256,  # Curve SECP256R1 (P-256)
            EC2KpX: x_coordinate,  # X coordinate of the public key
            EC2KpY: y_coordinate,  # Y coordinate of the public key
            KpAlg: Es256  # Algorithm ES256 (ECDSA w/ SHA-256)
        })
    else:
        raise ValueError("Unsupported public key type")

    # Step 5: Verify the COSE_Sign message
    try:
        cose_message.key = cose_key  # Attach the public key for verification
        return cose_message.verify_signature()
    except Exception as e:
        print(f"Verification failed: {e}")
        return False



with open('build/cose_test.cose', 'rb') as file:
    cose_sign = file.read()

cbor_data = cbor2.loads(cose_sign)
print(cose_sign)

with open('build/cose_test.payload', 'rb') as file:
    payload = file.read()

with open('build/cose_test.key') as file:
    key = file.read()

res = verify(key, cose_sign, payload)
print("RES", res);