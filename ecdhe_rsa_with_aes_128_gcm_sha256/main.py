import hashlib
import hmac
import math
from Crypto.Cipher import AES
import handshakes
import struct


def prf(secret, label, seed, material_length=40):
    label_seed = label + seed

    def A(i):
        if i == 0:
            return label_seed
        else:
            hmac_sha256 = hmac.new(secret, msg=A(i-1), digestmod=hashlib.sha256)
            return hmac_sha256.digest()

    num_iters = math.ceil(material_length/32.0)
    p_hash = b''

    for i in range(1, num_iters+1):
        hmac_sha256 = hmac.new(secret, msg=A(i) + label_seed, digestmod=hashlib.sha256)
        p_hash += hmac_sha256.digest()

    return p_hash


if __name__ == '__main__':
    key_material = prf(secret=data.MASTER_SECRET,
                       label=b'key expansion',
                       seed=data.SERVER_RANDOM+data.CLIENT_RANDOM)

    client_write = key_material[:16]
    server_write = key_material[16:32]
    client_iv = key_material[32:36]
    server_iv = key_material[36:40]
    
    gcm_cipher = AES.new(client_write, AES.MODE_GCM, nonce=client_iv+data.ENCRYPTED_CLIENT_REQUEST[:8])
    # gcm_cipher.update(SEQUENCE_NUM+RECORD_TYPE+TLS_VERSION+LENGTH)
    compressed_len = struct.pack('!H', len(data.ENCRYPTED_CLIENT_REQUEST[8:-16]))
    tag = (b'\x00\x00\x00\x00\x00\x00\x00\x01' +
           b'\x17' +
           b'\x03\x03' +
           compressed_len)
    gcm_cipher.update(tag)
    plaintext = gcm_cipher.decrypt_and_verify(data.ENCRYPTED_CLIENT_REQUEST[8:-16],
                                              data.ENCRYPTED_CLIENT_REQUEST[-16:])
    print(plaintext)

    gcm_cipher = AES.new(server_write, AES.MODE_GCM, nonce=server_iv+data.ENCRYPTED_SERVER_RESPONSE[:8])
    compressed_len = struct.pack('!H', len(data.ENCRYPTED_SERVER_RESPONSE[8:-16]))
    gcm_cipher.update(b'\x00\x00\x00\x00\x00\x00\x00\x01' +
                      b'\x17' +
                      b'\x03\x03' +
                      compressed_len)
    plaintext = gcm_cipher.decrypt_and_verify(data.ENCRYPTED_SERVER_RESPONSE[8:-16],
                                              data.ENCRYPTED_SERVER_RESPONSE[-16:])

    # plaintext = gcm_cipher.decrypt(data.ENCRYPTED_SERVER_RESPONSE[8:-16])
    print(plaintext)
