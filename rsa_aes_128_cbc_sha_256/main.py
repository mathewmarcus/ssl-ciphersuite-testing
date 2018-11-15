import hashlib
import hmac
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
import data

KEY_FILE = './server.key'


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


def mac(mac_secret, seq_num, type_, version, length, iv, enc):
    hmac_sha256 = hmac.new(mac_secret, seq_num+type_+version+length+iv+enc, digestmod=hashlib.sha1)
    return hmac_sha256.digest()


def main():
    with open(KEY_FILE) as f:
        server_private_key = RSA.import_key(f.read())

    cipher = PKCS1_v1_5.new(server_private_key)
    pre_master_secret = cipher.decrypt(data.PREMASTER_SECRET, None)

    # master_secret = prf(pre_master_secret,
    #                     b'master secret',
    #                     data.CLIENT_RANDOM+data.SERVER_RANDOM,
    #                     material_length=48)[:48]
    # print(master_secret.hex())

    handshake_messages = data.CLIENT_HELLO + data.SERVER_HELLO + data.CERTIFICATE + data. SERVER_HELLO_DONE + data.CLIENT_KEY_EXCHANGE

    session_hash = hashlib.sha256(handshake_messages).digest()
    print('Session hash SHA256: {}'.format(hashlib.sha256(handshake_messages).hexdigest()))
    print('Session hash MD5: {}'.format(hashlib.md5(handshake_messages).hexdigest()))
    print('Session hash SHA: {}'.format(hashlib.sha1(handshake_messages).hexdigest()))
    master_secret = prf(secret=pre_master_secret,
                        label=b'extended master secret',
                        seed=session_hash,
                        material_length=48)[:48]
    print('Master secret: {}'.format(master_secret.hex()))
    key_material = prf(secret=master_secret,
                       label=b'key expansion',
                       seed=data.SERVER_RANDOM+data.CLIENT_RANDOM,
                       material_length=104)

    client_write_MAC_key = key_material[:20]
    server_write_MAC_key = key_material[20:40]
    client_write_key = key_material[40:56]
    server_write_key = key_material[56:72]
    client_iv = key_material[72:88]
    server_iv = key_material[88:104]

    print('Client write MAC key: {}'.format(client_write_MAC_key.hex()))
    print('Server write MAC key: {}'.format(server_write_MAC_key.hex()))
    print('Client write key: {}'.format(client_write_key.hex()))
    print('Server write key: {}'.format(server_write_key.hex()))
    cbc_cipher = AES.new(client_write_key, AES.MODE_CBC, IV=data.ENCRYPTED_CLIENT_REQUEST[:16])
    # cbc_cipher = AES.new(client_write_key, AES.MODE_CBC, IV=client_iv)
    plaintext = cbc_cipher.decrypt(data.ENCRYPTED_CLIENT_REQUEST[:-20])
    print(plaintext[:16].hex())
    print('MAC: {}'.format(data.ENCRYPTED_CLIENT_REQUEST[-20:].hex()))
    print('IV: {}'.format(data.ENCRYPTED_CLIENT_REQUEST[:16].hex()))

    print('Calculated MAC: {}'.format(mac(client_write_MAC_key, b'\x00\x00\x00\x00\x00\x00\x00\x01',
                                          b'\x17',
                                          b'\x03\x03',
                                          b'\x00\x60',
                                          data.ENCRYPTED_CLIENT_REQUEST[:16],
                                          data.ENCRYPTED_CLIENT_REQUEST[16:-20])
                                      .hex()))
    print(plaintext)

    server_cbc_cipher = AES.new(server_write_key, AES.MODE_CBC, IV=data.ENCRYPTED_SERVER_RESPONSE[:16])
    # server_cbc_cipher = AES.new(server_write_key, AES.MODE_CBC, IV=server_iv)
    server_plaintext = server_cbc_cipher.decrypt(data.ENCRYPTED_SERVER_RESPONSE[16:-20])
    print(server_plaintext)

if __name__ == '__main__':
    main()
