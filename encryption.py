from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import logging
import config
import logg

log = logg.setup_logger(name="Genbu-Encryption", level=logging.DEBUG)

class EncryptionHelper:
    """Class for encryption and decryption processes"""
    @staticmethod
    def aes_encrypt(plaintext: bytes) -> bytes:
        """
        function for AES encrypt the given plaintext
        :param plaintext:
        :return: ciphertext
        """
        cipher = AES.new(config.SECRET_KEY, AES.MODE_CBC) #create new cipher
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        log.debug(f"First Ciphertext: {ciphertext}")
        ciphertext = cipher.iv + ciphertext #this way we dont send the IV back, so I've opted to put the IV and ciphertext together
        log.debug(f"IV: {cipher.iv}")
        log.debug(f"IV + Ciphertext: {ciphertext}")

        return ciphertext

    @staticmethod
    def aes_decrypt(ciphertext: bytes) -> bytes:
        """
        function for AES Decrypting
        :param ciphertext:
        :param secretkey:
        :return:
        """
        iv = ciphertext[:AES.block_size] #separating the IV
        log.debug(f"IV: {iv}")
        ciphertext = ciphertext[AES.block_size:]
        log.debug(f"Ciphertext: {ciphertext}")
        cipher = AES.new(config.SECRET_KEY, AES.MODE_CBC, iv=iv) #create new instance
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        log.debug(f"Decrypted: {decrypted}")
        return decrypted

    @staticmethod
    def generate_hmac(ciphertext: bytes) -> str:
        """
        function for generating hmac
        :param ciphertext:
        :param secretkey:
        :return:
        """
        mac = hmac.new(config.SECRET_KEY, ciphertext, hashlib.sha256).hexdigest() #hexdigest so it can be send in a json
        log.debug(f" NEW GENERATED HMAC: {mac} for {ciphertext}")
        return mac

    @staticmethod
    def verify_hmac(ciphertext: bytes, received_hmac: str) -> bool:
        """
        function for verifying hmac
        :param ciphertext:
        :param received_hmac:
        :return:
        """
        calculated_hmac = EncryptionHelper.generate_hmac(ciphertext=ciphertext)
        log.debug(f"CALCULATED HMAC: {calculated_hmac}")
        log.debug(f"RECEIVED CIPHERTEXT: {ciphertext}")
        log.debug(f"RECEIVED HMAC: {received_hmac}")
        return hmac.compare_digest(calculated_hmac, received_hmac)



if __name__ == '__main__':
    # Example usage
    message = b"Hello World"
    key = get_random_bytes(16)  # 128-bit key
    encrypted_message = EncryptionHelper.aes_encrypt(message)

    hmac = EncryptionHelper.generate_hmac(encrypted_message)
    # Assume the message has been transmitted and received elsewhere
    # Verify HMAC before decryption
    if EncryptionHelper.verify_hmac(encrypted_message, hmac):
        decrypted_message = EncryptionHelper.aes_decrypt(encrypted_message)
        print(type(message))
        print(type(encrypted_message))
        print(type(decrypted_message))
        print("Original Message:", message)
        print("Encrypted Message:", encrypted_message)
        print("Decrypted Message:", decrypted_message)
    else:
        print("HMAC verification failed. Message may have been tampered with.")