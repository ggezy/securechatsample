import logging
import logg
import encryption
import base64
import requests


class ChatHandler:
    """Class for processing the chat"""

    @staticmethod
    def process_message(user: str, message: str) -> dict:
        """
        Function to process the chat message before sending to the server
        :param user:
        :param message:
        :return:
        """
        encrypted_message = encryption.EncryptionHelper.aes_encrypt(message.encode())

        hmac_signature = encryption.EncryptionHelper.generate_hmac(encrypted_message)
        message = {'user': user,
                   'message': base64.b64encode(encrypted_message).decode(),
                   'hmac_signature': hmac_signature}
        return message

    @staticmethod
    def receive_message(messages: list) -> dict:
        """
        Function to decrypt messages from the server.
        :param messages:
        :return:
        """
        for msg in messages:
            if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(msg['message']),
                                                       received_hmac=msg['hmac_signature']):
                decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(msg['message']))
                return {'user': msg['user'], 'message': decrypted_message.decode()}
            else:
                return {'user': msg['user'], 'message': 'Message tampered!'}
