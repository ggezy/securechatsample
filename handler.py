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
        response = requests.post("http://127.0.0.1:8000/send_message", json=message)
        return NotImplemented

    @staticmethod
    def receive_message(messages: list):
        """
        Function to decrypt messages from the server.
        :param messages:
        :return:
        """
        if len(messages) > 0:
            for message in messages:
                if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(message['message']), received_hmac=message['hmac_signature']):
                    decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(msg['message']))
                    return {'user': message['user'], 'message': decrypted_message.decode()}
                else:
                    return {'user': message['user'], 'message': 'Message tampered!'}

        return NotImplemented
