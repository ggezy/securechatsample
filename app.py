from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from Crypto.Random import get_random_bytes
import encryption
import base64

app = Flask(__name__)
"""
Process Flow: Login -> Send Message (Send into messages pool contains (User, Encrypted Message, HMAC) -> Receiver Message via pooling (Decrypt the inputted Message)
"""
# Secret key for encryption and HMAC (16 bytes for AES-128)
SECRET_KEY = get_random_bytes(32)
#login_manager = LoginManager()
#login_manager.init_app(app)
#login_manager.login_view = 'login'
app.config['SECRET_KEY'] = SECRET_KEY

messages = []

users = {
    "admin": "admin",
    "minda": "minda1",
    "ledy": "ledy1",
    "naya": "naya1"
}

# Route for serving HTML templates and handling form submissions
@app.route('/')
def index():
    return render_template('index.html')

#@login_manager.user_loader
#def load_user(user_id):
#    for user in users.values():
#        if user.id == int(user_id):
#            return user
#    return None

#Hash matching


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users.get(username, None) is not None and users.get(username, None) == password:
            login_user(username)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Send message, pool into global messages
    :return:
    """
    user = request.form.get('user')
    message = request.form.get('message')

    encrypted_message = encryption.EncryptionHelper.aes_encrypt(message.encode(), SECRET_KEY)

    hmac_signature = encryption.EncryptionHelper.generate_hmac(encrypted_message, SECRET_KEY)

    messages.append({'user': user,
                     'message': base64.b64encode(encrypted_message).decode(),
                     'hmac_signature': hmac_signature})
    print(messages)
    return jsonify({'status': 'Message sent successfully'})


@app.route('/receive_messages', methods=['GET'])
def receive_messages():
    """
    retrieve message from global messages, re-iterate over and over (pooling)
    :return:
    """
    decrypted_messages = []
    for msg in messages:
        if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(msg['message']), secretkey=SECRET_KEY, received_hmac=msg['hmac_signature']):
            decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(msg['message']), SECRET_KEY)
            decrypted_messages.append({'user': msg['user'], 'message': decrypted_message.decode()})
        else:
            decrypted_messages.append({'user': msg['user'], 'message': 'Message tampered!'})

    return jsonify(decrypted_messages)


if __name__ == '__main__':
    app.run(debug=True)