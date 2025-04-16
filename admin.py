from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(None)
print(bcrypt.generate_password_hash('admin123').decode('utf-8'))
