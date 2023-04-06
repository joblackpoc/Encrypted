from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open('fernet.key', 'wb') as key_file:
        key_file.write(key)
    print('Key generate and save to fernet.key')

if __name__== '__main__':
    generate_key()