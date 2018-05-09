import jks
import os, struct
from Crypto.Cipher import AES

def get_key_fromjecks(file_name,keystore_pass,keyalias):
    ks = jks.KeyStore.load(file_name, keystore_pass)
    for alias, sk in ks.secret_keys.items():
        if sk.alias==keyalias:
            print("input password for %s" % sk.alias)
            password=input();
            ks.entries[sk.alias].decrypt(password)
            key="".join("{:02x}".format(b) for b in bytearray(sk.key))
    return key
def encrypt_file(key,AESmode, in_filename, out_filename=None,  chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = os.urandom(16)
    #print("iv is "+str(iv))
    encryptor = AES.new(key, AESmode,iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                print(len(chunk))
                print(chunk)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += bytes([16 - len(chunk) % 16]) * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key,AESmode, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AESmode, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
def crypto(enc_mode,keystore_path,keyslias):
    print("Enter password for keystore")
    password=input()
    key=get_key_fromjecks(keystore_path,password,keyslias)
    key=bytes.fromhex(key)
    b=list(key)
    key=bytes(b)
    #print(len(b))
    #print(key)
    encrypt_file(key,enc_mode,"smieszkow.txt","smieszki.enc")
    print("Encrypted")

def decrypto(enc_mode,keystore_path,keyslias):
    print("Enter password for keystore")
    password=input()
    key=get_key_fromjecks(keystore_path,password,keyslias)
    key=bytes.fromhex(key)
    b=list(key)
    key=bytes(b)
    #print(len(b))
    #print(key)
    decrypt_file(key,enc_mode,"smieszki.enc","smieszki.txt")
    print("Decrypted")

crypto(AES.MODE_OFB,"keystore2.jceks","newaes")
decrypto(AES.MODE_OFB,"keystore2.jceks","newaes")