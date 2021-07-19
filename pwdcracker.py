import hashlib
import argparse as arg

def get_arguments():
    """Get arguments from the command line"""
    parser = arg.ArgumentParser()
    parser.add_argument('-t', '--type', dest='type', help='The type of hash to bruteforce [default: "md5"]', choices=['md5', 'sha1', 'sha224', 'sha256',
                        'sha384', 'sha512', 'sha3_224', 'sha3_256','sha3_384', 'sha3_512', 'shake_128', 'shake_256', 'blake2b', 'blake2s'], default='md5', type=str)
    parser.add_argument('-f', '--file', dest='file', help='Path to File containing Passwords [default: passwords.txt]', default='passwords.txt')
    parser.add_argument('-ha', '--hash', dest='hash', help='The Hash to bruteforce')
    options = parser.parse_args()
    if not options.hash:
        options = None
    return options

def decrypt(hashType, hashToDecrypt, pwdFile):
    print(f'[*] Decrypting {hashType} hash "{hashToDecrypt}" with {pwdFile}, please wait...')
    with open(pwdFile, 'r') as file:
        for line in file.readlines():
            if hashType == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha224':
                hash_object = hashlib.sha224(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha256':
                hash_object = hashlib.sha256(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha384':
                hash_object = hashlib.sha384(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha512':
                hash_object = hashlib.sha512(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha3_224':
                hash_object = hashlib.sha3_224(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha3_256':
                hash_object = hashlib.sha3_256(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha3_384':
                hash_object = hashlib.sha3_384(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'sha3_512':
                hash_object = hashlib.sha3_512(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'shake_128':
                hash_object = hashlib.shake_128(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'shake_256':
                hash_object = hashlib.shake_256(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'blake2b':
                hash_object = hashlib.blake2b(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
            elif hashType == 'blake2s':
                hash_object = hashlib.blake2s(line.strip().encode())
                check_hash(hashType, hash_object, hashToDecrypt, line)
    print('[-] Password not in File')

def check_hash(hashType, hash_obj, hashToDecrypt, plainText):
    hashed_word = hash_obj.hexdigest()
    if hashed_word == hashToDecrypt:
        print(f'\t[+] Found {hashType.upper()} Password: {plainText.strip()}\n')
        exit(0)
         

if __name__ == '__main__':
    optionsValues = get_arguments()
    if optionsValues:
        print('\n')
        decrypt(str(optionsValues.type).lower(), optionsValues.hash, optionsValues.file)
    else:
        type_of_hash = input("[>] Type of hash to bruteforce: ")
        pwd_file = input("[>] Path to passwords file: ")
        hash_to_decrypt = input("[>] Hash to bruteforce: ")
        print('\n')
        decrypt(type_of_hash.lower(), hash_to_decrypt, pwd_file)