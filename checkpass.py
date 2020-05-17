import requests
import hashlib
import sys


def banner():
    print('''
+-----------------------------------------------+
| checkpass find out if your password leaked    | 
| checkpass v.0.1                               |
| Author: Elvin --> 'elvinsl'                   |
| Github: https://github.com/elvinsl/checkpass  |
+-----------------------------------------------+  
    ''')


def request_api_data(first_five_char):
    url = f'https://api.pwnedpasswords.com/range/{first_five_char}'
    r = requests.get(url)
    if r.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {r.status_code}, check API and try again.')
    return r.text


def leaks_pass_count(hashes, pass_hash):
    hashes = (line.split(':') for line in hashes.splitlines())
    for h, count in hashes:
        if h == pass_hash:
            return count
    return 0


def check_pwned(password):
    sha1pass = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(first5_char)
    return leaks_pass_count(response, tail)


def main(args):
    for password in args:
        count = check_pwned(password)
        if count:
            print(f'{password} was found {count} times. Change your damn password!')
        else:
            print(f'{password} was not found. Think twice use once!')
    return 'Done!'


if __name__ == '__main__':
    banner()
    if len(sys.argv) >= 2:
        sys.exit(main(sys.argv[1:]))
    else:
        print('Usage: python3 checkmypass.py <pass1> <pass2> ...')
