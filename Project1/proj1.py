from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from math import gcd as bltin_gcd
import math
import base64
import sys, os, signal
import binascii
from pwn import *

def getpubkey():
	with open('./pub.pem', 'rb') as f:
		pub = f.read()
		key = RSA.importKey(pub)
	return key

def coprime(a, b):
	return bltin_gcd(a, b) == 1

def egcd(a,b):
	if a==0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b%a, a)
		return (g, x-(b // a)*y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g!= 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m



if __name__ == "__main__" :

	key = getpubkey()
	n = key.n
	e = key.e

	#choose X where X is relatively prime to n
	tmp = 3
	while (coprime(tmp, n)!=True):
		tmp += 1
	X = tmp


	#create Y = C* X^e mod n
	with open('./flag.enc', 'r') as f:
		flag = f.read().strip()
		flag = base64.b64decode(flag)

		C = int(binascii.hexlify(flag), 16)

		Y = C * (X**e) % n

	#get decrypted Y
	en = SHA256.new()
	en = binascii.unhexlify(hex(Y)[2:])

	send_code = base64.b64encode(en)

	#connect to server nc 140.113.194.66 8888
	conn = remote('140.113.194.66', 8888)
	reply = conn.recvuntil(':')
	#print(reply)
	conn.sendline(send_code)
	#print(send_code)
	conn.recvline() #get the server reply 'decrypted message.....\n'
	Z = conn.recvline() #get the decrypted Y
	conn.close()
	#print(Z)
	#retrieve the decrypted message
	Z = base64.b64decode(Z)
	Z = int(binascii.hexlify(Z),16)
	#find out X inverse
	x_inverse = modinv(X, n)

	#solve P
	P = (Z * x_inverse) % n
	
	ans = SHA256.new()
	ans = binascii.unhexlify(hex(P)[2:])
	#write ans to file
	print(ans)
	with open('flag', 'wb') as file:
		file.write(ans)