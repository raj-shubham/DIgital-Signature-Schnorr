import math 
import random 
import secrets
import primes_list

# Utility function to do 
# modular exponentiation. 
# It returns (x^y) % p 
primesList = primes_list.primes

def power(x, y, p): 
	
	# Initialize result 
	res = 1; 
	
	# Update x if it is more than or 
	# equal to p 
	x = x % p; 
	while (y > 0): 		
		# If y is odd, multiply 
		# x with result 
		if (y & 1): 
			res = (res * x) % p; 

		# y must be even now 
		y = y>>1; # y = y/2 
		x = (x * x) % p; 
	
	return res; 

# This function is called 
# for all k trials. It returns 
# false if n is composite and 
# returns false if n is 
# probably prime. d is an odd 
# number such that d*2<sup>r</sup> = n-1 
# for some r >= 1 
def miillerTest(d, n): 
	
	# Pick a random number in [2..n-2] 
	# Corner cases make sure that n > 4 
	a = 2 + random.randint(1, n - 4); 

	# Compute a^d % n 
	x = power(a, d, n); 

	if (x == 1 or x == n - 1): 
		return True; 

	# Keep squaring x while one 
	# of the following doesn't 
	# happen 
	# (i) d does not reach n-1 
	# (ii) (x^2) % n is not 1 
	# (iii) (x^2) % n is not n-1 
	while (d != n - 1): 
		x = (x * x) % n; 
		d *= 2; 

		if (x == 1): 
			return False; 
		if (x == n - 1): 
			return True; 

	# Return composite 
	return False; 

# It returns false if n is 
# composite and returns true if n 
# is probably prime. k is an 
# input parameter that determines 
# accuracy level. Higher value of 
# k indicates more accuracy. 
def isPrime( n, k): 
	
	# Corner cases 
	if (n <= 1 or n == 4): 
		return False; 
	if (n <= 3): 
		return True; 

	# Find r such that n = 
	# 2^d * r + 1 for some r >= 1 
	d = n - 1; 
	while (d % 2 == 0): 
		d //= 2; 

	# Iterate given nber of 'k' times 
	for i in range(k): 
		if (miillerTest(d, n) == False): 
			return False; 

	return True; 

def primeFactors(n):
	primeFactorsList = list()
	flag = 0 
	while n % 2 == 0: 
		if not flag:
			primeFactorsList.append(2)
			flag = 1
		n = n // 2
		
	# n must be odd at this point 
	# so a skip of 2 ( i = i + 2) can be used 
	for i in range(3,int(math.sqrt(n))+1,2): 
		flag = 0
		# while i divides n , print i ad divide n 
		while n % i== 0: 
			if not flag:
				primeFactorsList.append(i)
				flag = 1
			n = n // i 
			
	# Condition if n is a prime 
	# number greater than 2 
	if n > 2: 
		primeFactorsList.append(n)
	return primeFactorsList	
# Driver Program to test above function 

def generatePrime(n,t):
	"""
		n: no. of bits in prime
		t: security parameter (no. of times we run miller rabin)
	"""
	# generate an odd random number 
	# secrets module provide secure random functions
	random_n_bit_odd_number = 0
	found_prime = False
	while not found_prime:
		while True:
			random_n_bit_odd_number = secrets.randbits(n)
			passed_base_primality = True
			if not (random_n_bit_odd_number % 2):
				random_n_bit_odd_number = random_n_bit_odd_number + 1
			for elements in primesList:
				if 0 == random_n_bit_odd_number%elements:
					passed_base_primality = False
					break
			if passed_base_primality:
				break
		if isPrime(random_n_bit_odd_number, t):
			found_prime = True
	return random_n_bit_odd_number

def generateSafePrime(n,t):
	"""
		n: no. of bits in prime
		t: security parameter (no. of times we run miller rabin)
	"""
	if n < 15:
		print("Bitsize must be greater than 15")
		exit(0)
	safe_prime_candidate = 0
	found_prime = False
	while not found_prime:
		while True:
			safe_prime_candidate = 2*generatePrime(n-1,t) + 1
			passed_base_primality = True
			for elements in primesList:
				if 0 == safe_prime_candidate%elements:
					passed_base_primality = False
					break
			if passed_base_primality:
				break
		if isPrime(safe_prime_candidate, t):
			found_prime = True
	return safe_prime_candidate


def generateCyclicGroupGenerator(prime):
	n = prime -1 
	primeFactorsList = primeFactors(n)
	generator_candidate = 0
	while not generator_candidate:
		generator_candidate = secrets.randbelow(prime)
		for elements in primeFactorsList:
			b = power(generator_candidate, n//elements, prime)
			if 1 == b:
				generator_candidate = 0
				break
	return generator_candidate

def provableHash(g,m,r,y,p):
	hashval = power(g,m,p)*power(g,r*y,p)
	hashval = power(hashval,1,p)
	return hashval
	#return power(100*m*r, 1, p)
	#return 100000


#n = 315
#primeFactorsList = primeFactors(n) 
#print(primeFactorsList)

print("Enter size of safe prime (bits):")
prime_size_bits = int(input())
print("Enter security parameter (Rabin-Miller number of iterations):")
security_parameter = int(input()) # iterations of miller rabin
print("Generating Safe Primes")
p = generateSafePrime(prime_size_bits,security_parameter)
print("Safe prime: ",p)
print("\nPublishing generator: ")
g = generateCyclicGroupGenerator(p)
print("\ngenerator: ",g)

#prover:
print("Enter Signer's private key:")
x = int(input())
print("Enter message:")
m = int(input()) # message
k = secrets.randbits(prime_size_bits-1) #random_nonce
r = power(g,k,p) 
y = power(g,x,p) # public
e = provableHash(g,m,r,y,p)
s = (k-x*e)%(p-1)
print("\n\ne = provableHash(g,m,r,y,p) = ",e)
print("s = (k-x*e)mod(p-1) = ",s)
print("signature pair : (e,s) : ( ",e,", ",s," )")
print("Signature done!")
# signature pair : e,s

#verifier:
print("\n\n")
print("Verification")
rv = power(g,s,p)*power(y,e,p)
rv = power(rv,1,p)
print("r = ",r)
print("rv = ",rv)
ev = provableHash(g,m,rv,y,p)
print("ev = provableHash(g,m,rv,y,p) = ",ev)

if e == ev:
	print('\nSignature successfully verified as e == ev.')
