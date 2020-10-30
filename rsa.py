#This code is primarily for my own understanding of RSA Encryption and is in noway intended to be used for production environments

import random

def textToInt(w):
    sum = 0
    for i in range(len(w)):
        sum += (ord(w[i]) * (256 ** i))
    return sum

def getB256(A):
    x = A
    listA = []
    while x != 0:
        x, r = int(x/256), x%256
        listA.append(r)
    return listA

def intToText(n):
    ints = getB256(n)
    res = ""
    for num in ints:
        res += chr(num)
    return res

def divisionWithRemainder(a, b):
    if b != 0:
        return [int(a/b), a%b]
    else:
        return "E"

def extendedGCD(a, b):
    #Find GCD and inverse of two numbers according to the Extended Euclidean Algorithm
    r0 = max(a, b)
    r1 = min(a, b)
    
    #set according to algorithm
    u = 1
    g = r0
    x = 0
    y = r1
    
    #Run the Loop
    while y > 0:
        q, t = divisionWithRemainder(g, y)
        s = u - (q*x)
        u = x
        g = y
        x = s
        y = t
    v = (g - (r0*u))/r1
    return [g, u, v]

def FastPowerSmall(g, A, N): 
    a = g
    b = 1
    while A > 0:
        if A % 2 == 1:
            b *= a
        a = (a ** 2) % N
        #print (a) 
        A = int(A/2)
    return b % N

def findroot(c, e, p, q):
    m = (p-1)*(q-1)
    N = p*q
    #Compute inverse of e in mod m
    d = extendedGCD(e, m)[2]
    if d < 0: d = m + d
    #Return the solution, c^d mod pq
    return FastPowerSmall(c, d, N)

def millerRabin(a, n):
    if n%2 == 0 or extendedGCD(a, n)[0] != 1:
        return True
    
    m = n-1
    k = 0
    while m%2 == 0 and m != 0:
        m = m//2
        k = k+1
    a = FastPowerSmall(a, m, n)
    if a == 1:
        return False
    
    for i in range(0, k):
        if (a + 1) % n == 0:
            return False
        a = (a * a) % n
    return True

def probablyPrime(n):
    for i in range(20):
        a = random.randint(2,n-1)
        #print (a)
        if millerRabin(a, n) == True: return False
    return True

def findPrime(lb, ub):
    is_prime = False
    while is_prime == False:
        n = random.randint(lb,ub)
        if probablyPrime(n):
            is_prime = True
            break
            
    return n

def generateRSAKey(b):
    ub = int("1"*b, 2)
    lb = int("1"*(b-1), 2)
    #ub = int("9"*b)
    p = findPrime(lb, ub)
    q = findPrime(lb, ub)
    N = p*q
    m = (p-1)*(q-1)
    coprime_e = False
    coprime_c = False
    #Ensure that gcd(e, (p-1)(q-1)) = 1 and gcd(c, pq) = 1
    while coprime_e == False:
        e = random.randint(p,m)
        gcd = extendedGCD(e, m)[0]
        if gcd == 1:
            coprime_e = True
            break
    while coprime_c == False:
        c = random.randint(q,N)
        gcd = extendedGCD(c, N)[0]
        if gcd == 1:
            coprime_c = True
            break

    d = extendedGCD(e, m)[2]
    if d < 0: d += m
    public_key = [N, e]
    private_key = [N, d]
    return [public_key, private_key]

def RSAEncrypt(message, PublicKey):
    if type(message) == str:
        m = textToInt(message)
    else:
        m = message
    c = FastPowerSmall(m, PublicKey[1], PublicKey[0])
    return c

def RSADecrypt(cipher, PrivateKey):
    m = FastPowerSmall(cipher, PrivateKey[1], PrivateKey[0])
    return m

#Driver Code
keys = generateRSAKey(16)
message = 314159
cipher = RSAEncrypt(message, keys[0])
decrypted = RSADecrypt(cipher, keys[1])
print("Message given:", message)
print("Decrypted message:", decrypted)
print(decrypted == message)

#Output
#Message given: 314159
#Decrypted message: 314159
#True