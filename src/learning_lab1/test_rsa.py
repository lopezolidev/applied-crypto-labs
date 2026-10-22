def validate(n):
    """
    Applying integer division subsequently to find out if the number is prime
    """
    div = 2
    while div <= (n // 2):
        r = n % div
        if r == 0: return False
        div += 1
    return True

def find_gcd(n, m):
    """
    finding GCD trough the Euclidean algorithm
    """
    while True:
        r1 = m % n
        if r1 == 0:
            return n
        m = n
        n = r1

def find_lowest_e(tot):
    """
    iteration to find lowest number 'e' which gcd(e, tot) = 1
    """
    e = 2
    while e < tot:
        gcd = find_gcd(e, tot)
        if gcd == 1: 
            return e
        e += 1

def rsa_proc(p, q):
    """
    This function implements the basic RSA process of public key generation

    """
    # step 1: validate both numbers are prime
    if not validate(p):
        return
    if not validate(q):
        return
    # guard clauses

    # step 2: find out the modular space
    n = p * q
    # modular space 

    # step 3: calculate totien function
    totient = (p -1) * (q -1)

    # step 4: find public key (e component)
    e = find_lowest_e(totient)

    return (e, n), totient


def generate_priv_key(e, phi):

    original_phi = phi

    d_prev = 0
    d_curr = 1


    while True:
        q = phi // e # division
        r = phi - q * e # residue
        d_new = d_prev - q * d_curr # accountancy of how many times 'e' appears
        
        if r == 1:
            if d_new < 0:
                d_new = d_new + original_phi
                return d_new
            return d_new
        
        phi = e
        e = r
        d_prev = d_curr
        d_curr = d_new

public_key, secret_totient = rsa_proc(7, 11)

print(f"public key, given 7 and 11 is: {public_key}")

e_value = public_key[0]
private_key = generate_priv_key(e_value, secret_totient)

print(f"private key, given 7 and 11 is: {private_key}")