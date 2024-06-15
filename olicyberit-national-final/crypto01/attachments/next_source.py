import os
import gmpy2
print([x + int(gmpy2.next_prime(x)) for x in os.getenv('FLAG', 'flag{redacted}').encode()])