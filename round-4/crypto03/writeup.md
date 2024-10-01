# openECSC 2024 - Final Round

## [crypto] A key-homomorphic, chameleon stream cipher (1 solve)

I ran out of ideas for challenge names, so I just generated it with <https://cseweb.ucsd.edu/~mihir/crypto-topic-generator.html> :)

Anyway, read the source, exploit, have fun!

Author: Robin Jadoul <@robin_jadoul>

## Overview

The challenge implements a few variations of an NTRU encryption scheme
and hands out several broadcast and multi-transmission ciphertexts.
The plaintexts are additive secret shares of an encryption key that
so that once all have been recovered, the flag can be decrypted.
The first encryption method uses the plaintext directly, while
the next two implement some suggested mitigations from the NTRU technical report #6:
`Implementation Notes for NTRU PKCS Multiple Transmissions`.

## Solution

We give a brief overview of some techniques that can be used to solve the individual sub-challenges,
the approaches and the challenge in general are based on <https://ietresearch.onlinelibrary.wiley.com/doi/epdf/10.1049/iet-com.2013.1092>.
Some parameters were changed, in particular the choice of `H` for the second mitigation
introduces some overlap between the $z(x)$ and $C(z(x))$, which complicates regular decryption
but does not hinder the attack in any meaningful way.

1. This is a multiple-transmission attack on the plain NTRU variant.
   The key observation is that by subtracting two ciphertexts,
   the contribution of the message will be removed, after which taking
   a pseudo-inverse of $h$ will reveal the difference of the corresponding
   random polynomials $r$.
   This in turn reveals much information about the coefficients of $r$,
   as they are sampled only from $\{-1, 0, 1\}$.
   Any remaining uncertainty about coefficients of $r$ can be brute forced
   by checking against $c - h r$ having ternary coefficients.
2. This is a broadcast attack against the plain NTRU variant.
   <https://eprint.iacr.org/2011/590> describes a linearization attack using
   only $3N/2$ ciphertexts.
3. Multiple-transmission, now using an extra randomization polynomial.
   The extra randomization is encrypted normally and then used as a blinding
   factor to hide the message.
   Through some algebraic manipulations of the ciphertext, this can be turned into
   a broadcast setting for the plain NTRU setting, and we can re-use the previous
   sub-challenge to solve it.
4. The attack on a broadcast setting follows the pattern above.
5. The second mitigation uses a polynomial $z(x)$ that can be recovered from
   the high coefficients of the "plain plaintext" and $z(x + 1)^6 (mod 3)$ as a
   mask on the actual plaintext $m$.
   Unfortunately, the exponent and the modulus interact, leaving only every third
   coefficient of the mask potentially nonzero.
   Taking a difference of ciphertexts again cancels out most of the message digits,
   leaving a linear system with small coefficients (the sum of components of the $z(x)$,
   which lie in $\{-1, 0, 1\}$).
   This can be solved with a lattice approach.
6. The lattice attack above no longer works for this setting.
   I am not immediately aware of any approaches that can target the
   full broadcast setting for this padding, but it does not feel unreasonable
   for the shared message digits to enable some further lattice attacks.
   Luckily, no share is assigned to this `p6` function anyway :)

## Exploit

See [solution.py](solution.py)
