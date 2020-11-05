# Project 2: Symmetric Encryption Vulnerabilties
*Jeff Qiu*  
*November 6, 2020*

## Problem 1

**Flag**: `Death on the Nil`

### Finding bias
To find the bias within PRG, we query 100 bytes of `0x00` for 100 
times and divide up the response into bytes. We then gather all `i`th byte in 
each response together and tally their frequency. If the `i`th byte is unbiased 
and uniformly distributed, each possible byte should occur around 1 times in 
that location. However, the 30th byte have `0x0` occuring around 10 times. This 
indicate a clear bias that we could use to exploit.

### Finding flag
We observe that, if we use a 29 bytes query, the 30th byte in the PRG will 
overlap with the 1st byte in the flag. Because `xor(0x0, byte)=byte`, we can
run the query 100 times and count the most frequent byte in that location to
get the first byte of the flag. If we repeat the process from 29-bytes query to
14-bytes query, we can get the entire message.

### Why we cannot recover longer flags
If the length of the flag exceeds the location of the bias, we would not be able
to recover flag bytes beyond the locaation of the bias, since we cannot build a
query to overlap the biased byte with the byte in the flag.

### Estimated number of queries
We queried 100 times to find the bias, and another 100 times for each byte in 
the flag, which 1700 queries in total. We can techniaclly query less as long as
there is a clear difference in frequency in each byte, but we choose 100 just 
to be sufficiently clear.



## Problem 2

**Flag**: 
```And a million miles / Hello from the other side```

### Finding flag

We take the second approach suggested in the writeup, which is to construct the
query such that 1 bytes of the flag are included in the first block. We first 
find the maximum length possible for the flag by querying an empty string. Then
we construct a `flag_query` by adding `max_flag_length-1` bytes of 0s. The 
response we get from `flag_query` will include the encoded flag starting from
the `max_flag_length`-th byte. 

We then construct a `test_query` of the same length, except with the last byte
being one of `string.printable` and get a reaponse. If the first 
`max_flag_length` bytes of the test response is the same as the reference 
response, then we have found the first character in the flag.

We repeat the process, gradually reducing whitespace in `flag_query` and 
replacing whitespace in `test_query` with characters recovered flag, until all 
`max_flag_length` characters have been found.

### Estimated number of queries

For each character in the flag, we run queries for at most all of the printable 
character, which is 100 queries.



## Problem 3

**Flag**: ```serIOUS FaLl ```

We observed that, although adding the first byte to the query will always 
increase the response's length by 1, additional bytes in the query will not 
increase the length of the response if they overlaps with previous segments in 
the message. Therefore we choose the first two bytes by query all possible 
2-bytes combination of letters and space, which makes $50^2$ queries for the 
first two bytes, and choosing the one that only increased response length by 1.
We then continue to test out byte-by-byte, choosing each byte that, when added,
does not increase the length of the response. Each additional byte costs about
50 queries.

The attack does not contradict the fact that AES-CTR has good CPA security. In 
this attack, we are exploiting a weakness in zlib compression, which is 
unrelated to AES-CTR. 

## Problem 4

For problem 4, we construct a query for `fourb` such that the message `M'` have 
the same length as `M`, the message in `foura`. We then devided up the cipher 
text from `foura` to 3 16-byte blocks, and append the last block of `cipher_a`
with the first 2 blocks of `cipher_b` to form our final cipher, which returns
`b'Admin access granted.'` when fed into `fourc`.


## Problem 5

We observe the following quality of the decryption function:
$$
m[1] = AES^{-1}(k, c[1]) \oplus c[0]\\
m[2] = AES^{-1}(k, c[2]) \oplus c[1]
$$
Therefore, if $c[0]=c[1]$, $AES^{-1}(k, c[1]) = AES^{-1}(k, c[2])$ and 
$m[1]\oplus[2]=c[0]=k$. Using this property, we design the algorithm as follows:
- Output `test_c = bytearray(32)` to `fiveb`; 
- Because `test_c` is not properly padded, `fiveb` will return plain message `test_m`, which we parse as `m1+m2`;
- Let `k=bitwise_xor(m1, m2)` and use `k` and target message to construct `c3` with the encryption method outlined in the question;
- Query our encrypted message to `fivec` and get success response.


## Problem 6

**Flag**: ```I had a crazy dream last night! I was swimming in an ocean of orange soda. Turns out it was just a Fanta sea.```

We first observed the following property of `AES-CBC`: given a 32 bytes 
ciphertext, divide it up into 2 16-byte blocks, $c_0$ and $c_1$, with 
corresponding message $m_0$ and $m_1$:
$$
m_1 = AES^{-1}(k, c_0) \oplus c_0 \Longrightarrow AES^{-1}(k, c_0) = m_1 \oplus c_0
$$
We noticed that, although we cannot get information about the real $m_1$ from 
the oracle, we can know the padding information of the message. If we know 
the length of the padding, we can recover the padding part of the message, which
is constructed with a known pattern. We achieve this by constructing a 
$\hat c_0$ such that for every block, the $\hat m_1$ recovered is consist 
entirely of paddings. Since we did not change anything about $c_1$, we can 
recover $AES^{-1}(k, c_0) = m_1 \oplus c_0 = \hat c_0 \oplus \hat m_1$. Since
we already know the real $c_1$, we can recover $m_1$ with a simple xor. We 
construct the algorithm as follows:

Given a 32 bytes ciphertext, divide it up into 2 16-byte blocks, `c0` and `c1`:
1. For the `16-i`th byte in `m1`:
   1. Confirm `partial_aes1` has length `i-1`;
   2. xor `partial_aes1` with the padding portion to get `partial_c0_hat`
   3. Prepand `partial_c0_hat` with `c1` to get later part of the query
   4. For each possible byte `b`:
      1. Take the first `16-i` bytes of `c0` and `b`, forming the first part of the query
      2. Form the query by appending two parts of the query
      3. Feed query to `sixb`
      4. If get back true, update `partial_aes1` with xor of `b` and ascii 1
2. xor `partial_aes1` with `c1` to get `m1`
3. Print out `m1`

We repeat the process for each 16-byte block pairs in the original cipher text.
Each byte would take at most 256 queries to the oracle, which for a 128 bytes
message, takes at most $2^{15}$ queries.