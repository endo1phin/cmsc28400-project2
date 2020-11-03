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

**Flag**: `And a million miles / Hello from the other side`

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
