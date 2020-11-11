import urllib.request
from Crypto.Cipher import AES
import binascii
import base64
import random
import os
import zlib

################################################################################
# CS 284 Padding Utility Functions
################################################################################

# s is a bytearray to pad, k is blocklength
# you won't need to change the block length
def cmsc284pad(s,k=16):
    if k > 255:
        print("pkcs7pad: padding block length must be less than 256")
        return bytearray()
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s.extend([i])
    return s

# s is bytes to pad, k is blocklength
# you won't need to change the block length
def cmsc284padbytes(s,k=16):
    if k > 255:
        raise Exception("pkcs7pad: padding block length must be less than 256")
    n = k - (len(s) % k)
    if n == 0:
        n = k
    for i in range(1,n+1):
        s += chr(i).encode("utf-8")
    return s

# s is bytes to unpad, k is blocklength
# you won't need to change the block length
def cmsc284unpad(s,k=16):
    if not cmsc284checkpadding(s,k):
        print("cmsc284unpad: invalid padding")
        return b''
    n = s[len(s)-1]
    return s[:len(s)-n]

# checks padding on s and returns a boolean
# you won't need to change the block length
def cmsc284checkpadding(s,k=16):
    if(len(s) == 0):
       #print("Invalid padding: String zero length"%k) 
       return False
    if(len(s)%k != 0): 
       #print("Invalid padding: String is not multiple of %d bytes"%k) 
       return False
    n = s[len(s)-1]
    if n > k or n == 0:
       return False
    else: 
        for i in range(n):
            if s[len(s)-1-i] != (n-i):
                return False
    return True

################################################################################
# Function for querying the server
################################################################################

SERVER = "http://cryptoclass.cs.uchicago.edu/"
def make_query(task, cnetid, query):
    DEBUG = False
    if DEBUG:
        print("making a query")
        print("Task:", task)
        print("CNET ID:", cnetid)
        print("Query:", query)
    if (type(query) is bytearray) or (type(query) is bytes):
        url = SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = SERVER + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnetid) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    if DEBUG:
        print("Querying:", url)

    with urllib.request.urlopen(url) as response:
        raw_answer = response.read()
        answer = base64.urlsafe_b64decode(raw_answer)
        if DEBUG:
            print("Answer:", answer)
        return answer
    return None


################################################################################
# Problem 1 SOLUTION
################################################################################

from collections import Counter


def p1_find_bias(cnetid, n):
    query_length = 100
    # tally of the i-th byte across n queries
    tally = {i:[] for i in range(query_length)}
    most_frequent_byte = []
    for _ in range(n):
        response = make_query('one', cnetid, bytearray(query_length))
        # print(query.hex())
        for i in range(query_length):
            tally[i].append(hex(response[i]))
    for i in range(query_length):
        c = Counter(tally[i])
        most_frequent_byte.append((i, c.most_common(1)[0]))
    res = sorted(most_frequent_byte, key=lambda x: x[-1][-1],reverse=True)[0]
    # print("The {}th byte has {} occuring {} times out of {} queries".format(
    #     res[0], res[1][0], res[1][1], p1_n))
    return res[0]

def p1_recover_flag(cnetid, n):
    p1_flag_length = len(make_query('one', cnetid, ""))
    p1_bias_location = p1_find_bias(cnetid, n)
    query_length_start = p1_bias_location # recover the first byte of flag
    query_length_end = p1_bias_location-p1_flag_length # recover the last byte of flag
    for query_length in range(query_length_start, query_length_end, -1):
        tally = []
        for _ in range(n):
            response = make_query('one', cnetid, bytearray(query_length))
            tally.append(response[p1_bias_location])
        c = Counter(tally)
        print(chr(c.most_common(1)[0][0]), end='', flush=True)
    print()
            
def problem1(cnetid):
    p1_recover_flag(cnetid, 200)


################################################################################
# Problem 2 SOLUTION
################################################################################

import string

def problem2(cnetid):
    candidates = string.printable
    max_flag_len = len(make_query('two', cnetid, ""))
    res = []
    # prepad_length = 47
    for prepad_length in range(max_flag_len, 0, -1):
        flag_query = bytearray(prepad_length)
        flag_response = make_query('two', cnetid, flag_query)
        for char in candidates:
            test_query = bytearray(max_flag_len)
            for i in range(1, len(res)+1):
                test_query[-i-1] = ord(res[-i])
            test_query[-1] = ord(char)
            assert(len(test_query)==max_flag_len)
            test_response = make_query('two', cnetid, test_query)
            if test_response[:max_flag_len] == flag_response[:max_flag_len]:
                print(char, end='', flush=True)
                res.append(char)
    print()


################################################################################
# Problem 3 SOLUTION
################################################################################

def initial_two(cnetid, l):
    res = []
    for char1 in string.ascii_letters+' ':
        for char2 in string.ascii_letters+' ':
            response = make_query("three", cnetid, char1+char2)
            if len(response) == l+1:
                return char1+char2

def problem3(cnetid):
    empty_query = make_query("three", cnetid, "")
    l = len(empty_query)
    net_query_len = len("password=;userdata=")
    res = initial_two(cnetid, l)
    print(res, end='')
    for i in range((l-net_query_len)//2):
        for char in string.ascii_letters+' ':
            query = res + char
            response = make_query("three", cnetid, query)
            if len(response) == l+1:
                print(char, end='', flush=True)
                res = query
                break
    print()


################################################################################
# Problem 4 SOLUTION
################################################################################

import math

# chop up stream by block size
def p4_chop(s):
    block_size = 16
    return [s[i*block_size:(i+1)*block_size] 
            for i in range(math.ceil(len(s)/block_size))]
        

def problem4(cnetid):
    # get the last block of cipher ('professor')
    cipher_a = make_query("foura", cnetid, "")
    block3 = p4_chop(cipher_a)[-1]
    
    # get the first 2 blocks of cipher
    query_b = "davidcabb&uid=133"
    cipher_b = make_query("fourb", cnetid, query_b)
    block12 = p4_chop(cipher_b)[0]+p4_chop(cipher_b)[1]

    # send query to fourc
    print(make_query("fourc", cnetid, block12+block3))


################################################################################
# Problem 5 SOLUTION
################################################################################

def bitwise_xor(s1, s2):    
    r = bytearray()    
    if len(s1)==0 or len(s2)==0:
        return r
    for c1,c2 in zip(s1,s2):         
        r.extend([c1^c2])    
    return r


def problem5(cnetid):
    m3 = b'let me in please'

    test_c = bytearray(32)
    test_m = make_query("fiveb", cnetid, test_c)
    k = bytes(bitwise_xor(test_m[:16], test_m[16:]))

    cipher = AES.new(k, AES.MODE_ECB)
    m_bar = cmsc284pad(bytearray(m3))
    c1 = cipher.encrypt(bytes(bitwise_xor(m_bar[:16], k)))
    c2 = cipher.encrypt(bytes(bitwise_xor(m_bar[16:], c1)))
    c = c1+c2

    print(make_query("fivec", cnetid, c))

################################################################################
# Problem 6 SOLUTION
################################################################################

def int_list_to_bytearray(l):
    res = bytearray()
    for i in l:
        res.extend(i.to_bytes(1, 'big'))
    return res

def get_padding(n):
    return int_list_to_bytearray([i for i in range(1, n+1)])

def problem6(cnetid):    

    c = make_query("sixa", cnetid, "")
    c_bytes = p4_chop(c)
    n_blocks = len(c_bytes)

    for n in range(0, n_blocks-1):
        partial_aes1_list = [bytearray()]
        c1 = c_bytes[n+1]
        c0 = c_bytes[n]
        i = 1
        while i < 17:
            byte_found = 0
            partial_aes1  = partial_aes1_list.pop()
            partial_m1_hat = get_padding(i)
            partial_m1_hat = get_padding(i)
            partial_c0_hat = bitwise_xor(partial_aes1, partial_m1_hat[1:])
            query_back = partial_c0_hat + bytearray(c1)
            query_front = c0[:-i]
            for b in range(256):
                query = query_front + b.to_bytes(1,'big') + query_back
                if make_query("sixb", cnetid, query) == b'true':
                    new_aes_byte = b ^ 1
                    partial_aes1_list.append(new_aes_byte.to_bytes(1, 'big') + partial_aes1)
                    byte_found = 1
                    if n!=n_blocks-2:
                        break
            if byte_found:
                i+=1
        partial_aes1  = partial_aes1_list.pop()
        m0 = bitwise_xor(partial_aes1, c0)
        print(m0.decode(), end='')  


################################################################################
# Driver
################################################################################


if __name__ == "__main__":
    # your driver code for testing here

    cnetid = 'zqiu'
    print("cnetid: "+cnetid)

    print("Problem 1: ", end='', flush=True)
    problem1(cnetid)

    print("Problem 2: ", end='', flush=True)
    problem2(cnetid)

    print("Problem 3: ", end='', flush=True)
    problem3(cnetid)

    print("Problem 4: ", end='', flush=True)
    problem4(cnetid)

    print("Problem 5: ", end='', flush=True)
    problem5(cnetid)

    print("Problem 6: ", end='', flush=True)
    problem6(cnetid)