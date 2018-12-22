import hmac
import time
import os
import sys
from hashlib import sha1


def hmac_sha1_time(secret_key):
    """ 
    Takes a secret key as a str and coverts it to a byte array, which is then hashed with the time 
    """

    TIME_STEP = 30 # standard TOTP uses a 30 second time interval
    current_time = int(time.time() // 30)

    byte_key = secret_key.encode('utf-8') 
    byte_time = current_time.to_bytes(4, byteorder = sys.byteorder)

    hashed = hmac.new(key = byte_key, msg = byte_time, digestmod = sha1).digest() # use the hmac library to calculate the hmac-sha1 hash
    return(hashed)

def dynamic_truncation(signature):
    """
    Uses the dynamic truncation method defined in RFC 4226 to generate a 4 byte string
    """ 

    # First we want to get the last byte of the signature
    
    length_of_sig = len(signature)
    last_byte = signature[length_of_sig - 1]
    
    # Then we calculate the offset 
    
    offset = last_byte % 16

    #Then we grab all the bytes and concatenate them together
    
    trunc_string = signature[offset].to_bytes(1, byteorder = sys.byteorder)
    
    for i in range(1,4):
        trunc_string += signature[offset + i].to_bytes(1, byteorder = sys.byteorder)
    
    return(trunc_string)

def generate_code(bytestring, digits = 6):
    """
    Takes a string of 4 bytes and outputs a 6 digit number according to RFC 4226
    """

    #First we have to take the string of bytes and turn it into an int

    power = int.from_bytes(bytestring, byteorder = sys.byteorder)

    # Then we need to remove the highest order bit

    power = power % (2 ** 32)
    
    # Next we can calculate the final value

    code = power % (10 ** digits)
    
    return(code)

if __name__ == "__main__":
    value = hmac_sha1_time('3iduav923f98[csdacoinai32j9fvasdfhfha')
    byte_value = dynamic_truncation(value)
    code = generate_code(byte_value)
    print(code)


