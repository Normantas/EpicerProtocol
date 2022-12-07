from ast import Bytes
import base64
import string
import sys
import hashlib
import hmac

abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 ‎'
CurrentKey = ""

## Autokey (Credit to... some unknown person on stack overflow for asking this question..?)

def encryptMessage (messages, keys):  
    return cipherMessage(messages, keys, 'encrypt')

def decryptMessage(messages, keys):
    return cipherMessage(messages, keys, 'decrypt')

def cipherMessage (messages, keys, mode):
    cipher = []
    k_index = 0
    key = keys
    for i in messages:
        text = abc.find(i)
        if mode == 'encrypt':
             text += abc.find(key[k_index])
             key += i

        elif mode == 'decrypt':
             text -= abc.find(key[k_index])
             key += abc[text]
        text %= len(abc)
        k_index += 1
        cipher.append(abc[text])
    return ''.join(cipher)

## One time pad (Credit to Daniel Gräber for making this)

one_time_pad = list(abc)

def encrypt(msg, key):
    ciphertext = ''
    for idx, char in enumerate(msg):
        charIdx = abc.index(char)
        keyIdx = one_time_pad.index(key[idx])

        cipher = (keyIdx + charIdx) % len(one_time_pad)
        ciphertext += abc[cipher]

    return ciphertext

def decrypt(ciphertext, key):
    if ciphertext == '' or key == '':
        return ''

    charIdx = abc.index(ciphertext[0])
    keyIdx = one_time_pad.index(key[0])

    cipher = (charIdx - keyIdx) % len(one_time_pad)
    char = abc[cipher]

    return char + decrypt(ciphertext[1:], key[1:])


def Hmac(CurrentMessage, CurrentKey):
    return hmac.new(CurrentKey.encode(), CurrentMessage.encode(), hashlib.sha512).hexdigest()



def EncryptMessage(CurrentMessage, CurrentKey):
    ## Checking input
    if len(CurrentMessage) > 256:
        return "Bad message length. Max length 256 characters."
    elif len(CurrentMessage) < 256:
        CurrentMessage = CurrentMessage.ljust(256, '‎')
    if not len(CurrentKey) == 512:
        return "Bad current key length."

    ## Finishing message
    CompleteHash = Hmac(CurrentMessage, CurrentKey)
    FinalMessage = CompleteHash + CurrentMessage + CompleteHash

    ## Sending message
    return encrypt(FinalMessage, CurrentKey)

def DecryptMessage(CurrentMessage, CurrentKey):
    Decrypted = decrypt(CurrentMessage, CurrentKey)

    ## Integrity check
    DecryptedMessage = Decrypted[128:384]
    MessageHash = Hmac(DecryptedMessage, CurrentKey)

    Hash1,Hash2 = Decrypted[0:128],Decrypted[384:512]

    print("\n")
    print(Hash1)
    print("\n")
    print(Hash2)
    print("\n")
    print("\n")

    if Hash1 == MessageHash and Hash2 == MessageHash:
        return DecryptedMessage
    else:
        return "Integrity check failed!"



if __name__ == '__main__':
    CurrentKey = open("CurrentKey.txt", "r", encoding="utf-8").read()
    ## CurrentMessage = open("CurrentMessage.txt", "r", encoding="utf-8").read()

    CurrentMessage = input()

    EncryptedMessage = EncryptMessage(CurrentMessage, CurrentKey)
    if len(EncryptedMessage) < 512:
        raise Exception(EncryptedMessage)
    
    print(EncryptedMessage)

    DecryptedMessage = DecryptMessage(EncryptedMessage, CurrentKey)
    if len(DecryptedMessage) < 256:
        raise Exception(DecryptedMessage)
    
    print(DecryptedMessage)