# -*- coding: utf-8 -*-
"""
Created on Mon Feb  6 23:16:00 2017

@author: Syed Mohsin Bukhari
"""

import binascii
import re
import collections
import codecs
from Crypto.Cipher import AES

def hextobase64(inp_str):
    binp_str = inp_str.encode(encoding='UTF-8')
    out_str = binascii.b2a_base64(binascii.unhexlify(binp_str))
    out_str = out_str.decode(encoding='UTF-8').rstrip()
    return out_str
    
def fixedxor(inp1, inp2):
    out_buf = format(int(inp1, 16) ^ int(inp2, 16), '02x')
    if (len(out_buf)%2==1):
        out_buf = '0'+out_buf
    return out_buf
    
def xorchardecrypt(inptext, key):
    out_text = ''    
    for onebyte in [inptext[i:i+2] for i in range(0,len(inptext),2)]:
        out_text = out_text + chr(int(fixedxor(onebyte, key), 16))
    return out_text

def xorcharencrypt(inptext, key):
    out_code = ''
    for onechar in inptext:
        tempchar = hex(int(ord(onechar)))
        tempchar = tempchar[2:]
        out_code = out_code + fixedxor(tempchar, key)
    return out_code
    
def englishscoring(inptext):
    # counts readable characters
    score = len(re.findall("[A-Z]|[a-z]|[ ]", inptext))
    return score
    
def crackxorencryption(inptext):
    maxscore = 0
    max_i = -1
    decrypted_str = ''
    for i in range(0, 255):
        temp = xorchardecrypt(inptext,hex(i)[2:])
        tempscore = englishscoring(temp)
        if tempscore > maxscore:
            maxscore = tempscore
            max_i = i
            decrypted_str = temp
    return {'score': maxscore, 'key': max_i, 'key character': chr(max_i), 'string': decrypted_str.rstrip()}

def findxordstring(inplines):
    maxscore = 0
    maxcracked = {'score': 0, 'key': '', 'string': ''}
    for oneline in inplines:
        templine = oneline.rstrip()
        tempcracked = crackxorencryption(templine)
        tempscore = englishscoring(tempcracked['string'])
        if tempscore > maxscore:
            maxscore = tempscore
            maxcracked = tempcracked
    return maxcracked
    
def repeatingkeyxor(inptext, repeatingkey = 'ICE'):
    out_encrypted = ''
    for i in range(0, len(inptext)):
        tempkey = repeatingkey[i%len(repeatingkey)]
        out_encrypted = out_encrypted + xorcharencrypt(str(inptext[i]), hex(int(ord(tempkey))))
    return out_encrypted

def decodewithrepeatingkey(inptext, repeatingkey):
    endcodedstring = ''
    for ind in range(0 , len(inptext), 2):
        endcodedstring += chr(int(inptext[ind:ind+2], 16))
        
    decodedstringhex = repeatingkeyxor(endcodedstring, repeatingkey)
    
    decodedstring = ''
    for ind in range(0 , len(decodedstringhex), 2):
        decodedstring += chr(int(decodedstringhex[ind:ind+2], 16))
        
    return decodedstring
    
def findrepxorkeysize(inptext):
    keysize_hammingdists = {}
    bestkeysize = 99999
    leasthammingdist = 99999
    for keysize in range(2,41):
        keysizeblocks = []
        hammingdistanceblocks = []
        for ind in range(0, len(inptext)-(len(inptext)%(2*keysize)), 2*keysize):
            keysizeblocks.append(inptext[ind:ind+(2*keysize)])
        for ind in range(0, len(keysizeblocks)-1):
            hammingdistanceblocks.append(hammingdistancehex(keysizeblocks[ind],keysizeblocks[ind+1])/keysize)
        hammingdist = sum(hammingdistanceblocks)/len(hammingdistanceblocks)
        keysize_hammingdists[keysize] = hammingdist
        
        if hammingdist<leasthammingdist:
            leasthammingdist = hammingdist
            bestkeysize = keysize
    
    cntr_kszhdist = collections.Counter(keysize_hammingdists)
    keysize_hammingdists = cntr_kszhdist.most_common()
#    print(keysize_hammingdists)
    return bestkeysize
    
def findthekey(inputcode, inp_key_size):
    transposeblocks = []
    for ind in range(0,len(inputcode)-(len(inputcode)%(2*inp_key_size)), 2*inp_key_size):
        transposeblocks.append(inputcode[ind:ind+(2*inp_key_size)])
        
    finalkey = ''
    for keyind in range(0, 2*inp_key_size, 2):
        stringtodecode = ''
        for ind in range(0,len(transposeblocks),2):
            stringtodecode = stringtodecode + transposeblocks[ind][keyind:keyind+2]
        finalkey += crackxorencryption(stringtodecode)['key character']
        
    return finalkey

def hammingdistance(inp1, inp2):
    assert len(inp1) == len(inp2)
    inp1_bin = ''
    inp2_bin = ''
    for i in range(0, len(inp1)):
        inp1_bin = inp1_bin + format(ord(inp1[i]), '08b')
        inp2_bin = inp2_bin + format(ord(inp2[i]), '08b')
    return sum(c1 != c2 for c1, c2 in zip(inp1_bin, inp2_bin))

def hammingdistancehex(inp1, inp2):
    assert len(inp1) == len(inp2)
    inp1_bin = format(int(inp1, 16), '08b')
    while ((len(inp1_bin)%8)!=0):
        inp1_bin = '0'+inp1_bin
    inp2_bin = format(int(inp2, 16), '08b')
    while ((len(inp2_bin)%8)!=0):
        inp2_bin = '0'+inp2_bin
    return sum(c1 != c2 for c1, c2 in zip(inp1_bin, inp2_bin))
    
def base64tohex(inptext):
    hexifiedstr = codecs.encode( codecs.decode(bytearray(inptext, 'utf-8'), 'base64'), 'hex' )
    texttodecode = ''
    for ind in range(0, len(hexifiedstr), 2):
        texttodecode += codecs.decode( hexifiedstr[ind:ind+2] )
    return texttodecode

def decryptaesecb_base64(rawfile):
    cipher = AES.AESCipher(bytes('YELLOW SUBMARINE', encoding = 'utf-8'), AES.MODE_ECB)
    hexstrfile = base64tohex(rawfile)
    hexstrfile = binascii.unhexlify(hexstrfile)
    decryptedtext = cipher.decrypt(hexstrfile).rstrip(b'\x00').decode('utf-8')
    return decryptedtext

def decryptaesecb_hex(rawfile):
    cipher = AES.AESCipher(bytes('YELLOW SUBMARINE', encoding = 'utf-8'), AES.MODE_ECB)
    hexstrfile = binascii.unhexlify(rawfile)
    decryptedtext = cipher.decrypt(hexstrfile).rstrip(b'\x00').decode('utf-8')
    return decryptedtext

def challenge1():
    print('\n\n---- Challenge 1 ----')
    print(hextobase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

def challenge2():
    print('\n\n---- Challenge 2 ----')
    print(fixedxor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))

def challenge3():
    print('\n\n---- Challenge 3 ----')
    print(crackxorencryption('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

def challenge4():
    print('\n\n---- Challenge 4 ----')
    print('This takes sometime so please wait....')
    with open('challenge4file.txt') as f:
        print( findxordstring(f.readlines()) )

def challenge5():
    print('\n\n---- Challenge 5 ----')
    print(repeatingkeyxor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE'))

def challenge6():
    print('\n\n---- Challenge 6 ----')
    with open('challenge6file.txt') as filetodecode:
        rawfile = filetodecode.read()
        
    texttodecode = base64tohex(rawfile)
    bestkeysize = findrepxorkeysize(texttodecode)
    bestkey = findthekey(texttodecode, bestkeysize)
    
#    decodedstring = decodewithrepeatingkey(texttodecode, bestkey)
#    print(decodedstring)
    print({'key': bestkey, 'keysize': bestkeysize})
    
def challenge7():
    print('\n\n---- Challenge 7 ----')
    with open('challenge7file.txt') as filetodecode:
        rawfile = filetodecode.read()
    
    decryptedtext = decryptaesecb_base64(rawfile)
    
    # prints only the first 100 characters. You can index accordingly to print everything
    print(decryptedtext[:100] + '....')

def challenge8():
    print('\n\n---- Challenge 8 ----')
    with open('challenge8file.txt') as filetodecode:
        rawfile = filetodecode.readlines()
    
    outindex = -1
    minkeys = 99999
    for indmain in range(len(rawfile)):
        thisline = rawfile[indmain].rstrip()
        
        txtblocks = []
        for ind in range(0, len(thisline)-(len(thisline)%32), 32):
            txtblocks.append(thisline[ind:ind+32])
        
        txtblockscounter = collections.Counter(txtblocks)
        
        if len(txtblockscounter.keys()) < minkeys:
            minkeys = len(txtblockscounter.keys())
            outindex = indmain
            
    print({'line number': (outindex + 1), 'line': rawfile[outindex].rstrip()})

def __main__():
    challenge1()
    challenge2()
    challenge3()
    challenge4()
    challenge5()
    challenge6()
    challenge7()
    challenge8()
    
__main__()