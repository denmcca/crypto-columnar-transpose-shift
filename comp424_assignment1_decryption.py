#!/usr/bin/env python3
"""Assignment #1

    Due Mar 13 by 11:59pm Points 20 Submitting a file upload Available until Mar 13 at 11:59pm

COMP 424 Spring 2021 Assignment 1

Due: 3/13 at 11:59PM

You intercepted a single ciphertext. Decipher it as much as you can. To receive full or partial credit you must show all your work. Attach any code you have implemented (you can use any programming language) or any code you have found anywhere that is publicly online (but you must include citations of all sources you used in the report).

KUHPVIBQKVOSHWHXBPOFUXHRPVLLDDWVOSKWPREDDVVIDWQRBHBGLLBBPKQUNRVOHQEIRLWOKK RDD

You may assume you already know:

1. The encryption/decryption algorithm is a combination of columnar transposition and simple shift substitution

2. The key length is less than or equal to 10 letters long

3. The original message is in English

4. The original message contains only letters (i.e., no punctuation marks, numbers, etc).

You will submit a .zip file on Canvas that includes all the source code, dictionary files, etc. that you used to decipher this. Also included in the zip file, a one-page report that includes the original message (if successfully deciphered) as well as a detailed description of your approach.

Cheating: This assignment is an individual assignment. You can discuss this with other students. You cannot share source code.

Good luck!"""

from os import remove
import string
import itertools
import sys
import collections
import sys
import csv
# import multiprocessing
import queue
import threading
import time

CIPHER_TEXT = "KUHPVIBQKVOSHWHXBPOFUXHRPVLLDDWVOSKWPREDDVVIDWQRBHBGLLBBPKQUNRVOHQEIRLWOKKRDD"
# CIPHER_TEXT = "TICGTEWIMWGLPPMWWZBF"
MIN_WORD_SIZE = 3
csv_queue = queue.Queue(1000000)
high_percent = 0.00
last_output = ''

def main():
    start_main = time.perf_counter()
    # Cipher is a mixture of columnar transposition and simple shift substitution.
    transposer = ColumnarTransposer()

    # Key is 10 or less in length.
    try:
        max_key_len = int(sys.argv[1]);
    except:
        max_key_len = 10
    try:
        min_key_len = int(sys.argv[2])
    except:
        min_key_len = 1

    n = max_key_len
    m = min_key_len

    # # English letters only. No punctuations or numbers.
    # with open("words_dictionary.json", "r") as f:
        # dictionary = json.loads(f.read())
    with open("Data_google-10000-english.txt", "r") as f:
        dictionary = {w.strip().upper(): 1 for w in f.read().split(
            '\n') if len(w.strip()) >= MIN_WORD_SIZE}

    # https://medium.com/hackernoon/julia-a-language-for-the-future-of-cybersecurity-76f13b869924
    ENGLISH_FREQS = [0.0749, 0.0129, 0.0354, 0.0362, 0.1400, 0.0218, 0.0174, 0.0422, 0.0665, 0.0027, 0.0047,
                     0.0357, 0.0339, 0.0674, 0.0737, 0.0243, 0.0026, 0.0614, 0.0695, 0.0985, 0.0300, 0.0116, 
                     0.0169, 0.0028, 0.0164, 0.0004]

    variances = []
    shifted_ciphers = [0]*len(string.ascii_uppercase)
    for i in range(len(string.ascii_uppercase)):
    # if True:
        shifter = CeasarShift(string.ascii_uppercase)
        shifted_cipher = shifter.shift(CIPHER_TEXT, i, inverse=True)
        shifted_ciphers[i] = shifted_cipher
        variances.append(get_variances(shifted_cipher, ENGLISH_FREQS))
    min_var = min(variances)
    shifted_cipher = shifted_ciphers[variances.index(min_var)]
    print('\n'.join(shifted_ciphers))
    # with open('results.txt', 'w') as log:
    #     log.write('deciphered_text,key,letter_percent%s' % os.linesep)
    print('\n\nChecking Shifted Cipher: %s\n\n' % shifted_cipher)


    t = threading.Thread(target=write_to_csv, args=[csv_queue], daemon=True)
    t.start()
    # import traceback
    for i in range(m, n + 1):
        start = time.perf_counter()
        print('Testing %d character keys.' % i)
        # args = []
        # pool_size = 100
        import math
        poss_combs = math.factorial(10) / math.factorial(10 - i)
        percent5 = poss_combs * 0.05
        # print(poss_combs)
        # print(int(percent5))
        for num, key in enumerate(itertools.permutations(range(10), r=i)):
            # if not (num % 1000000):
            #     sys.stdout.write('.')
            #     sys.stdout.flush()
            # print(key)
            # print(num / poss_combs)
            # try:
            # print((num / poss_combs * 100) % percent5)
            if not (num % percent5):
                sys.stdout.write('\r%d%%' % int(num / poss_combs * 100))
                sys.stdout.flush()
            #     pass
            # except:
            #     pass
            try:
                check_key(key, dictionary, transposer, shifted_cipher)
            except Exception as ex:
                # traceback.print_exc()
                # print(ex)
                pass
        sys.stdout.write('\r100%\n')
        print("time to complete N=%d: %0.2fs" % (i, time.perf_counter() -  start), flush=True)

    csv_queue.put(None)
    print("Waiting for writing thread to complete.")
    t.join()

   
    with open('results.csv', 'r') as f:
        reader = csv.reader(f, delimiter=',')
        high_pct = {'Percent':0.00}
        # skip header
        next(f)
        # next(reader)
        for row in reader:
            if high_pct['Percent'] < float(row[2]):
                high_pct['Percent'] = float(row[2])
                high_pct['Key used'] = row[1]
                high_pct['Most likely message'] = row[0]
                high_pct['Words found'] = row[3]
    print('\nResult: \n%s' % '\n'.join('%s: %s' % (k, str(high_pct[k])) for k in high_pct))
    print("\nTotal time: %0.2fs" % (time.perf_counter() - start_main))
                
def check_key(key, dictionary, transposer, shifted_cipher):
    global high_percent
    global last_output
    output = transposer.decrypt(key, shifted_cipher)
    # key = ''.join(key)
    # print(output)
    # print(last_output)
    if output == last_output:
        raise Exception
    last_output = output
    letter_percent, found_words = check_transposed_output(output, dictionary)
    if letter_percent > high_percent:
        high_percent = letter_percent
        viable_output = "%s,%s,%.4f,{%s}" % (output, ''.join(str(k) for k in key), letter_percent, ' '.join(found_words))
        csv_queue.put(viable_output)
        return viable_output

def check_transposed_output(output, dictionary):
    found_words = []
    letter_count = 0
    # crawl through output from start to finish looking for words in hashed dictionary.
    start = 0;
    end = len(output)
    # print('\nscanning: %s' % output, flus~h=True)
    # stop at middle
    while start < end:
        i = start + MIN_WORD_SIZE
        j = end - MIN_WORD_SIZE
        while j > 0:
            # print('i:%d, j:%d' % (i, j))
            # check start letter group for dictionary entry
            if dictionary.get(output[start:i], 0):
                # if found add to letter_count and append to found words
                fw = output[start:i]
                letter_count += len(fw)
                found_words.append(fw)
            # check rear letter group
            if dictionary.get(output[j:end], 0):
                fw = output[j:end]
                letter_count += len(fw)
                found_words.append(fw)
            # expand front word search to another character
            i += 1
            # expand rear word search
            j -= 1
        # move starting point on front one more toward rear
        start += 1
        # move starting point on rear
        end -= 1

    # for w in dictionary:
    #     if len(w) > 3:
    #         if not output.find(w) == -1:
    #             letter_count += len(w)
    #             found_words.append(w)
    letter_percent = letter_count / len(output)
    return letter_percent, found_words
    # if letter_percent > high_percent:
    #     # with open('results.txt', 'a') as log:
    #     high_percent = letter_percent
    #     viable_output = "%s,%s,%.4f,%s\n" % (output, key, letter_percent, found_words)
    #     csv_queue.put(viable_output)
    #     return viable_output

def write_to_csv(csv_queue):
    print('Opening csv file.')
    with open('results.csv', 'w') as log:
        csvwriter = csv.writer(log, delimiter=',')
        log.write('deciphered_text,key,letter_percent,found_words\n')
        for r in iter(csv_queue.get, None):
            # sys.stdout.write('\nw')
            # sys.stdout.flush()
            csvwriter.writerow(r.split(','))
            log.flush()
            csv_queue.task_done()




def get_variances(msg, freqs):
    variances = [0]*len(freqs)
    # if len(msg) != len(freqs):
    #     raise Exception("Length of inputs do not match: %d, %d" % (len(msg), len(freqs)))
    for count in collections.Counter(msg).most_common():
        i = ord(count[0])-ord('A')
        # print('i: %d, count: %s, msg: %s, freqs: %s' % (i, count, msg, freqs))
        variances[i] = abs(((count[1] / len(msg)) - freqs[i]) / freqs[i])
    return sum(variances)
    



class ColumnarTransposer():
    @ staticmethod
    def get_order_from_key(key):
        # Get key element order
        key = list(key)
        order = {i: k for i, k in enumerate(sorted(key))}
        ordered_index = []
        for c in key:
            for e in order:
                if order[e] == c:
                    ordered_index.append(e)
                    break
            order.pop(e)
        return ordered_index

    @ staticmethod
    def padding(msg_chunk, pad_size, remove=False):
        if not remove:
            pad_count = pad_size - len(msg_chunk)
            return msg_chunk + '_' * pad_count
        return str(msg_chunk).rstrip('_')

    def encrypt(self, key, msg):
        # ceiling
        col_len = len(msg)//len(key) + (1 if len(msg) % len(key) else 0)
        # break up message into chunks
        chunks = [self.padding(msg[i:i+len(key)], len(key)) for i in range(0, len(msg), len(key))]
        chunks = [''.join(chunks[j][i] for j in range(col_len)) for i in range(len(key))]
        return ''.join(chunks[i] for i in self.get_order_from_key(key))

    def decrypt(self, key, msg):
        col_len = len(msg)//len(key)
        # 1 break up the input into col_len pieces
        chunks = {i:msg[j:j+col_len] for i, j in zip(self.get_order_from_key(key), range(0, len(msg), col_len))}
        # reorder chunks using ordered_index
        chunks = [chunks[i] for i in range(len(chunks))]
        return ''.join([self.padding(''.join([chunks[j][i] 
            for j in range(len(chunks))]), pad_size=col_len, remove=True) for i in range(col_len)])

class SimpleShiftSubstitutor():
    def __init__(self, key, nshift=4):
        self.key = key
        self.shifted_key = "".join([self.key[(i + nshift) % len(self.key)] for i in range(len(self.key))])


    def shift(self, text, inverse=False):
        text = text.upper()
        if not len(text):
            return ''
        if not text[0] in self.key:
            return (text[0] + self.shift(text[1:]))
        return (self.shifted_key[self.key.find(text[0])] + self.shift(text[1:]))


class CeasarShift():
    def __init__(self, key=string.ascii_uppercase):
        self.key = key

    def shift(self, text, nshift, inverse=False):
        shifted_text = ''
        for c in text:
            try:
                shifted_text += self.key[(self.key.index(c)+nshift
                                            *(-1 if inverse else 1))
                                            % (len(self.key))]
            except:
                shifted_text += c
        return shifted_text









# @ contextlib.contextmanager
# def read_zip_file(zip_file):
#     with zipfile.ZipFile(zip_file) as zf:
#         for filename in zf.namelist():
#             with zf.open(filename, "r") as f:
#                 for line in f:
#                     print(line)
#                     # if len(line) > 10:
#                         # break
#                     yield line





if __name__ == "__main__":
    main()




"""
def encryptRailFence(plaintext):
    table = {}
    i = 1
    increment = True
    for c in plaintext:
        row = table.get(i, [])
        row.append(c)
        table[i] = row
        if increment:
            if not (i < 3):
                increment = False
                i -= 1
            else:
                i += 1
        else:
            if not (i > 1):
                increment = True
                i += 1
            else: 
                i -= 1

    message = ""
    for k in table:
        for c in table[k]:
            message += c
                
    return message
"""
