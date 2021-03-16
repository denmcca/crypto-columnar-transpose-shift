#!/usr/bin/env python3
from cryptos import ColumnarTransposer, CeasarShift
import string
import itertools
import sys
import collections
import sys
import csv
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
        shifter = CeasarShift(string.ascii_uppercase)
        shifted_cipher = shifter.shift(CIPHER_TEXT, i, inverse=True)
        shifted_ciphers[i] = shifted_cipher
        variances.append(get_variances(shifted_cipher, ENGLISH_FREQS))
    min_var = min(variances)
    shifted_cipher = shifted_ciphers[variances.index(min_var)]
    print('\n'.join(shifted_ciphers))
    print('\n\nChecking Shifted Cipher: %s\n\n' % shifted_cipher)


    t = threading.Thread(target=write_to_csv, args=[csv_queue], daemon=True)
    t.start()
    for i in range(m, n + 1):
        start = time.perf_counter()
        print('Testing %d character keys.' % i)
        import math
        poss_combs = math.factorial(10) / math.factorial(10 - i)
        percent5 = poss_combs * 0.05
        for num, key in enumerate(itertools.permutations(range(10), r=i)):
            if not (num % percent5):
                sys.stdout.write('\r%d%%' % int(num / poss_combs * 100))
                sys.stdout.flush()
            try:
                check_key(key, dictionary, transposer, shifted_cipher)
            except Exception as ex:
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
    # stop at middle
    while start < end:
        i = start + MIN_WORD_SIZE
        j = end - MIN_WORD_SIZE
        while j > 0:
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

    letter_percent = letter_count / len(output)
    return letter_percent, found_words


def write_to_csv(csv_queue):
    print('Opening csv file.')
    with open('results.csv', 'w') as log:
        csvwriter = csv.writer(log, delimiter=',')
        log.write('deciphered_text,key,letter_percent,found_words\n')
        for r in iter(csv_queue.get, None):
            csvwriter.writerow(r.split(','))
            log.flush()
            csv_queue.task_done()


def get_variances(msg, freqs):
    variances = [0]*len(freqs)
    for count in collections.Counter(msg).most_common():
        i = ord(count[0])-ord('A')
        # print('i: %d, count: %s, msg: %s, freqs: %s' % (i, count, msg, freqs))
        variances[i] = abs(((count[1] / len(msg)) - freqs[i]) / freqs[i])
    return sum(variances)


if __name__ == "__main__":
    main()
