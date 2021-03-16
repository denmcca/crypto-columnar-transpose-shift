import string

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
        chunks = [self.padding(msg[i:i+len(key)], len(key))
                  for i in range(0, len(msg), len(key))]
        chunks = [''.join(chunks[j][i] for j in range(col_len))
                  for i in range(len(key))]
        return ''.join(chunks[i] for i in self.get_order_from_key(key))

    def decrypt(self, key, msg):
        col_len = len(msg)//len(key)
        # 1 break up the input into col_len pieces
        chunks = {i: msg[j:j+col_len]
                  for i, j in zip(self.get_order_from_key(key), range(0, len(msg), col_len))}
        # reorder chunks using ordered_index
        chunks = [chunks[i] for i in range(len(chunks))]
        return ''.join([self.padding(''.join([chunks[j][i]
                                              for j in range(len(chunks))]), pad_size=col_len, remove=True) for i in range(col_len)])


class SimpleShiftSubstitutor():
    def __init__(self, key, nshift=4):
        self.key = key
        self.shifted_key = "".join(
            [self.key[(i + nshift) % len(self.key)] for i in range(len(self.key))])

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
                                          * (-1 if inverse else 1))
                                         % (len(self.key))]
            except:
                shifted_text += c
        return shifted_text
