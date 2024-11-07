from collections import Counter


def analyze_frequencies(text, is_bytes=False):
    if is_bytes:
        text = bytes(int(text[i:i+8], 2) for i in range(0, len(text), 8))
        char_freq = Counter(text)
        digram_freq = Counter([text[i:i + 2] for i in range(len(text) - 1)])
    else:
        char_freq = Counter(text)
        digram_freq = Counter(crypt.cut_string_into_pairs(text))
    return char_freq, digram_freq


def generate_substitution_key(char_freq, digram_freq, french_char_freq, french_digram_freq):    # Map most common characters from ciphertext to most common characters in French
    char_mapping = {}
    for (cipher_char, _), (french_char, _) in zip(char_freq.most_common(), french_char_freq.most_common()):
        char_mapping[cipher_char] = french_char

    digram_mapping = {}
    for (cipher_digram, _), (french_digram, _) in zip(digram_freq.most_common(), french_digram_freq.most_common()):
        digram_mapping[cipher_digram] = french_digram

    return char_mapping, digram_mapping


def decrypt(C):
    M = ""

    url = "https://www.gutenberg.org/ebooks/13846.txt.utf-8"  # Example URL
    text = crypt.load_text_from_web(url)

    french_char_freq, french_digram_freq = analyze_frequencies(text, is_bytes=False)

    char_freq, digram_freq = analyze_frequencies(C, is_bytes=True)

    char_mapping, digram_mapping = generate_substitution_key(char_freq, digram_freq, french_char_freq,
                                                             french_digram_freq)

    i = 0
    while i < len(C):
        if i + 1 < len(C):
            digram = C[i:i + 2]
            if digram in digram_mapping:
                M += digram_mapping[digram]
                i += 2  # skip the next byte
                continue

        char_byte = C[i:i + 1]  # single byte
        if char_byte in char_mapping:
            M += char_mapping[char_byte]
        else:
            M += chr(C[i])

        i += 1

    return M


ciphertext = b"..."
decrypted_message = decrypt(ciphertext)
print("Message chiffré:", ciphertext)
print("Message déchiffré:", decrypted_message)
