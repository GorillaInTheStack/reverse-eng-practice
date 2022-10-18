#!/usr/bin/python3
"""
    author: Husamu-Aldeen Alkhafaji
    version: 0.0.1
    date: 15/10/2022
"""
import argparse
import base64
import gzip
import re

# Compromise indicators which the script will use to determine if the file is malicious
compromise_indicators = {"base64": r"^.*\[System\.Convert\]::FromBase64String.*$",
                         "gzipDe": r"^.*\[System\.IO\.Compression\.CompressionMode\]::Decompress.*$",
                         "gzipCom": r"^.*\[System\.IO\.Compression\.CompressionMode\]::Compress.*$",
                         "iex": r"iex|IEX|Invoke-Expression"}

# Regex patterns to match with the script string
base64_pattern = r"[\"\'](?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})[\"\']"
commands_pattern = r"(cmd\.exe|cmd|powershell)"

# The hex magic number of gzip to check if a value is actually compressed (The first two hex values).
gzip_magic_num = b"\x1f\x8b"

# Any hidden code found will be added here.
hidden_code = []


def decode_base64(st):
    """
    takes in a base64 string and decodes it
    :param st: base64 string
    :return: bytearray
    """
    tmp = base64.b64decode(st.encode("UTF-16LE"))  # The encoding used commonly by powershell
    return tmp


def decompress(st):
    """
    takes in a bytearray and tries to decompress it
    :param st: bytearray
    :return: bytearray (decompressed)
    """
    return gzip.decompress(st)


def extract_code(st):
    """
    takes in the script code and tries to extract any hidden code and saves it in the global variable hidden_code
    :param st: script string
    :return: None
    """
    # Gets all base64 strings in the script
    cand = re.findall(base64_pattern, st, re.MULTILINE)

    for entry in cand:
        try:
            entry = entry.replace("'", "")
            entry = entry.replace("\"", "")
            decoded_bytes = decode_base64(entry)
            if gzip_magic_num in decoded_bytes:  # Check if it is compressed, if so, decompress
                decom = decompress(decoded_bytes)
                hidden_code.append(decom)
            else:  # Else add hidden code to global variable
                decoded = decoded_bytes.decode("UTF-16LE")
                hidden_code.append(decoded)
                # Check if decoded code has more hidden code, if so, call this func again.
                candidates_embed = re.findall(base64_pattern, decoded, re.MULTILINE)
                if candidates_embed:
                    extract_code(decoded)
        except (TypeError, UnicodeDecodeError) as e:
            print("Error while trying to find hidden code: ", e)
            continue


def check_file(st):
    """
    takes in the script as string and prints to console if the file is malicious
    :param st: script string
    :return: None
    """

    # Try to extract any hidden code
    extract_code(st)

    # Check for suspicious API calls in the script
    candidates_b = re.findall(compromise_indicators["base64"], st, re.MULTILINE)
    candidates_de = re.findall(compromise_indicators["gzipDe"], st, re.MULTILINE)
    candidates_com = re.findall(compromise_indicators["gzipCom"], st, re.MULTILINE)
    candidates_iex = re.findall(compromise_indicators["iex"], st, re.MULTILINE)

    # Output to console
    if (candidates_iex and candidates_de) or (candidates_b and candidates_iex) or (candidates_iex and candidates_com):
        print("File is likely malicious!")
        for code in hidden_code:
            print("Found hidden code: ", code)
    else:
        print("The file might not be malicious")

    if candidates_b:
        print("File has suspicious call: ", compromise_indicators["base64"])
    if candidates_iex:
        print("File has suspicious call: ", compromise_indicators["iex"])
    if candidates_com:
        print("File has suspicious call: ", compromise_indicators["gzipCom"])
    if candidates_de:
        print("File has suspicious call: ", compromise_indicators["gzipDe"])


if __name__ == "__main__":
    # Gather args
    parser = argparse.ArgumentParser(description='This file will attempt to detect s subtype of malicious powershell '
                                                 'scripts that uses encoding to hide code.')
    parser.add_argument('filepath', metavar='filepath', type=str,
                        help='The file path to the powershell script')
    args = parser.parse_args()

    # Open file and start checking if it is malicious
    with open(args.filepath, "r") as f:
        script = f.readlines()
        sc_str = "".join(script)
        check_file(sc_str)
