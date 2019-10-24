import os
import zlib
import json
import magic
import random
import struct
import string
import base64
import requests
import logging
from hashlib import sha1
from Crypto.Util import asn1
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

from ..protobuf import emotet_pb2
from ..utils import emoutils


PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

class EmotetEmulator():
    USER_AGENT = None
    HOSTNAME = None
    HOSTNAME_LEN = None
    NATIVE_SYSTEM_INFO_ARCH = None
    SESSION_ID = None
    CRC32 = None
    HOST_RUNNING_PROC = None
    HOST_UNKVALUE = None
    AES_KEY = None


    def __init__(self, keyfilename, ipsfilename, cape=None, triage=None, hostname=None, useragent=None):
        if cape:
            self.import_pbk_and_cncs_from_cape(cape)
        elif triage:
            self.import_pbk_and_cncs_from_triage(triage)
        else:
            self.import_public_key(keyfilename)
            self.import_cncs(ipsfilename)

        self.AES_KEY = self._get_random_aes_key()
        self.CRC32 = 0xF3BAD2A6 #0x00 #0xBCD02C92 #0x9AEC529E #struct.unpack("=L", self.AES_KEY[:4])[0] # Get a random value for the first requests
        self.CRC32 = struct.unpack("=L", self.AES_KEY[:4])[0] # Get a random value for the first requests
        self.NATIVE_SYSTEM_INFO_ARCH = 0 + 0x19E74 # On many samples of emotet they add the value 0x19E74 to this value
        self.HOST_RUNNING_PROC = self._get_running_proc()
        self.HOST_UNKVALUE = ""
        self.SESSION_ID = 1

        if hostname:
            self.HOSTNAME = hostname + '_E00FFE62'
        else:
            self.HOSTNAME = self._get_hostname()

        self.HOSTNAME_LEN = len(self.HOSTNAME)

        if useragent:
            self.USER_AGENT = useragent
        else:
            self.USER_AGENT = self._get_user_agent()

    def reset(self):
        self.AES_KEY = self._get_random_aes_key()
        #self.CRC32 = struct.unpack("=L", self.AES_KEY[:4])[0] # Get a random value for the first requests
        self.NATIVE_SYSTEM_INFO_ARCH = 0 + 0x19E74 # On many samples of emotet they add the value 0x19E74 to this value
        self.HOST_RUNNING_PROC = self._get_running_proc()
        self.HOST_UNKVALUE = ""
        self.SESSION_ID = 1
        self.HOSTNAME = self._get_hostname()

        self.HOSTNAME_LEN = len(self.HOSTNAME)
        self.USER_AGENT = self._get_user_agent()

#
# Bot initialization
#
    def _get_user_agent(self):
        filename = os.path.join(PROJECT_PATH, "config/user-agents.txt")
        user_agents = emoutils.parse_bot_config_file(filename)

        return random.choice(user_agents)

    def _get_running_proc(self):
        filename = os.path.join(PROJECT_PATH, "config/base-procs.txt")
        base_procs = emoutils.parse_bot_config_file(filename)

        filename = os.path.join(PROJECT_PATH, "config/random-procs.txt")
        random_procs = emoutils.parse_bot_config_file(filename)

        procs = base_procs
        for i in range(random.randint(1, 13)):
            idx = random.randint(0, len(random_procs) - 1)
            procs.append(random_procs[idx])

        random.shuffle(procs)
        return procs

    def _get_hostname(self):
        filename = os.path.join(PROJECT_PATH, "config/names.txt")
        names = emoutils.parse_bot_config_file(filename)

        filename = os.path.join(PROJECT_PATH, "config/surnames.txt")
        surnames = emoutils.parse_bot_config_file(filename)

        auxi = [
            "PC",
#            "computer",
#            "personal",
        ]
        name = random.choice(names) + random.choice(surnames) + "X" + random.choice(auxi)

        return "{0}_{1:08X}".format(name, struct.unpack("=L", self.AES_KEY[:4])[0] >> 1).upper()

    def _get_bot_info(self):
        bot_info = emotet_pb2.HostInfo()
        bot_info.scmanager = 0x00
        bot_info.bot_id = self.HOSTNAME
        bot_info.arch = self.NATIVE_SYSTEM_INFO_ARCH
        bot_info.session_id = self.SESSION_ID
        bot_info.file_crc32 = self.CRC32
        bot_info.proccess_list = ','.join(self.HOST_RUNNING_PROC) + ','
        bot_info.unknown = self.HOST_UNKVALUE
        return bot_info.SerializeToString()

    def _get_random_aes_key(self):
        return ''.join([ chr(random.getrandbits(8)) for i in xrange(0x10)])
#
# Pyload generation
#
    def _encrypt_command(self, command):
        needed_padding = 16 - (len(command) % 16)
        padding = chr(needed_padding) * needed_padding
        aes_cipher = AES.new(self.AES_KEY, AES.MODE_CBC, "\x00" * 0x10)
        return aes_cipher.encrypt(command + padding)

    def _decrypt_command(self, command):
        aes_cipher = AES.new(self.AES_KEY, AES.MODE_CBC, "\x00" * 0x10)
        return aes_cipher.decrypt(command[0x60 + 20:])

    def generate_payload(self):
        bot_info = self._get_bot_info()

        compressed_payload = zlib.compress(bot_info, 1)
        c2command = self.encode_message(compressed_payload)

        enc_c2command = self._encrypt_command(c2command)
        c2command_sha1 = sha1(c2command).digest()

        exported_aes_key = self.export_aes_key()

        return exported_aes_key + c2command_sha1 + enc_c2command

    def export_aes_key(self):
        return self.RSA_PUBLIC_KEY.encrypt(self.AES_KEY)

    def encode_message(self, data):
        c2command = emotet_pb2.C2Request()
        c2command.command = 0x10
        c2command.data = data
        return c2command.SerializeToString()
#
# Import botnet RSA key and C2C list
#
    def import_pbk_and_cncs_from_cape(self, filename):
        with open(filename) as json_file:
            data = json.load(json_file)

        pkey_pem = data["RSA public key"]
        pubkey = RSA.importKey(pkey_pem)
        self.RSA_PUBLIC_KEY = PKCS1_OAEP.new(pubkey)
        self.CNC_LIST = data["address"]

    def import_pbk_and_cncs_from_triage(self, filename):
        with open(filename) as json_file:
            data = json.load(json_file)

        pkey_pem = data["keys"][0]["value"]
        pubkey = RSA.importKey(pkey_pem)
        self.RSA_PUBLIC_KEY = PKCS1_OAEP.new(pubkey)
        self.CNC_LIST = data["c2"]

    # https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
    # https://doom99.net/index.php?/archives/13-Gemalto-IDPrime-OBKG,-MS_PUBLICKEYBLOB-and-SSH.html
    def import_public_key(self, filename):
        with open(filename, "rb") as f:
            b64enc_key = f.read()

        b64dec_key = base64.b64decode(b64enc_key)
        seq = asn1.DerSequence()
        seq.decode(b64dec_key)
        pubkey = RSA.construct((seq[0], seq[1]))
        pubkey = PKCS1_OAEP.new(pubkey)
        self.RSA_PUBLIC_KEY = pubkey

    def import_cncs(self, filename):
        with open(filename, "rb") as f:
            ips = f.readlines()

        self.CNC_LIST = [ip.strip("\r\n") for ip in ips]
#
# C2C communication
#
    def _get_headers(self, cnc, path):
        return {
            "User-Agent": self.USER_AGENT,
            "Referer": "http://{cnc}/{path}/".format(cnc=cnc.split(':')[0], path=path),
            "Content-Type": "application/x-www-form-urlencoded",
            "DNT": "1"
        }

    def _get_path(self):
        path = []
        filename = os.path.join(PROJECT_PATH, "config/url-path-words.txt")
        valid_words = emoutils.parse_bot_config_file(filename)
        for i in range(random.randint(1, 3)):
            idx = random.randint(0, len(valid_words) - 1)
            path.append(valid_words[idx])

        return '/'.join(path)

    def _get_url_var(self):
        return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + '0123456789') for i in range(random.randint(4, 16)))

    def do_task(self, cnc):
        payload = self.generate_payload()
        b64en_payload = base64.b64encode(payload)

        url_var = self._get_url_var()
        path = self._get_path()
        headers = self._get_headers(cnc, path)

        try:
            result = requests.post("http://{cnc}/{path}".format(cnc=cnc, path=path), data={url_var: b64en_payload}, headers=headers, stream=True, timeout=5)
            buff = result.raw.read()
            if len(buff):
                dec_command = self._decrypt_command(buff)

                data_size = struct.unpack("=L", dec_command[:4])[0]
                decompressed_command = zlib.decompress(dec_command[4:])

                if data_size != len(decompressed_command):
                    return ""

                response = emotet_pb2.C2Response()
                response.ParseFromString(decompressed_command)
                return response

        except requests.exceptions.ConnectTimeout as e:
            logging.debug("[!] Timeout!")

        except requests.exceptions.ConnectionError as e:
            logging.debug("[!] Connection Error!")

        except requests.exceptions.ReadTimeout as e:
            logging.debug("[!] Read timeout!")

        except ValueError as e:
            logging.debug("[!] This cnc is probably takedown")

        except Exception as e:
            logging.debug("[!] Unknown exception: {e}".format(e=str(e)))

        return None

    def download(self, try_all_cnc):
        for cnc in self.CNC_LIST:
            print("=== {cnc} ===".format(cnc=cnc))
            emoutils.print_bot_config(self)

            c2_response = self.do_task(cnc)
            if c2_response == None:
                logging.debug("[!] Can't register the bot")
                continue

            if c2_response.status != 0:
                logging.debug("[!] Can't register the bot")
                continue

            if len(c2_response.file):
                logging.debug("[+] Bot registered")
                self.CRC32 = zlib.crc32(c2_response.file) & 0xFFFFFFFF
                c2_response = self.do_task(cnc)
                if c2_response == None:
                    continue
                if len(c2_response.modules):
                    modules = self.process_modules(c2_response.modules)
                    return modules

            elif len(c2_response.modules):
                logging.debug("[+] Bot already registered")
                modules = self.process_modules(c2_response.modules)
                return modules
            else:
                logging.debug("[!] Can't register the bot we were ?banned?! Try from other country or with other bot id")
                if try_all_cnc:
                    # Reset bot values. "Create" a new bot in order to avoid get banned or something in the next attemps
                    self.reset()
#                    emoutils.print_bot_config(self)
                    logging.debug("[+] Bot values have been reset")
                    continue
                else:
                    return []

        return []

    def process_modules(self, data):
        modules = []
        i = 0
        while i < len(data):
            #if data[i] != '\x89':
            #    print("[!] Unexpected value parsing modules!")
            #    return modules

            read, data_len = emoutils.decode_len(data[i:])
            if not data_len:
                logging.debug("[!] Didn't find module protobuf!")
                return modules

            i += read

            module = emotet_pb2.Module()
            module.ParseFromString(data[i: i + data_len])
            modules.append(module)
            i += data_len

        return modules


