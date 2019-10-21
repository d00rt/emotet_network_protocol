import os
import json
import logging
import requests
import tempfile
# Simple file parser. Those files can contain comments
# For a valid comment the line must start with '#' character
def parse_bot_config_file(filename):
    if not os.path.exists(filename):
        raise Exception("The file {0} doesn't exist".format(filename))

    with open(filename, "r") as f:
        lines = f.readlines()

    sanitized = []
    for l in lines:
        if l[0] == '#':
            continue
        sanitized.append(l.strip("\r\n"))

    if sanitized == []:
        raise Exception("The file {0} doesn't contain only contains comments or is empty".format(filename))

    return sanitized

# protobuf encoding
def decode_len(data):
    i = 0
    size = 0
    shl = 0
    while i < len(data):
        size |= (ord(data[i]) & 0x7F) << shl
        shl += 7
        if (ord(data[i]) & 0x80) == 0:
            i += 1
            break
        i += 1
    return i, size

def print_bot_config(bot):
    logging.debug("self.AES_KEY = {0}".format(repr(bot.AES_KEY)))
    logging.debug("self.USER_AGENT = '{0}'".format(bot.USER_AGENT))
    logging.debug("self.HOSTNAME = '{0}'".format(bot.HOSTNAME))
    logging.debug("self.HOST_RUNNING_PROC = {0}".format(bot.HOST_RUNNING_PROC))
    logging.debug("self.CRC32 = {0}".format(bot.CRC32))

def get_analysis_from_cape(i):
    try:
        result = requests.get("https://www.capesandbox.com/configdownload/{0}/Emotet/".format(i))
        if result.ok:
            _, filename = tempfile.mkstemp()
            with open(filename, "wb") as f:
                f.write(result.text)
            return filename

    except Exception as e:
        return ""

def get_analysis_from_triage(i, filename):
    if not os.path.exists(filename):
        print("[!] Not found Triage API key file: {0}.".format(filename))
        return ""

    api_key = parse_bot_config_file(filename)[0]

    if api_key == "[COPY YOUR API KEY HERE]":
        print("[!] Register into Triage https://tria.ge to get your API KEY")
        return ""

    headers = {'Authorization':'Bearer {0}'.format(api_key)}
    try:
        result = requests.get("https://api.tria.ge/v0/samples/{0}/task1/report_triage.json".format(i), headers=headers)
        data = result.json()
    except Exception as e:
        return ""

    # Process the report in order to extract Emotet configuration from it
    if not data.get("extracted", None):
        print "[!] Triage analysis {0} doesn't have a Emotet config".format(i)
        return ""

    # Get configuration from dump
    config = None
    for dmp in data["extracted"]:
        if not dmp.get("config", None):
            continue

        config = dmp["config"]
        break

    # Check if gotten config is a emotet config
    if config == None:
        print "[!] Emotet configuration not found on Triage {0} analysis".format(i)
        return ""
    if not config.get("family", None):
        print "[!] Emotet configuration not found on Triage {0} analysis".format(i)
        return ""
    if config["family"] != "emotet":
        print "[!] Emotet configuration not found on Triage {0} analysis".format(i)
        return ""

    _, filename = tempfile.mkstemp()
    with open(filename, "wb") as f:
        json.dump(config, f)
    return filename


