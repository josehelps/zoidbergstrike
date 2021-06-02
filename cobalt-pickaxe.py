#!/usr/bin/env python2

import argparse
import json
import yaml
import subprocess
import xmltodict
import socket
import os
import sys
from pathlib import Path
from modules.CustomConfigParser import CustomConfigParser
from modules import logger, shodan

VERSION = 1

def write_results(OUTPUT_FILE, results, log):
    # write parsed results to a files
    try:
        with open(OUTPUT_FILE, 'a') as outfile:
            json.dump(results, outfile)
    except Exection as e:
        log.error("writing result file: {0}".format(str(e)))

def parse_nmap(nmap_results, log):
    results = []

    for result in nmap_results:
        match = dict()
        if result['nmaprun']['host']['status']['@state'] == 'up':
            for port in result['nmaprun']['host']['ports']['port']:
                if 'script' in port:
                    match = json.loads(port['script']['@output'])
                    print(json.dumps(match,indent=2))
    return results


def check_nmap(log):
# only support nix*  at the moment
    try:
        NMAP_PATH = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
    except:
        log.error("nmap not found, please make sure nmap is installed and accessible via path (which nmap)")
        sys.exit(1)
    return NMAP_PATH.stdout.rstrip()

def nmap_scan(open_instances, NSE_SCRIPT_PATH, NMAP_PATH, log):
    nmap_results = []
    for open_instance in open_instances:
        log.info("grabbing beacon from {}:{}".format(open_instance['ip'],open_instance['port']))
        if open_instance['port'] ==  '':
            cmd = [NMAP_PATH, open_instance['ip'], '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-F', '-T5', '-oX', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
        else:
            cmd = [NMAP_PATH, open_instance['ip'], '-p', str(open_instance['port']), '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-F', '-T5', '-oX', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
        json_result = dict()
        json_result = xmltodict.parse(result.stdout)
        nmap_results.append(json_result)
    return nmap_results

def ips_from_inputfile(INPUT_FILE):
    cobalt_ips = []
    ips_file = open(INPUT_FILE,'r')
    for ip in ips_file.readlines():
        match = dict()
        try:
            socket.inet_aton(ip)
            match['ip'] = ip.rstrip()
            match['port'] = ''
            cobalt_ips.append(match)
        except socket.error:
            log.error("{0} not a valid ip address on file {1}".format(ip, INPUT_FILE))
            sys.exit(1)
    return cobalt_ips

def read_searches(SEARCH_YML):
    searches = dict()
    with open(SEARCH_YML, 'r') as file:
        searches = yaml.full_load(file)
    return searches

def mine_cobalt(search, SHODAN_API, log):
    cobalt_ips = []
    if 'shodan' in search:
        for s in search['shodan']:
            log.info("collecting all servers in shodan with search: {}".format(s))
            results = shodan.search(s, SHODAN_API, log)
            log.info("found {} matching instances".format(len(results)))
            for ip in results:
                cobalt_ips.append(ip)
    log.info("total mined cobalt servers {}".format(len(cobalt_ips)))
    return cobalt_ips


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="scans for open cobalt strike team servers and grabs their beacon configs and write this as a json log to be analyzed by any analytic tools like splunk, elastic, etc..")
    parser.add_argument("-c", "--config", required=False, default="cobalt-pickaxe.conf", help="config file path")
    parser.add_argument("-o", "--output", required=False, default='results.json.log', help="file to write to the results, defaults to results.json.log")
    parser.add_argument("-V", "--version", default=False, action="store_true", required=False, help="shows current cobalt-pickaxe version")
    parser.add_argument("-i", "--input", required=False, default = "", help="newline delimeted file of cobalt strike server ips to grab beacon configs from. example ips.txt")

    # parse them
    args = parser.parse_args()
    config = args.config
    OUTPUT_FILE = args.output
    ARG_VERSION = args.version
    INPUT_PATH = args.input

    # needs config parser here
    tool_config = Path(config)
    if tool_config.is_file():
        print("cobalt-pickaxe is using config at path {0}".format(tool_config))
        configpath = str(tool_config)
    else:
        print("ERROR: cobalt-pickaxe failed to find a config file at {0}..exiting".format(tool_config))
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level'])
    log.info("INIT - cobalt-pickaxe v" + str(VERSION))

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)

    NMAP_PATH = check_nmap(log)
    SEARCH_YML = config['searches']
    NSE_SCRIPT_PATH = config['nse_script']

    if INPUT_PATH == "":
        log.info("scanning for all potential cobalt server ips")
        cobalt_ips = []
        abs_path = os.path.abspath(SEARCH_YML)
        searches = read_searches(abs_path)
        cobalt_ips = mine_cobalt(searches, config['shodan_token'], log)
    else:
        abs_path = os.path.abspath(INPUT_PATH)
        log.info("reading from input file: {}".format(abs_path))
        cobalt_ips = ips_from_inputfile(abs_path)
        log.info("scanning for {0} ips from file".format(len(cobalt_ips)))

    NSE_SCRIPT_PATH = os.path.abspath(NSE_SCRIPT_PATH)
    nmap_results = nmap_scan(cobalt_ips, NSE_SCRIPT_PATH, NMAP_PATH, log)
    results = parse_nmap(nmap_results, log)
    write_results(OUTPUT_FILE, results, log)

    log.info("finished successfully!")
