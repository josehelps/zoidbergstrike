#!/usr/bin/env python2

import shodan
import argparse
import json
import yaml
import subprocess
import xmltodict
import socket
import os

def shodan_search(search, API_KEY):
    api = shodan.Shodan(API_KEY)
    ips_and_ports = []

    try:
        #results = api.search(search, page=1)
        results = api.search(search)
        total_results = results['total']
        print('[+] Total results: {0}'.format(total_results))
        open_instances = []
        for r in results['matches']:
            open_instance = dict()
            open_instance ['ip'] = r['ip_str']
            open_instance['port'] = r['port']
            if 'domain' in r:
                open_instance['domains'] = r['domain']
            else:
                open_instance['domains'] = ''
            open_instance['hostnames'] = r['hostnames']
            open_instance['timestamp'] = r['timestamp']
            if 'ssl' in r:
                open_instance['ssl'] = r['ssl']['cert']['subject']


            #print ('{}'.format(open_instance))
            open_instances.append(open_instance)
#            print ('{} '.format(json.dumps(open_instance,indent=2)))

    except Exception as e:
        print ('[!] Shodan search error: {}'.format(e))
    return open_instances

def nmap_scan(open_instances):
    nmap_results = []

    #open_instances = [{'ip':'149.28.233.75', 'port':''}]
    for open_instance in open_instances:
        print("grabbing beacon from {}:{}".format(open_instance['ip'],open_instance['port']))
#        results = nmap.scan_top_ports(open_instance['ip'],args='-p ' + str(open_instance['port']) + ' --script=/Users/jhernandez/splunk/cobalt_scanner/grab_beacon_config.nse')
        cmd = ['/usr/bin/nmap', open_instance['ip'], '--script=/home/jhernandez/splunk/cobalt-pickaxe/grab_beacon_config.nse','-oX', '-']
        result = subprocess.run(cmd, capture_output=True, text=True)
        json_result = dict()
        json_result = xmltodict.parse(result.stdout)
        print(json.dumps(json_result, indent=2))
        nmap_results.append(json_result)
    return nmap_results

def ips_from_inputfile(INPUT_FILE):
    cobalt_ips = []
    ips_file = open(INPUT_FILE,'r')
    for ip in ips_file.readlines():
        try:
            socket.inet_aton(ip)
            cobalt_ips.append(ip.rstrip())
        except socket.error:
            print("ERROR, {0} not a valid ip address on file {1}".format(ip, INPUT_FILE))
            sys.exit(1)
    return cobalt_ips

def read_searches(SEARCH_YML):
    searches = dict()
    with open(SEARCH_YML, 'r') as file:
        searches = yaml.full_load(file)
    return searches

def mine_cobalt(search, SHODAN_API, VERBOSE):
    cobalt_ips = []
    if 'shodan' in search:
        for s in search['shodan']:
            if VERBOSE:
                print("collecting all servers in shodan with search: {}".format(s))
            results = shodan_search(s, SHODAN_API)
            if VERBOSE:
                print("found {} matching instances".format(len(results)))
            for ip in results:
                cobalt_ips.append(ip)
    if VERBOSE:
        print("total mined cobalt servers {}".format(len(cobalt_ips)))
    return cobalt_ips


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="scans for open cobalt strike team servers and grabs their beacon configs and write this as a json log to be analyzed by any analytic tools like splunk, elastic, etc..")
    parser.add_argument("-a", "--apikey", required=True, help="api for shodan")
    parser.add_argument("-o", "--output", required=False, default='results.json.log', help="file to write to the results, defaults to results.json.log")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-i", "--input", required=False, default = "", help="newline delimeted file of cobalt strike server ips to grab beacon configs from. example ips.txt")
    parser.add_argument("-s", "--search", required=False, default = "search.yml", help="contains the different searches to run on each service provider when hunting for team servers. Defaults to search.yml")

    # parse them
    args = parser.parse_args()
    SHODAN_API = args.apikey
    OUTPUT_FILE = args.output
    VERBOSE = args.verbose
    INPUT_PATH = args.input
    SEARCH_YML = args.search


    if INPUT_PATH == "":
        if VERBOSE:
            print("scanning for all potential cobalt server ips")
        cobalt_ips = []
        abs_path = os.path.abspath(SEARCH_YML)
        searches = read_searches(abs_path)
        cobalt_ips = mine_cobalt(searches, SHODAN_API, VERBOSE)

    else:
        abs_path = os.path.abspath(INPUT_PATH)
        if VERBOSE:
            print("reading from input file: {}".format(abs_path))
        cobalt_ips = ips_from_inputfile(abs_path)
        print("scanning for {0} ips from file".format(len(cobalt_ips)))


    #nmap_results = nmap_scan(cobalt_ips)

    print("finished successfully!")
