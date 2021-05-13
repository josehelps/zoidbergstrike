#!/usr/bin/env python2

import shodan
import argparse
import json
import subprocess
import xmltodict

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-a", "--apikey", required=True, help="Your api key")
   return parser.parse_args()

def attempt_login(open_instances):
    for o in open_instances:
        print ('{} '.format(json.dumps(o,indent=2)))


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

def main():
    args = parse_args()
    apikey = args.apikey

#    jarm_search = 'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1' 
#    print("collecting all servers in shodan with search: {}".format(jarm_search))
#    open_instances = shodan_search(jarm_search, apikey)
    cobalt_product_search = 'product:"cobalt strike team server"'
    open_instances = shodan_search(cobalt_product_search, apikey)
    print("found {} matching instances".format(len(open_instances)))
    nmap_results = nmap_scan(open_instances) 


main()
