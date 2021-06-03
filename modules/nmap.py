
import subprocess
import xmltodict
import json

def check(log):
# only support nix*  at the moment
    try:
        NMAP_PATH = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
    except:
        log.error("nmap not found, please make sure nmap is installed and accessible via path (which nmap)")
        sys.exit(1)
    return NMAP_PATH.stdout.rstrip()

def scan(open_instances, NSE_SCRIPT_PATH, NMAP_PATH, log):
    nmap_results = []
    for open_instance in open_instances:
        log.info("grabbing beacon from {}:{}".format(open_instance['ip'],open_instance['port']))
        if open_instance['port'] ==  '':
            cmd = [NMAP_PATH, open_instance['ip'], '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-F', '-T5', '-oX', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
        else:
            cmd = [NMAP_PATH, open_instance['ip'], '-p', str(open_instance['port']), '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-T5', '-oX', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
        json_result = dict()
        json_result = xmltodict.parse(result.stdout)
        nmap_results.append(json_result)
    return nmap_results

def parse(nmap_results, log):
    results = []
    log.info("parsing data from {0} beacons".format(len(nmap_results)))
    for result in nmap_results:
        match = dict()
        parsed_result = dict()
        #print(json.dumps(result))
        if result['nmaprun']['host']['status']['@state'] == 'up':
            if isinstance(result['nmaprun']['host']['ports']['port'], list):
                for port in result['nmaprun']['host']['ports']['port']:
                    if "script" in port:
                        match = json.loads(port['script']['@output'])
                        print(json.dumps(match,indent=2))
            else:
                if "script" in result['nmaprun']['host']['ports']['port']:
                    port = result['nmaprun']['host']['ports']['port']
                    match = json.loads(port['script']['@output'])
                    print(json.dumps(match,indent=2))
        parsed_result['ip'] = 
        parsed_result['domain'] =
        parsed_result['hostname'] =
        parsed_result['x64_config_method_1'] =
        parsed_result['x64_config_port'] =
        parsed_result['x64_config_spawn_to'] =
        parsed_result['x64_config_jitter'] =
        parsed_result['x64_config_c2_server'] =
        parsed_result['x64_config_beacon_type'] =
        parsed_result['x64_config_method_1'] =
        parsed_result['x64_config_method_2'] =
        parsed_result['x64_config_method_1'] =

    return results
