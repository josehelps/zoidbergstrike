import shodan

def search(search, API_KEY, log):
    api = shodan.Shodan(API_KEY)
    open_instances = []

    try:
        #results = api.search(search, page=1)
        results = api.search(search)
        total_results = results['total']
        # need to caculate pages from here
        log.info('[+] Total results: {0}'.format(total_results))
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
        log.info('[!] Shodan search error: {}'.format(e))
    return open_instances
