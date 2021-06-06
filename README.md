# cobalt-pickaxe
A tool to hunt/mine for Cobalt Strike beacons and "reduce"
their beacon configuration for later indexing. Hunts can either be expansive and internet wide using services like securitytrails, shodan, or zoomeye or specific to an list of ips.
![](static/minerman.png)

### Getting started
 
1. [Install](#installation) the tool
2. [Configure](#configuration) your tokens if doing internet hunts
3. [Mine](#search-examples) (search) for beacons
4. See results `cat results.json | jq`

:tv: **Demo**

![](static/demo.gif)

### Installation 

* requirements:     `virtualenv, python3`

1. `git clone https://github.com/d1vious/cobalt-pickaxe && cd cobalt-pickaxe` clone project and cd into the project dir
2. `pip install virtualenv && virtualenv -p python3 venv && source venv/bin/activate && pip install -r requirements.txt` create virtualenv and install requirements

Continue to [configuring](#configuration) a Security Trails, Shodan, or ZoomEye API key.

### Configuration [`cobalt-pickaxe.conf`](https://github.com/d1vious/cobalt-pickaxe/blob/master/cobalt-pickaxe.conf.example)

Make sure you set a token for one of the available [providers](https://github.com/d1vious/cobalt-pickaxe/blob/main/cobalt-pickaxe.conf.example#L18-L25). If you need to create one for your account follow [these](htt://need wiki page) instructions. 

```
[global]
output = results.json
# stores matches in JSON here

log_path = cobalt-pickaxe.log
# Sets the log_path for the logging file

log_level = INFO
# Sets the log level for the logging
# Possible values: INFO, ERROR

nse_script = grab_beacon_config.nse
# path to the nse script that rips down cobalt configs. This is specifically using https://github.com/whickey-r7/grab_beacon_config

searches = search.yml
# contains the different searches to run on each internet scanning service provider (eg shodan, zoomeye, security trails) when hunting for team servers.

shodan_token = TOKENHERE
# shodan token for searching

zoomeye_token = TOKENHERE
# zoomeye token for searching

securitytrails_token = TOKENHERE
# security trails token for searching
```

### Search The Internet
To modify the default mining done across different providers customize `search.yml`. To understand what cobalt-pickaxe checks by default see [Search Examples](#search-examples).

Run:

`python cobalt-pickaxe.py`

### Search IP list
populate `ips.txt` with potential Cobalt Strike C2 IPs a new line delimeted, example:

```
1.1.1.1
2.2.2.2
3.3.3.3
```

Run: 

`python cobalt-pickaxe.py -i ips.txt`

If you need inspiration from hunters we highly recommend:

* [Mike]()
* [DFI report]()
* [Brad]()

### Usage

```
usage: cobalt-pickaxe.py [-h] [-c CONFIG] [-o OUTPUT] [-V] [-i INPUT]

scans for open cobalt strike team servers and grabs their beacon configs and write this as a json log to be analyzed by any analytic tools
like splunk, elastic, etc..

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file path
  -o OUTPUT, --output OUTPUT
                        file to write to the results, defaults to results.json.log
  -V, --version         shows current cobalt-pickaxe version
  -i INPUT, --input INPUT
                        newline delimeted file of cobalt strike server ips to grab beacon configs from. example ips.txt
```

### Search Examples

All these are shipped out of the box configured under [`search.yml`](https://github.com/d1vious/cobalt-pickaxe/blob/main/search.yml). 

#### SHODAN

##### Find specific [JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/) signatures, out of the box we track Cobalt Strike 4.x 
`'ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1'`

##### Team server detected by Shodan
`'product:"cobalt strike team server"'`


# Author

* Michael Haag [@Mhaggis]()
* Jose Hernandez [@d1vious](https://twitter.com/d1vious)

# Credits & References

Inspiration came from a hangful of blogs:
Much of this is only possible because whiskey-7 shared with us grb_beacon.nse

# TODO
* add remaining beacon data from nse script (do not have everything parsed)
* add zoomeye
* add securitytrails
* include ^ search examples
