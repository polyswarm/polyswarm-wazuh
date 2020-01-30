#!/usr/bin/python3.6
#
# PolySwarm Integration <info@polyswarm.io>
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import sys
import time
import os

from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    from polyswarm_api.api import PolyswarmAPI
except Exception as e:
    Print.error('No module \'polyswarm_api\' found. Install: pip3 install polyswarm-api==v1.1.1')
    sys.exit(1)

# ossec.conf configuration:
#  <integration>
#      <name>custom-polyswarm</name>
#      <api_key>api_key_here</api_key>
#      <group>syscheck</group>
#      <alert_format>json</alert_format>
#  </integration>

# Global vars

INTEGRATION_NAME = 'custom-polyswarm'

debug_enabled = False

# Set paths
PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{PWD}/logs/integrations-polyswarm.log'
ERR_FILE = f'{PWD}/logs/integrations-polyswarm-err.log'
SOCKET_ADDR = f'{PWD}/queue/ossec/queue'

class Print:
    @staticmethod
    def _get_time():
        return time.strftime('%a %b %d %H:%M:%S %Z %Y')

    @staticmethod
    def _append_file(filename, text):
        f = open(filename,'a')
        f.write(f'{text}\n')
        f.close()

    @staticmethod
    def debug(msg):
        if debug_enabled:
            msg = f'{Print._get_time()} DEBUG: {msg}'

            print(msg)

            Print._append_file(LOG_FILE, msg)

    @staticmethod
    def log(msg):
        msg = f'{Print._get_time()} {msg}'

        print(msg)

        Print._append_file(LOG_FILE, msg)

    @staticmethod
    def error(msg):
        msg = f'{Print._get_time()} ERROR: {msg}'

        print(msg)

        Print._append_file(ERR_FILE, msg)


def send_event(msg, agent = None):
    json_msg = json.dumps(msg)

    if not agent or agent['id'] == '000':
        string = f'1:{INTEGRATION_NAME}:{json_msg}'
    else:
        agent_id = agent['id']
        agent_name = agent['name']
        agent_ip = agent['ip'] if 'ip' in agent else 'any'
        string = f'1:[{agent_id}] ({agent_name}) {agent_ip}->{INTEGRATION_NAME}:{json_msg}'

    Print.debug(f'event: {string}')
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()


class PolySwarm:
    def __init__(self, apikey):
        self.polyswarm_api = PolyswarmAPI(apikey)
        self.alert_output = {}
        self.alert_output['integration'] = INTEGRATION_NAME
        self.alert_output['polyswarm'] = {}
        self.alert_output['polyswarm']['status'] = 'ok'

    def create_output(self, key, value, variable_type='String'):
        key = key.rstrip('.')
        self.alert_output['polyswarm'][key] = value

    def return_output(self):
        return self.alert_output

    def search_hash(self, hash):
        """Search Hash"""
        # TODO: Refactor
        try:
            Print.debug(f'Running hash search on {hash}')
            results = self.polyswarm_api.search(hash.lower().lstrip().rstrip())
            for search_result in results:
                if search_result.failed:
                    Print.error(f'Failed to get result for {search_result.failure_reason}')
                    # todo mark playbook step as failed so we respond appr

                    return

                for artifact in search_result.result:
                    Print.debug('Got artifact results')

                    self.create_output('sha1', artifact.sha1.hash)
                    self.create_output('sha256', artifact.sha256.hash)
                    self.create_output('md5', artifact.md5.hash)

                    for h, h_val in artifact.metadata.hash.items():
                        self.create_output(str(h), str(h_val))

                    # a score between 0.0 and 1.0 indicating malintent
                    polyscore = artifact.polyscore

                    # all assertion responses from engines
                    all_assertions = artifact.last_scan.assertions
                    # malicious only assertions from engines
                    malicious_detections = list(artifact.last_scan.detections)

                    mal_detect_ratio = float(len(malicious_detections)) / len(all_assertions) if len(malicious_detections) else 0.0
                    self.create_output('malicious_detections.ratio',
                                       mal_detect_ratio)

                    # return because we're only matching first hash
                    self.create_output('malicious_detections.count', len(malicious_detections))
                    self.create_output('malicious_detections.confidence', int(mal_detect_ratio * 50 + polyscore * 50))
                    self.create_output('assertions.count', len(all_assertions))

                    self.create_output('polyscore', polyscore)


                    longest_malware_family_name = ""

                    if malicious_detections:
                        detection_kva = []
                        detection_str = []
                        for assertion in all_assertions:
                            d = {
                                'verdict': 'malicious' if assertion.verdict else 'benign',
                                'engine_name': assertion.engine_name,
                                'malware_family': assertion.metadata.get('malware_family', '')
                            }

                            detection_str.append('{}: {}'.format(assertion.engine_name, assertion.metadata.get('malware_family', '')))

                            detection_kva.append(d)
                            self.create_output('assertions.{}.{}'.format(assertion.engine_name, 'verdict'),
                                               'malicious' if assertion.verdict else 'benign')
                            self.create_output('assertions.{}.{}'.format(assertion.engine_name, 'bid'), assertion.bid)

                            e_malware_fam = assertion.metadata.get('malware_family', '')
                            if e_malware_fam:
                                self.create_output('{}.{}'.format(assertion.engine_name, 'malware_family'),
                                                   e_malware_fam)
                            if len(e_malware_fam) > len(longest_malware_family_name):
                                longest_malware_family_name = e_malware_fam

                            self.create_output('assertions.{}.{}'.format(assertion.engine_name, 'malware_family'),
                                               longest_malware_family_name)
                        self.create_output('malicious_detections.details', detection_kva, variable_type='KeyValueArray')
                        self.create_output('longest_malware_family_name', longest_malware_family_name)

                        # todo figure out how do get playbooks to iterate through KVAs without dirty hacks.

                        #self.create_output('malicious_detections_str', '\n'.join(detection_str))

                    return
        except Exception as e:
            Print.error(f'Uncaught exception {e}')



def main(args):
    json_alert = {}

    Print.debug('# PolySwarm Starting')

    # Read args
    alert_file_location = args[1]
    apikey = args[2]

    Print.debug('# API Key')
    Print.debug(apikey)

    Print.debug('# File location')
    Print.debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)

    Print.debug('# Processing alert')
    Print.debug(json_alert)

    polyswarm = PolySwarm(apikey)

    # If there is no a md5 checksum present in the alert. Exit.
    if not 'md5_after' in json_alert['syscheck']:
        return(0)

    polyswarm.search_hash(json_alert['syscheck']['md5_after'])

    send_event(polyswarm.return_output(),
               json_alert['agent'])

    sys.exit(0)


if __name__ == '__main__':
    try:
        # Read arguments
        len_sys = len(sys.argv)
        Print.debug(f'args list: {len_sys}')
        if len(sys.argv) >= 3:
            msg = '{} {} {} {}'.format(sys.argv[0],
                                       sys.argv[1],
                                       sys.argv[2],
                                       sys.argv[3] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 3 and sys.argv[3] == 'debug')
            Print.log(msg)
        else:
            msg = '{0} Wrong arguments'.format(now)
            Print.error(msg)
            debug('# Exiting: Bad arguments.')
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        Print.error(str(e))
        raise
