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

DEBUG_ENABLED = False
OUTPUT_METADATA = True

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
        if DEBUG_ENABLED:
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
        self.alert_output['polyswarm']['found'] = 0
        self.alert_output['polyswarm']['malicious'] = 0

    def create_output(self, key, value):
        self.alert_output['polyswarm'][key] = value

    def return_output(self):
        return self.alert_output

    def search_hash(self, hash):
        """Search Hash"""
        try:
            Print.debug(f'PolySwarm Search Hash: {hash}')
            results = self.polyswarm_api.search(hash.lower().lstrip().rstrip())
            for search_result in results:
                if search_result.failed:
                    self.create_output('status', 'ko')
                    Print.error(f'Failed to get result for {search_result.failure_reason}')
                    # todo mark playbook step as failed so we respond appr

                    return

                for artifact in search_result.result:
                    Print.debug('Got artifact results')
                    self.alert_output['polyswarm']['found'] = 1

                    # all assertion responses from engines
                    all_assertions = artifact.last_scan.assertions

                    # malicious only assertions from engines
                    malicious_detections = list(artifact.last_scan.detections)
                    self.create_output('positives', len(malicious_detections))

                    # total engines asserting
                    self.create_output('total', len(all_assertions))

                    # a score between 0.0 and 1.0 indicating malintent
                    self.create_output('polyscore', artifact.polyscore)

                    if malicious_detections:
                        for assertion in all_assertions:
                            # output only by malicious ones
                            if assertion.verdict:
                                self.create_output(f'microengine.{assertion.engine_name}.verdict', 'maliciuos')
                                if assertion.metadata.get('malware_family'):
                                    self.create_output(f'microengine.{assertion.engine_name}.malware_family',
                                                       assertion.metadata.get('malware_family'))

                                self.alert_output['polyswarm']['malicious'] = 1

                    if OUTPUT_METADATA:
                        for h, h_val in artifact.metadata.hash.items():
                            print("PRINTING METADATA")
                            print(str(h), str(h_val))
                            self.create_output(f'metadata.hash.{str(h)}', str(h_val))

                        for h, h_val in artifact.metadata.pefile.items():
                            print("PRINTING METADATA")
                            print(str(h), str(h_val))
                            self.create_output(f'metadata.pefile.{str(h)}', str(h_val))

                        for h, h_val in artifact.metadata.lief.items():
                            print("PRINTING METADATA")
                            print(str(h), str(h_val))
                            self.create_output(f'metadata.lief.{str(h)}', str(h_val))

                        for h, h_val in artifact.metadata.exiftool.items():
                            print("PRINTING METADATA")
                            print(str(h), str(h_val))
                            self.create_output(f'metadata.exiftool.{str(h)}', str(h_val))

                    self.create_output('name', artifact.name)
                    self.create_output('sha1', artifact.sha1.hash)
                    self.create_output('sha256', artifact.sha256.hash)
                    self.create_output('md5', artifact.md5.hash)
                    self.create_output('permalink', artifact.scan_permalink)


        except Exception as e:
            import traceback
            traceback.print_exc()
            Print.error(f'Uncaught exception {traceback.print_exc()}')


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

    # If there is no a md5 checksum present in the alert. Exit.
    if not 'md5_after' in json_alert['syscheck']:
        return(0)

    polyswarm = PolySwarm(apikey)

    polyswarm.search_hash(json_alert['syscheck']['md5_after'])

    # set output from Wazuh details
    polyswarm.create_output('source.alert_id', json_alert['id'])
    polyswarm.create_output('source.file', json_alert['syscheck']['path'])
    polyswarm.create_output('source.md5', json_alert['syscheck']['md5_after'])
    polyswarm.create_output('source.sha1', json_alert['syscheck']['sha1_after'])


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
            DEBUG_ENABLED = (len(sys.argv) > 3 and sys.argv[3] == 'debug')
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
