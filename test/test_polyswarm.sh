#!/bin/bash

API_KEY=$(awk '/custom-polyswarm/{getline; print}' /var/ossec/etc/ossec.conf|sed -n 's:.*<api_key>\(.*\)</api_key>.*:\1:p')
EVENT_SAMPLE=${1}

[ -z "${API_KEY}" ] && printf "Error: Configure PolySwarm <api_key> in /var/ossec/etc/ossec.conf\n" && exit 1
[ -z "${EVENT_SAMPLE}" ] && printf "Usage: %s <event_sample>\n" "${0}" && exit 1

bash scripts/install.sh
printf "[*] Installed latest version.\n"

/var/ossec/integrations/custom-polyswarm "${EVENT_SAMPLE}" "${API_KEY}" debug

#eof
