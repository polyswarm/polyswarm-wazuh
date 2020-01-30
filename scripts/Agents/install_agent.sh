#!/bin/bash

[ -z "${1}" ] || [ -z "${2}" ] && printf "Usage: %s <agent_name> <ip>\n" "${0}" && exit 1

AGENT_NAME="${1}"
IP="${2}"

curl -k -u foo:bar -X POST -d "name=${AGENT_NAME}&ip=${IP}" "https://localhost:55000/agents"

#eof
