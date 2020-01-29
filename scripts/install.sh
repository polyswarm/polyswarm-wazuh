#!/bin/bash

INTEGRATION_NAME='custom-polyswarm'

cp etc/rules/polyswarm_rules.xml /var/ossec/etc/rules/
cp integrations/{${INTEGRATION_NAME},${INTEGRATION_NAME}.py} /var/ossec/integrations/

chmod 750 /var/ossec/integrations/{${INTEGRATION_NAME},${INTEGRATION_NAME}.py}
chown root:ossec /var/ossec/integrations/{${INTEGRATION_NAME},${INTEGRATION_NAME}.py}

if [ -z "${1}" ] && [ "${1}" == "restart" ]; then
    systemctl restart wazuh-manager
    systemctl restart wazuh-api
fi

#eof
