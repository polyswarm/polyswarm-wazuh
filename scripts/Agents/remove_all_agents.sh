/var/ossec/bin/manage_agents -l|grep ID|awk '{print $2}'|sed 's/,//g'|while read -r ID; do echo "y"|/var/ossec/bin/manage_agents -r "${ID}"; done
/var/ossec/bin/manage_agents -l
