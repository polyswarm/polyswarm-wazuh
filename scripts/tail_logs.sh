tail -f $(find /var/ossec/logs/ -name '*.log'|sed ':a;N;$!ba;s/\n/ /g')
