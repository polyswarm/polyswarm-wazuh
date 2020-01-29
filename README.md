# polyswarm-wazuh

## Requirements

* yum -y install python3.6
* yum -y install python3-pip
* pip3 install polyswarm-api==1.1.1

## Install

1. Execute `install.sh` script
```
$ bash scripts/install.sh

```
2. Add integration settings to `/var/ossec/etc/ossec.conf` file inside
block `<ossec_config>..</ossec_config>`
```
<integration>
  <name>custom-polyswarm</name>
  <api_key>YOUR_API_KEY</api_key> <- Add PolySwarm API Key here
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

## Tested Versions
* 3.10.2
* 3.11.1
