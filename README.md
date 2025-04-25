# Palo Alto NGFW Resource Analyzer and Datasheet Comparison

This script:

1. Downloads the [datasheets](https://www.paloaltonetworks.com/products/product-comparison)
2. Contacts a Palo Alto Networks firewall over the XML API
3. Runs a series of "show" commands and extracts information from the firewall runtime, configuration, and optionally its Panorama
4. Outputs an Excel document in which the actual usage for every datasheet metric is listed for the firewall, and compared to the maximum for all NGFW models

The Excel file makes use of conditional formatting to quickly point out metrics where the current usage is close to, or exceeds, the maximum for the current platform.

It also allows comparing the current resource usage with other models as well as datasheet values between different models.

This reduces (but far from negates) the amount of manual work required to properly size hardware refresh projects as well as firewall health checks.

**After generating the Excel file, select your current firewall model (or any model you are planning to replace it with) to see the % of total capacity that would be consumed.**

![](img1.jpg)

**The % is highlighted in shades of red the closer it gets to 100%.**

![](img2.jpg)

**The datasheet values themselves are also compared between the selected model (left) and all other models, coded in blue for a same value, red for a worse value, and green for a better one.**

![](img3.jpg)

### Panorama

The script will contact the device's managing Panorama(s) if available, mainly to retrieve historical throughput and connection numbers. Disable with --skip-panorama.


### Usage

```
usage: main.py [-h] [-k] [--panorama-ip1 PANORAMA_IP1] [--panorama-ip2 PANORAMA_IP2] [-2 PANORAMA_API_KEY] [-s] [-a] [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}] firewall api_key

Get data from a Palo Alto PanOS firewall and compare it with its published limits from their website

positional arguments:
  firewall              Firewall IP address or hostname
  api_key               A valid API key with read privileges for the device.

options:
  -h, --help            show this help message and exit
  -k, --ignore-certs    Don't check for valid certificates when connecting to firewalls. Default: Validate certificates
  --panorama-ip1 PANORAMA_IP1
                        Force a different primary Panorama IP or FQDN. Default: Retrieve IP from the firewall configuration
  --panorama-ip2 PANORAMA_IP2
                        Force a different secondary Panorama IP or FQDN. Default: Retrieve IP from the firewall configuration
  -2 PANORAMA_API_KEY, --panorama-api-key PANORAMA_API_KEY
                        Force a different API key to contact Panorama. Default: use the firewall key
  -s, --skip-panorama   Do not contact Panorama(s), report will be missing certain metrics. Default: contact Panorama
  -a, --auto-approve    Do not ask for confirmation and review of the commands that will be executed. Default: ask for confirmation
  -x {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --debug-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging message verbosity. Default: WARNING
```
```
Example:

  $ python3 main.py 192.0.2.1 ==APIKEY123
```

### Support

The script has been tested with PanOS 10.2, 11.1, 11.2, Multi-VSYS, Multi-VR, Multi-LR. Multi-DP has **not** been tested.

Linecard models are currently out of scope due to the ambiguity in comparing chassis usage to datasheet values.


### Requirements

- [pint](https://pypi.org/project/Pint/) (install with ```pip3 install pint```)
- [xlsxwriter](https://pypi.org/project/XlsxWriter/) (install with ```pip3 install xlsxwriter```)
- [requests](https://pypi.org/project/requests/) (install with ```pip3 install requests```)
- [lxml](https://pypi.org/project/lxml/) (install with ```pip3 install lxml```)

### License

This project is licensed under the [Apache-2.0 license](LICENSE).
