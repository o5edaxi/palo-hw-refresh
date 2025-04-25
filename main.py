"""Get data from a Palo Alto PanOS firewall and compare it with its published limits from their website"""
import sys
import re
import logging
import argparse
import inspect
import os
import json
from datetime import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from lxml import etree
import palo_hw_refresh.retrieve as retrieve
import palo_hw_refresh.extract as extract
import palo_hw_refresh.output as output


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


SCRAPE_URL_VALUES = 'https://www.paloaltonetworks.com/apps/pan/public/solr/proxy?corename=productcompare&q=*&wt=json&fq=language:"en_US"'  # Language is important for some reason
SCRAPE_URL_LEGEND = 'https://www.paloaltonetworks.com/products/product-comparison'
FILE_NAME = 'panw_datasheet.json'


def run_all_functions(module, mode):
    outputs = []
    # Get all the functions in the module
    functions = [func for func, obj in inspect.getmembers(module, inspect.isfunction)]
    # Run each function
    for func_name in functions:
        func = getattr(module, func_name)  # Get the function by name
        logging.debug('Running function %s of module %s with arguments: %s', func, module, mode)
        output = func(*mode) # Call the function with all arguments in "mode"
        logging.info('output is %s', output)
        outputs.append(output)
    return outputs


def main():
    # datasheet_dict == {'PA-440': {'Throughput': 1000, 'Sessions': 1234}, 'PA-450': {...}, ...}
    try:
        logging.info('Attempting to retrieve datasheet from disk, %s', FILE_NAME)
        with open(FILE_NAME, 'r') as f:
            datasheet_dict = json.load(f)
        logging.warning('Got datasheet from disk. Delete file %s to force retrieval from website', FILE_NAME)
    except FileNotFoundError:
        logging.warning('No datasheet found on disk, retrieving from website')
        datasheet_dict = retrieve.scrape_website(SCRAPE_URL_VALUES, SCRAPE_URL_LEGEND)
        with open(FILE_NAME, 'w') as f:
            json.dump(datasheet_dict, f)
        logging.info('Saved datasheet to disk as %s', FILE_NAME)
    fw_session = requests.Session()
    logging.debug('Session to contact firewall is %s', fw_session)
    fw_session.headers.update({'X-PAN-KEY': args.api_key})
    fw_session.verify = not args.ignore_certs
    pra_key = args.api_key
    if args.panorama_api_key:
        pra_key = args.panorama_api_key
    pra1_session = requests.Session()
    logging.debug('Session to contact Panorama1 is %s', pra1_session)
    pra1_session.headers.update({'X-PAN-KEY': pra_key})
    pra1_session.verify = not args.ignore_certs

    pra2_session = requests.Session()
    logging.debug('Session to contact Panorama2 is %s', pra2_session)
    pra2_session.headers.update({'X-PAN-KEY': pra_key})
    pra2_session.verify = not args.ignore_certs
    try:
        sysinfo = retrieve.get_xml_api(fw_session, args.firewall, retrieve.cmd_to_xml('show system info'))
        model = sysinfo.xpath('/response/result/system/model/text()')[0]
        serial = sysinfo.xpath('/response/result/system/serial/text()')[0]
        hostname = sysinfo.xpath('/response/result/system/hostname/text()')[0]
    except requests.exceptions.SSLError:
        logging.critical("The firewall's TLS certificate is untrusted. If this is expected, consider running the script with the --ignore-certs argument. Exiting...")
        sys.exit(1)
    system_state = retrieve.get_xml_api(fw_session, args.firewall, retrieve.cmd_to_xml('show system state'))
    merged_config = retrieve.get_xml_api(fw_session, args.firewall, retrieve.cmd_to_xml('show config effective-running'))
    panorama1_ip = merged_config.xpath('//deviceconfig/system/panorama/local-panorama/panorama-server/text()')
    panorama2_ip = merged_config.xpath('//deviceconfig/system/panorama/local-panorama/panorama-server-2/text()')
    panorama1_ip = panorama1_ip[0] if panorama1_ip else None
    panorama2_ip = panorama2_ip[0] if panorama2_ip else None
    logging.info('Got Panorama IPs: %s, %s', panorama1_ip, panorama2_ip)
    if args.panorama_ip1:
        panorama1_ip = args.panorama_ip1
        logging.warning('Overriding Panorama 1 IP with %s', panorama1_ip)
    if args.panorama_ip2:
        panorama2_ip = args.panorama_ip2
        logging.warning('Overriding Panorama 2 IP with %s', panorama2_ip)
    cmd_tup_list = run_all_functions(extract, ('__get_requirements__', system_state, merged_config, None, None))
    logging.info('Need to run commands: %s', cmd_tup_list)
    commands = set([item for x in cmd_tup_list for item in x[1] if item])
    pra_commands = set([item for x in cmd_tup_list for item in x[2] if item])
    if not args.auto_approve:
        print('Will run commands:')
        print(*commands, sep='\n')
        confirmation = input('These commands will be run once against the device using the XML API. Type "y" to proceed:')
        if confirmation.lower() not in ["y", "yes"]:
            print('Exiting')
            sys.exit(0)
    xml_api_output_dict = {}
    for command in commands:
        logging.debug('Fetching command for a function: %s', command)
        xml_api_output_dict[command] = retrieve.get_xml_api(fw_session, args.firewall, retrieve.cmd_to_xml(command))
    if panorama1_ip and not args.skip_panorama and not args.auto_approve:
        print('Will run commands on Panorama:')
        print(*pra_commands, sep='\n')
        confirmation = input('These commands will be run once against the managing Panorama(s) using the XML API. Type "y" to proceed:')
        if confirmation.lower() not in ["y", "yes"]:
            print('Exiting')
            sys.exit(0)
    pra_api_output_dict = None
    if panorama1_ip and not args.skip_panorama:
        pra_api_output_dict = {panorama1_ip: {}}
        for command in pra_commands:
            logging.debug('Fetching Panorama1 command for a function: %s', command)
            pra_api_output_dict[panorama1_ip][command] = retrieve.get_xml_api(pra1_session, panorama1_ip, retrieve.cmd_to_xml(command))
        if panorama2_ip:
            pra_api_output_dict[panorama2_ip] = {}
            for command in pra_commands:
                logging.debug('Fetching Panorama2 command for a function: %s', command)
                pra_api_output_dict[panorama2_ip][command] = retrieve.get_xml_api(pra2_session, panorama2_ip, retrieve.cmd_to_xml(command))
    answer_tup_list = run_all_functions(extract, (None, system_state, merged_config, xml_api_output_dict, pra_api_output_dict))
    answer_dict = {}
    comments_dict = {}
    for answer in answer_tup_list:
        answer_dict[answer[0]] = answer[1]
        comments_dict[answer[0]] = answer[2]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'FW_Analysis-{model}-{serial}-{hostname}-{timestamp}.xlsx'
    output.write_excel(answer_dict, comments_dict, datasheet_dict, filename)
    logging.warning('Finished.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get data from a Palo Alto PanOS firewall and compare it with its published limits from their website')
    parser.add_argument('firewall', type=str, help='Firewall IP address or hostname')
    parser.add_argument('api_key', type=str, help='A valid API key with read privileges for the device.')
    parser.add_argument('-k', '--ignore-certs', action='store_true', help="Don't check for valid certificates when connecting to firewalls. Default: Validate certificates")
    parser.add_argument('--panorama-ip1', type=str, help='Force a different primary Panorama IP or FQDN. Default: Retrieve IP from the firewall configuration')
    parser.add_argument('--panorama-ip2', type=str, help='Force a different secondary Panorama IP or FQDN. Default: Retrieve IP from the firewall configuration')
    parser.add_argument('-2', '--panorama-api-key', type=str, help='Force a different API key to contact Panorama. Default: use the firewall key')
    parser.add_argument('-s', '--skip-panorama', action='store_true', help="Do not contact Panorama(s), report will be missing certain metrics. Default: contact Panorama")
    parser.add_argument('-a', '--auto-approve', action='store_true', help="Do not ask for confirmation and review of the commands that will be executed. Default: ask for confirmation")
    parser.add_argument('-x', '--debug-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='WARNING', help='Logging message verbosity. Default: WARNING')
    args = parser.parse_args()
    logging.basicConfig(level=args.debug_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.info('Starting with args %s', args)
    main()
