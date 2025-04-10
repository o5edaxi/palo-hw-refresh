"""Functions to deal with API and PANW website"""
import requests
import logging
import json
import sys
import time
from datetime import datetime
from lxml import etree
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pint.errors
from pint import UnitRegistry


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ureg = UnitRegistry()
ureg.define('M = 1000000 = M')
ureg.define('G = 1000000000 = G')
ureg.define('T = 1000000000000 = T')


def cmd_to_xml(command):
    if command.startswith('<'):  # Allow passing XML through
        return command
    split = command.split()
    cmd_tree = etree.Element(split[0])
    levels = [cmd_tree]
    i = 0
    for a in split[1:]:
        if a[0] == '"' and a[-1] == '"':
            # It's just text for the last added element
            levels[i].text = a.strip('"')
            # Do not increment i, actually close the tag and go up one level. This allows for special cases like:
            # show thing "all" option "count"
            # <show><thing>all</thing><option>count</option></show>
            del levels[i]
            i -= 1
        else:
            levels.append(etree.SubElement(levels[i], a))
            i += 1
    cmd_string = etree.tostring(cmd_tree, pretty_print=False, xml_declaration=False, encoding="UTF-8")
    return cmd_string.decode('utf-8')


def get_xml_api(ses, fw, cmd):
    fw_url = f'https://{fw}/api/?type=op&cmd={cmd}'
    try:
        response = ses.get(fw_url, timeout=60)
        if response.status_code == 403 and not ( cmd.startswith('show ') or cmd.startswith('<show>')):
            logging.error('Insufficient privileges to run command %s, data will be missing in the Excel file', cmd)
            return '__unauthorized__'
        response.raise_for_status()
        response_xml = etree.fromstring(response.text)
        if response.text.startswith('<response status="success"><result><![CDATA'):
            return response_xml.xpath('/response/result/text()')[0]
        if response_xml.xpath('/response/@status')[0] != 'success':
            logging.info('API Error from firewall for command %s: %s', cmd, response.text)
            return response_xml.xpath('/response/result/text()')
        if not len(response_xml):
            logging.info('Empty XML for command %s: %s', cmd, response.text)
            return response_xml.xpath('/response/result/text()')
        return response_xml
    except requests.exceptions.HTTPError:
        logging.critical('[%s] Received HTTP %s while querying firewall %s', ses, response.status_code, fw)
        raise
    except etree.XMLSyntaxError as err:
        logging.critical('[%s] Firewall response is malformed: %s', ses, err)
        raise
    except requests.exceptions.RequestException as err:
        logging.critical('[%s] Error querying Firewall: %s', ses, err)
        raise


def scrape_website(values_url, legend_url):
    logging.warning('Downloading datasheets')
    scr_sesh = requests.Session()
    row = 0
    rows = 40
    product_dict_list = []
    response1 = scr_sesh.get(values_url + f'&start={row}&rows={rows}', timeout=10)
    logging.info('Got datasheets %d - %d', row, rows)
    logging.debug('Got response from first URL: %s', response1.text)
    response1.raise_for_status()
    grep = 'var sliderData = '
    if response1.text.startswith(grep):
        product_dict_list.append(json.loads(response1.text.strip(grep)))
    total_found = int(product_dict_list[0]['response']['numFound'])
    for i in range(1, 100):
        row += rows
        response1 = scr_sesh.get(values_url + f'&start={row}&rows={rows}', timeout=10)
        logging.debug('Got response from first URL: %s', response1.text)
        response1.raise_for_status()
        product_dict_list.append(json.loads(response1.text.strip(grep)))
        logging.info('Got datasheets %d - %d of %d total', row, row + rows, total_found)
        if (row + rows) >= total_found:
            break
        time.sleep(1)
    response2 = scr_sesh.get(legend_url, timeout=10)
    logging.debug('Got response from second URL: %s', response2.text)
    response2.raise_for_status()
    grep = '	var featureMap = '
    legend_dict = None
    for line in response2.text.split('\n'):
        if line.startswith(grep):
            legend_dict = json.loads(line.strip(grep).strip(';'))
            break
    if not product_dict_list or not legend_dict:
        logging.critical('Failed to get info from website')
        sys.exit(1)
    output_dict_dict = {}
    """
    legend
    {asd_dfi: {name: 'Throughput', group: 'Performance'}, asd2_dfi: {name: 'Sessions', group: 'Performance'}, ...}
    products
    [{response: {docs: [{product_name: 'PA-440', asd_dfi: '1000', asd2_dfi: '2000', ...}, {product_name: 'PA-450', ...]}}, {response: {docs: ...}}]
    output
    {'PA-440': {'Throughput': 1000, 'Sessions': 1234}, 'PA-450': {...}, ...}
    """
    for product_dict in product_dict_list:
        for dicti in product_dict['response']['docs']:
            prod_name = dicti['product_name']
            output_dict_dict[prod_name] = {}
            for metric_codename, metric_value in dicti.items():
                if metric_codename.endswith('_dfi'):
                    try:
                        if legend_dict[metric_codename]['name'].startswith('FACET'):  # These aren't used
                            continue
                        output_dict_dict[prod_name][legend_dict[metric_codename]['name']] = normalize_metric(metric_value, prod_name, legend_dict[metric_codename]['name'])
                    except KeyError:  # Not all are in the legend
                        logging.error("Didn't find name for metric %s in model %s having value %s", metric_codename, prod_name, metric_value)
                        pass
    return output_dict_dict


def normalize_metric(metric_str, prod, name):
    # Remove commas, asterisks, and standardize spacing
    cleaned = metric_str.replace(',', '').replace('*', '').strip()
    # bps is seen as Baud by pint... fix it
    cleaned = cleaned.replace('bps', 'bit/s').replace('Bps', 'byte/s')
    # NA N/A - etc
    cleaned = cleaned.replace('N/A', 'NA')
    cleaned = 'NA' if cleaned == '-' else cleaned
    cleaned = cleaned.replace('Watts', '').replace('Watt', '').strip()
    try:
        # If no unit specified, return as is
        return float(cleaned)
    except ValueError:
        if cleaned in ('Yes', 'No', 'System limit', 'System Limit', 'NA', 'TBD', 'check Customer Support Portal'):
            logging.info('Returning word metric %s standardized as %s for product %s with name %s', metric_str, cleaned, prod, name)
            return cleaned
        elif '(SR-IOV)' in cleaned:
            logging.info('Returning word metric %s standardized as %s for product %s with name %s', metric_str, cleaned,
                         prod, name)
            return cleaned
        elif name in ('End-of-sale'):
            dt = datetime.strptime(cleaned, "%b %Y")
            logging.info('Returning word metric %s standardized as %s for product %s with name %s', metric_str, cleaned, prod, name)
            return int(dt.timestamp())
        elif 'Traffic - ' in name or 'Mgmt - ' in name:
            return cleaned
        elif prod in ('PAN-PA-7000-100G-NPC-A', 'PAN-PA-7000-DPC-A', 'PA-7080', 'PA-7050') and '/' in cleaned:
            # These models all have metrics that vary, sometimes based on linecard model, sometimes based on supervisor
            # Datasheet displays min/max values. Comparison is NOT implemented for these values.
            return cleaned
        try:
            # Attempt unit conversion
            return float(ureg(cleaned).to('bit/s').magnitude)
        except pint.errors.UndefinedUnitError:
            # Return as is
            logging.warning('1-Could not normalize metric %s of product %s to integer: %s', name, prod, metric_str)
            return metric_str
        except pint.errors.DimensionalityError:
            if ureg(cleaned).units in ('M', 'G', 'T'):  # "DNS Domains per system", sometimes "4000000" sometimes "4M"
                return float(ureg(cleaned))
            # Return as is
            logging.warning('2-Could not normalize metric %s of product %s to integer: %s', name, prod, metric_str)
            return metric_str
        except AttributeError:
            # pint did arithmetic on a string, like ureg('1/2') == 0.5 so it has no .to() attribute
            logging.warning('3-Could not normalize metric %s of product %s to integer: %s', name, prod, metric_str)
            return metric_str

