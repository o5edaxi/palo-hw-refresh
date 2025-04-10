"""All these functions get called automatically by main with func('___get_requirements___') to find out what API call
outputs they need. The function name is lower() of the row name from the Palo Alto website, but isn't used anywhere
else. main() provides the config and "show system state" right upfront so the function is able to use it to construct
its requirements, such as adding the vsys name in the commands it needs"""
import re
import logging
import json
from lxml import etree

"""
Template:

def security_rule_schedules(mode, state, config, output):
    \"""Security rule schedules\"""
    key = 'Security rule schedules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value =  # IMPLEMENT YOUR LOGIC HERE. "state" is 'show system state' as a string, "config" is the merged config XML
    # as an lxml etree, "output" is the dictionary with the xml output of the commands you requested in "requirements"
    # which you can provide either as text (it will try to xmlize them) or xml. Return "__from_model__" to copy the
    # firewall model's datasheet value.
    return (key, value, comment)
"""
"""
Format:

Throughput: int(Bit/second)
Units: int(number)
Power: float(Watts)
Dates: int(unix)
Bool: Yes|No
Not available: NA

Arithmetic operations will be performed on the returned values for Throughput and Units (% of usage, =A1/B1) as well as
Dates (e.g. days to EoS)
Bools and "NA" will be marked for review in the Excel only if they differ (=A1=B1 FALSE) from datasheet, with various
logic

Return "__from_model__" to clone the datasheet value
"""

comment = ''

def app_id_firewall_throughput(mode, state, config, output):
    """App-ID firewall throughput"""
    # This and the other throughput/session checks cannot be performed without at least several weeks of
    # SNMP/Netflow/gNMI statistics from a proper monitoring solution, preferably including data from the switches
    # themselves. The code below is just a naive example to produce demo data. Do NOT use this for firewall
    # sizing. These metrics are also insufficient by themselves to evaluate firewall dataplane load, as a proper
    # analysis should include CPU usage, pool usage, as well as every kind of hardware and software buffer,
    # packet descriptor, and packet inspection queues. Throughput (for the worst case, i.e. not distinguishing
    # between App-ID/TP/IPSEC), port bitrate, connections, and cps, can also be somewhat approximated by looking at
    # Panorama device monitoring data, which has decent retention and a resolution of 10 minutes. This is to be
    # implemented. SCM/AIOps can also provide some of this data, but it is not exposed by its API. The TSF and
    # dp-monitor.log contain detailed metrics, but these only go back a few days.
    key = 'App-ID firewall throughput'
    requirements = ['show session info']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = int(output[requirements[0]].xpath('/response/result/kbps/text()')[0]) * 1000  # to bps
    value = '__not_implemented__'
    return (key, value, comment)


def threat_prevention_throughput(mode, state, config, output):
    """Threat prevention throughput"""
    key = 'Threat prevention throughput'
    requirements = ['show session info']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = int(output[requirements[0]].xpath('/response/result/kbps/text()')[0]) * 1000  # to bps
    value = '__not_implemented__'
    return (key, value, comment)


def ipsec_vpn_throughput(mode, state, config, output):
    """IPSec VPN throughput"""
    key = 'IPSec VPN throughput'
    requirements = ['show session info']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = int(output[requirements[0]].xpath('/response/result/kbps/text()')[0]) * 1000  # to bps
    value = '__not_implemented__'
    return (key, value, comment)


def connections_per_second(mode, state, config, output):
    """Connections per second"""
    key = 'Connections per second'
    requirements = ['show session info']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = int(output[requirements[0]].xpath('/response/result/cps/text()')[0])
    value = '__not_implemented__'
    return (key, value, comment)


def max_sessions_ipv4_or_ipv6(mode, state, config, output):
    """Max sessions (IPv4 or IPv6)"""
    key = 'Max sessions (IPv4 or IPv6)'
    requirements = ['show session info']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = int(output[requirements[0]].xpath('/response/result/num-active/text()')[0])
    value = '__not_implemented__'
    return (key, value, comment)


def security_rules(mode, state, config, output):
    """Security rules"""
    key = 'Security rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/security/rules/entry'))
    return (key, value, comment)


def security_rule_schedules(mode, state, config, output):
    """Security rule schedules"""
    key = 'Security rule schedules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//schedule/entry'))
    return (key, value, comment)


def nat_rules(mode, state, config, output):
    """NAT rules"""
    key = 'NAT rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/nat/rules/entry'))
    return (key, value, comment)


def decryption_rules(mode, state, config, output):
    """Decryption rules"""
    key = 'Decryption rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/decryption/rules/entry'))
    return (key, value, comment)


def app_override_rules(mode, state, config, output):
    """App override rules"""
    key = 'App override rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/application-override/rules/entry'))
    return (key, value, comment)


def tunnel_content_inspection_rules(mode, state, config, output):
    """Tunnel content inspection rules"""
    key = 'Tunnel content inspection rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/tunnel-inspect/rules/entry'))
    return (key, value, comment)


def sd_wan_rules(mode, state, config, output):
    """SD-WAN rules"""
    key = 'SD-WAN rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/sdwan/rules/entry'))
    return (key, value, comment)


def policy_based_forwarding_rules(mode, state, config, output):
    """Policy based forwarding rules"""
    key = 'Policy based forwarding rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/pbf/rules/entry'))
    return (key, value, comment)


def captive_portal_rules(mode, state, config, output):
    """Captive portal rules"""
    key = 'Captive portal rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/authentication/rules/entry'))
    return (key, value, comment)


def dos_protection_rules(mode, state, config, output):
    """DoS protection rules"""
    key = 'DoS protection rules'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/dos/rules/entry'))
    return (key, value, comment)


def max_security_zones(mode, state, config, output):
    """Max security zones"""
    key = 'Max security zones'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//zone/entry'))
    return (key, value, comment)


def address_objects(mode, state, config, output):
    """Address objects"""
    key = 'Address objects'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//address/entry'))
    return (key, value, comment)


def address_groups(mode, state, config, output):
    """Address groups"""
    key = 'Address groups'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//address-group/entry'))
    return (key, value, comment)


def members_per_address_group(mode, state, config, output):
    """Members per address group"""
    key = 'Members per address group'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    # Extract all entries
    entries = config.xpath("//address-group/entry")
    # Dictionary to store the count of members for each entry name
    member_counts = {}
    for entry in entries:
        name = entry.get("name")
        member_count = len(entry.xpath(".//static/member"))
        # Group counts by entry name
        if name not in member_counts:
            member_counts[name] = member_count
        else: # same addrgrp from different vsys
            member_counts[name] = member_count if member_count > member_counts[name] else member_counts[name]
    # Find the maximum count of members for each entry name
    value = 0
    for addrgrp, membernum in member_counts.items():
        if membernum > value:
            value = membernum
    return (key, value, comment)


def service_objects(mode, state, config, output):
    """Service objects"""
    key = 'Service objects'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//service/entry'))
    return (key, value, comment)


def service_groups(mode, state, config, output):
    """Service groups"""
    key = 'Service groups'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//service-group/entry'))
    return (key, value, comment)


def members_per_service_group(mode, state, config, output):
    """Members per service group"""
    key = 'Members per service group'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    # Extract all entries
    entries = config.xpath("//service-group/entry")
    # Dictionary to store the count of members for each entry name
    member_counts = {}
    for entry in entries:
        name = entry.get("name")
        member_count = len(entry.xpath(".//static/member"))
        # Group counts by entry name
        if name not in member_counts:
            member_counts[name] = member_count
        else:  # same svcgrp from different vsys
            member_counts[name] = member_count if member_count > member_counts[name] else member_counts[name]
    # Find the maximum count of members for each entry name
    value = 0
    for addrgrp, membernum in member_counts.items():
        if membernum > value:
            value = membernum
    return (key, value, comment)


def fqdn_address_objects(mode, state, config, output):
    """FQDN address objects"""
    key = 'FQDN address objects'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//address/entry/fqdn'))
    return (key, value, comment)


def max_dag_ip_addresses(mode, state, config, output):
    """Max DAG IP addresses"""
    key = 'Max DAG IP addresses'
    requirements = ['show object registered-ip all option "count"']
    if mode == '__get_requirements__':
        return (key, requirements)
    count = output['show object registered-ip all option "count"'].xpath('//count/text()')
    value = float(count[0] if count else 0)
    return (key, value, comment)


def tags_per_ip_address(mode, state, config, output):
    """Tags per IP address"""
    key = 'Tags per IP address'
    requirements = ["<show><object><registered-ip><tag><entry name='all'/></tag></registered-ip></object></show>"]
    if mode == '__get_requirements__':
        return (key, requirements)
    tags = [len(entry.xpath('.//member')) for entry in output[requirements[0]].xpath('//entry')]
    value = max(tags) if tags else 0
    return (key, value, comment)


def security_profiles(mode, state, config, output):
    """Security profiles"""
    key = 'Security profiles'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//profiles/*/entry'))
    return (key, value, comment)


def custom_app_id_signatures(mode, state, config, output):
    """Custom App-ID signatures"""
    key = 'Custom App-ID signatures'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//application/entry'))
    return (key, value, comment)


def shared_custom_app_ids(mode, state, config, output):
    """Shared custom App-IDs"""
    key = 'Shared custom App-IDs'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/shared/application/entry'))
    return (key, value, comment)


def custom_app_ids_virtual_system_specific(mode, state, config, output):
    """Custom App-IDs (virtual system specific)"""
    key = 'Custom App-IDs (virtual system specific)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/vsys/entry/application/entry'))
    return (key, value, comment)


def ip_user_mappings_management_plane(mode, state, config, output):
    """IP-User mappings (management plane)"""
    key = 'IP-User mappings (management plane)'
    requirements = ['show user ip-user-mapping-mp all option "count"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = float(output[requirements[0]].xpath('//count/text()')[0])
    return (key, value, comment)


def ip_user_mappings_data_plane(mode, state, config, output):
    """IP-User mappings (data plane)"""
    key = 'IP-User mappings (data plane)'
    requirements = ['show user ip-user-mapping all option "count"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = float(output[requirements[0]].xpath('//count/text()')[0])
    return (key, value, comment)


def active_and_unique_groups_used_in_policy(mode, state, config, output):
    """Active and unique groups used in policy"""
    key = 'Active and unique groups used in policy'
    requirements = ['show user group list']
    if mode == '__get_requirements__':
        return (key, requirements)
    match = re.search(r'Total: (\d+)', output[requirements[0]])
    value = match.group(1)
    return (key, value, comment)


def number_of_user_id_agents(mode, state, config, output):
    """Number of User-ID agents"""
    key = 'Number of User-ID agents'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//redistribution-agent/entry'))
    return (key, value, comment)


def monitored_servers_for_user_id(mode, state, config, output):
    """Monitored servers for User-ID"""
    key = 'Monitored servers for User-ID'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//user-id-collector/server-monitor/entry'))
    return (key, value, comment)


def terminal_server_agents(mode, state, config, output):
    """Terminal server agents"""
    key = 'Terminal server agents'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//ts-agent/entry'))
    return (key, value, comment)


def tags_per_user(mode, state, config, output):
    """Tags per User"""
    key = 'Tags per User'
    requirements = ["<show><object><registered-user><tag><entry name='all'/></tag></registered-user></object></show>"]
    if mode == '__get_requirements__':
        return (key, requirements)
    tags = [len(entry.xpath('.//member')) for entry in output[requirements[0]].xpath('//entry')]
    value = max(tags) if tags else 0
    return (key, value, comment)


def max_ssl_inbound_certificates(mode, state, config, output):
    """Max SSL inbound certificates"""
    key = 'Max SSL inbound certificates'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/decryption/rules/entry/type/ssl-inbound-inspection/certificates/member'))
    return (key, value, comment)


def ssl_certificate_cache_forward_proxy(mode, state, config, output):
    """SSL certificate cache (forward proxy)"""
    key = 'SSL certificate cache (forward proxy)'
    requirements = ['show system setting ssl-decrypt certificate-cache']
    if mode == '__get_requirements__':
        return (key, requirements)

    match = re.search(r'Cached (\d+) certificates', output[requirements[0]].xpath('//member/text()')[0])
    value = float(match.group(1))
    return (key, value, comment)


def max_concurrent_decryption_sessions(mode, state, config, output):
    """Max concurrent decryption sessions"""
    key = 'Max concurrent decryption sessions'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = '__not_implemented__'
    return (key, value, comment)


def decryption_port_mirror(mode, state, config, output):
    """Decryption Port Mirror"""
    key = 'Decryption Port Mirror'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/interface/ethernet/entry/decrypt-mirror'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def network_packet_broker(mode, state, config, output):
    """Network Packet Broker"""
    key = 'Network Packet Broker'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/network-packet-broker/rules/entry'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def hsm_supported(mode, state, config, output):
    """HSM Supported"""
    key = 'HSM Supported'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/deviceconfig/system/hsm-settings'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def total_entries_for_allow_list_block_list_and_custom_categories(mode, state, config, output):
    """Total entries for allow list, block list and custom categories"""
    key = 'Total entries for allow list, block list and custom categories'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//profiles/custom-url-category/entry/list/member'))
    return (key, value, comment)


def max_custom_categories(mode, state, config, output):
    """Max custom categories"""
    key = 'Max custom categories'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//profiles/custom-url-category/entry'))
    return (key, value, comment)


def max_custom_categories_virtual_system_specific(mode, state, config, output):
    """Max custom categories (virtual system specific)"""
    key = 'Max custom categories (virtual system specific)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/vsys/entry/profiles/custom-url-category'))
    return (key, value, comment)


def dataplane_cache_size_for_url_filtering(mode, state, config, output):
    """Dataplane cache size for URL filtering"""
    key = 'Dataplane cache size for URL filtering'
    requirements = ['show running url-cache statistics']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = float(0)
    for match in re.findall(r'number of urls\|\s+(\d+)', output[requirements[0]].xpath('//response/result/member/text()')[0]):
        value += float(match)
    return (key, value, comment)


def management_plane_dynamic_cache_size(mode, state, config, output):
    """Management plane dynamic cache size"""
    key = 'Management plane dynamic cache size'
    requirements = ['show system setting url-cache statistics']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = float(0)
    for match in re.findall(r'number of urls\|\s+(\d+)',
                            output[requirements[0]].xpath('//response/result/member/text()')[0]):
        value += float(match)
    return (key, value, comment)


def max_number_of_custom_lists(mode, state, config, output):
    """Max number of custom lists"""
    key = 'Max number of custom lists'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//external-list/entry'))
    return (key, value, comment)


def max_number_of_ips_per_system(mode, state, config, output):
    """Max number of IPs per system
    This command requires write privileges"""
    key = 'Max number of IPs per system'
    requirements = ['request system external-list list-capacities']
    if mode == '__get_requirements__':
        return (key, requirements)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//IP/running-cap/text()')[0])
    return (key, value, comment)


def max_number_of_dns_domains_per_system(mode, state, config, output):
    """Max number of DNS Domains per system
    This command requires write privileges"""
    key = 'Max number of DNS Domains per system'
    requirements = ['request system external-list list-capacities']
    if mode == '__get_requirements__':
        return (key, requirements)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//Domain/running-cap/text()')[0])
    return (key, value, comment)


def max_number_of_url_per_system(mode, state, config, output):
    """Max number of URL per system
    This command requires write privileges"""
    key = 'Max number of URL per system'
    requirements = ['request system external-list list-capacities']
    if mode == '__get_requirements__':
        return (key, requirements)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//URL/running-cap/text()')[0])
    return (key, value, comment)


def shortest_check_interval_min(mode, state, config, output):
    """Shortest check interval (min)"""
    key = 'Shortest check interval (min)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    entries = config.xpath('//external-list/entry/type/ip/recurring/*')
    value = '__from_model__'
    shortest = 99999999999999
    for entry in entries:
        if entry.tag == 'five-minute':
            shortest = 5 if shortest > 5 else shortest
        elif entry.tag == 'hourly':
            shortest = 60 if shortest > 60 else shortest
        elif entry.tag == 'daily':
            shortest = 1440 if shortest > 1440 else shortest
        elif entry.tag == 'weekly':
            shortest = 10080 if shortest > 10080 else shortest
        elif entry.tag == 'monthly':
            shortest = 44640 if shortest > 44640 else shortest
        else:
            # Unknown value, reset it and stop counting
            value = '__from_model__'
            break
    value = shortest if shortest != 99999999999999 else value
    return (key, value, comment)


def mgmt_out_of_band(mode, state, config, output):
    """Mgmt - out-of-band"""
    key = 'Mgmt - out-of-band'
    requirements = ['show interface "management"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len([x for x in output[requirements[0]].xpath('/response/result/info/state/text()') if x == 'up'])
    return (key, value, comment)


def mgmt_10_100_1000_high_availability(mode, state, config, output):
    """Mgmt - 10/100/1000 high availability"""
    key = 'Mgmt - 10/100/1000 high availability'
    requirements = ['show interface "hardware"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.ha\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            try:
                if match.group(1) == 'Up' and match.group(3) in ['RJ45', 'HA']:
                    if match.group(2) in ['10Mb', '100Mb', '1Gb']:
                        value += 1
                    elif match.group(2) == 'Unknown':
                        value = '__unknown__'
                        break
            except IndexError:
                continue
        if re.search(r"^net\.s\d+\.eth(\d+)\.hwcfg\:", line):
            match = re.search(r"^net\.s\d+\.eth(\d+)\.hwcfg\:", line)
            if int(match.group(1)) > 0:
                # net.s1.eth1.hwcfg
                match = re.search(r"link': (\w+).+'setting': ([\w\.]+)", line)
                try:
                    if match.group(1) == 'Up':
                        if match.group(2) in ['10Mb', '100Mb', '1Gb']:
                            value += 1
                        elif match.group(2) == 'Unknown':
                            value = '__unknown__'
                            break
                except IndexError:
                    continue
    return (key, value, comment)


def mgmt_40gbps_high_availability(mode, state, config, output):
    """Mgmt - 40Gbps high availability"""
    key = 'Mgmt - 40Gbps high availability'
    requirements = ['show interface "hardware"']
    if mode == '__get_requirements__':
        return (key, requirements)
    ifaces = output[requirements[0]].xpath("/response/result/hw/entry[(starts-with(name/text(), 'ha') or starts-with(name/text(), 'aux') or starts-with(name/text(), 'hsci')) and state/text() = 'up']")
    try:
        value = len([x for x in ifaces if int(x.xpath('speed/text()')[0]) == 40000])
    except ValueError:
        value='__unknown__'
    return (key, value, comment)


def mgmt_10gbps_high_availability(mode, state, config, output):
    """Mgmt - 10Gbps high availability"""
    key = 'Mgmt - 10Gbps high availability'
    requirements = ['show interface "hardware"']
    if mode == '__get_requirements__':
        return (key, requirements)
    ifaces = output[requirements[0]].xpath("/response/result/hw/entry[(starts-with(name/text(), 'ha') or starts-with(name/text(), 'aux') or starts-with(name/text(), 'hsci')) and state/text() = 'up']")
    try:
        value = len([x for x in ifaces if int(x.xpath('speed/text()')[0]) == 10000])
    except ValueError:
        value='__unknown__'
    return (key, value, comment)


def traffic_10_100_1000(mode, state, config, output):
    """Traffic - 10/100/1000"""
    key = 'Traffic - 10/100/1000'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and match.group(3) == 'RJ45':
                if match.group(2) in ['10Mb', '100Mb', '1Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_10m_100m_1g_25g_5g(mode, state, config, output):
    """Traffic - 10M/100M/1G/2.5G/5G"""
    key = 'Traffic - 10M/100M/1G/2.5G/5G'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and match.group(3) == 'RJ45':
                if match.group(2) in ['2.5Gb', '5Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_100_1000_10000(mode, state, config, output):
    """Traffic - 100/1000/10000"""
    key = 'Traffic - 100/1000/10000'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and match.group(3) == 'RJ45':
                if match.group(2) in ['100Mb', '1Gb', '10Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_1gbps_sfp(mode, state, config, output):
    """Traffic - 1Gbps SFP"""
    key = 'Traffic - 1Gbps SFP'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['1Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_10gbps_sfp(mode, state, config, output):
    """Traffic - 10Gbps SFP+"""
    key = 'Traffic - 10Gbps SFP+'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['10Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_25gbps_sfp28(mode, state, config, output):
    """Traffic - 25Gbps SFP28"""
    key = 'Traffic - 25Gbps SFP28'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['25Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_40_100gbps_qsfp_qsfp28(mode, state, config, output):
    """Traffic - 40/100Gbps QSFP+/QSFP28"""
    key = 'Traffic - 40/100Gbps QSFP+/QSFP28'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['40Gb', '100Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_100gbps_qsfp28(mode, state, config, output):
    """Traffic - 100Gbps QSFP28"""
    key = 'Traffic - 100Gbps QSFP28'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['100Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def traffic_400gbps_qsfpdd(mode, state, config, output):
    """Traffic - 400Gbps QSFP-DD"""
    key = 'Traffic - 400Gbps QSFP-DD'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for line in state.split('\n'):
        if re.search(r"^sys\.s\d+\.p\d+\.status\:", line):
            # sys.s1.ha1.status
            match = re.search(r"link': (\w+).+'setting': ([\w\.]+).+'type': (\w+)", line)
            if match.group(1) == 'Up' and 'SFP' in match.group(3):
                if match.group(2) in ['400Gb']:
                    value += 1
                elif match.group(2) == 'Unknown':
                    value = '__unknown__'
                    break
    return (key, value, comment)


def eight02_1q_tags_per_device(mode, state, config, output):
    """802.1q tags per device"""
    key = '802.1q tags per device'
    requirements = ['show interface "logical"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(set(output[requirements[0]].xpath("/response/result/ifnet/entry/tag/text()")))
    return (key, value, comment)


def eight02_1q_tags_per_physical_interface(mode, state, config, output):
    """802.1q tags per physical interface"""
    key = '802.1q tags per physical interface'
    requirements = ['show interface "logical"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    ifaces = output[requirements[0]].xpath("/response/result/ifnet/entry[starts-with(name/text(), 'ethernet')]/name/text()")
    ifaces = set([x.split('.')[0] for x in ifaces])
    for ifc in ifaces:
        ifc_subifs = len(output[requirements[0]].xpath(f"/response/result/ifnet/entry[starts-with(name/text(), '{ifc}')]/tag/text()"))
        if ifc_subifs > value:
            value = ifc_subifs
    return (key, value, comment)


def max_interfaces_logical_and_physical(mode, state, config, output):
    """Max interfaces (logical and physical)"""
    key = 'Max interfaces (logical and physical)'
    requirements = ['show interface "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(output[requirements[0]].xpath("/response/result/ifnet/entry"))
    return (key, value, comment)


def maximum_aggregate_interfaces(mode, state, config, output):
    """Maximum aggregate interfaces"""
    key = 'Maximum aggregate interfaces'
    requirements = ['show interface "logical"']
    if mode == '__get_requirements__':
        return (key, requirements)
    ifaces = output[requirements[0]].xpath(
        "/response/result/ifnet/entry[starts-with(name/text(), 'ae')]/name/text()")
    value = len(set([x.split('.')[0] for x in ifaces]))
    return (key, value, comment)


def maximum_sd_wan_virtual_interfaces(mode, state, config, output):
    """Maximum SD-WAN virtual interfaces"""
    key = 'Maximum SD-WAN virtual interfaces'
    requirements = ['show interface "logical"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(output[requirements[0]].xpath("/response/result/ifnet/entry[starts-with(name/text(), 'sdwan')]"))
    return (key, value, comment)


def poe_enabled_interfaces(mode, state, config, output):
    """PoE Enabled Interfaces"""
    key = 'PoE Enabled Interfaces'
    requirements = ['show poe detail']
    if mode == '__get_requirements__':
        return (key, requirements)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/used-pwr/text()")
    ifaces = [int(float(x.split('/')[0])) for x in ifaces]
    value = len([x for x in ifaces if x > 0])
    return (key, value, comment)


def poe_interface_speed(mode, state, config, output):
    """PoE Interface Speed"""
    key = 'PoE Interface Speed'
    requirements = ['show poe detail', 'show interface "hardware"']
    if mode == '__get_requirements__':
        return (key, requirements)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry[not(starts-with(used-pwr/text(), '0.0'))]/name/text()")
    speeds = []
    for iface in ifaces:
        speeds.append(int(output[requirements[1]].xpath(f'/response/hw/entry[name/text()="{iface}"]/speed/text()')))
    value = str(float(max(speeds)) / 1000).replace('.0', '') + 'G'
    return (key, value, comment)


def total_power_budget(mode, state, config, output):
    """Total Power Budget"""
    key = 'Total Power Budget'
    requirements = ['show poe detail']
    if mode == '__get_requirements__':
        return (key, requirements)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/alloc-pwr/text()")
    value = sum([int(float(x.split('/')[0]) + 0.9) for x in ifaces])  # Round the int up
    return (key, value, comment)


def max_power_per_single_port(mode, state, config, output):
    """Max Power per single port"""
    key = 'Max Power per single port'
    requirements = ['show poe detail']
    if mode == '__get_requirements__':
        return (key, requirements)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/alloc-pwr/text()")
    value = max([int(float(x.split('/')[0]) + 0.9) for x in ifaces])  # Round the int up
    return (key, value, comment)


def five_g(mode, state, config, output):
    """5G"""
    key = '5G'
    requirements = ['show interface "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/interface/cellular/entry'))
    return (key, value, comment)


def virtual_routers(mode, state, config, output):
    """Virtual routers"""
    key = 'Virtual routers'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry')) + \
            len(config.xpath('//config/devices/entry/network/logical-router/entry'))
    return (key, value, comment)


def virtual_wires(mode, state, config, output):
    """Virtual wires"""
    key = 'Virtual wires'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/virtual-wire/entry'))
    return (key, value, comment)


def base_virtual_systems(mode, state, config, output):
    """Base virtual systems"""
    key = 'Base virtual systems'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/vsys/entry'))
    return (key, value, comment)


def max_virtual_systems(mode, state, config, output):
    """Max virtual systems"""
    key = 'Max virtual systems'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/vsys/entry'))
    return (key, value, comment)


def ipv4_forwarding_table_size(mode, state, config, output):
    """IPv4 forwarding table size"""
    key = 'IPv4 forwarding table size'
    requirements = ['show routing resource', '<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>']
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements)
    try:
        value = int(output[requirements[0]].xpath("/response/result/entry/All-IPv4/total/text()")[0])
    except IndexError:
        value = 0
    if len(output[requirements[1]]):
        jsonrib4 = json.loads(output[requirements[1]].xpath("/response/result/json/text()")[0])
        if jsonrib4:
            for router, prefixes in jsonrib4.items():
                # Duplicate routes are objects in the json array of each prefix
                for prefix, routes in prefixes.items():
                    value += len(routes)
    return (key, value, comment)


def ipv6_forwarding_table_size(mode, state, config, output):
    """IPv6 forwarding table size"""
    key = 'IPv6 forwarding table size'
    requirements = ['show routing resource',
                    '<show><advanced-routing><route><afi>ipv6</afi></route></advanced-routing></show>']
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements)
    try:
        value = int(output[requirements[0]].xpath("/response/result/entry/All-IPv6/total/text()")[0])
    except IndexError:
        value = 0
    if len(output[requirements[1]]):
        jsonrib6 = json.loads(output[requirements[1]].xpath("/response/result/json/text()")[0])
        if jsonrib6:
            for router, prefixes in jsonrib6.items():
                # Duplicate routes are objects in the json array of each prefix
                for prefix, routes in prefixes.items():
                    value += len(routes)
    return (key, value, comment)


def system_total_forwarding_table_size(mode, state, config, output):
    """System total forwarding table size"""
    key = 'System total forwarding table size'
    requirements = ['show routing resource',
                    '<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>',
                    '<show><advanced-routing><route><afi>ipv6</afi></route></advanced-routing></show>']
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements)
    try:
        value = int(output[requirements[0]].xpath("/response/result/entry/All-Routes/total/text()")[0])
    except IndexError:
        value = 0
    if len(output[requirements[1]]):
        jsonrib4 = json.loads(output[requirements[1]].xpath("/response/result/json/text()")[0])
        if jsonrib4:
            for router, prefixes in jsonrib4.items():
                # Duplicate routes are objects in the json array of each prefix
                for prefix, routes in prefixes.items():
                    value += len(routes)
    if len(output[requirements[2]]):
        jsonrib6 = json.loads(output[requirements[2]].xpath("/response/result/json/text()")[0])
        if jsonrib6:
            for router, prefixes in jsonrib6.items():
                # Duplicate routes are objects in the json array of each prefix
                for prefix, routes in prefixes.items():
                    value += len(routes)
    return (key, value, comment)


def max_route_maps_per_virtual_router(mode, state, config, output):
    """Max route maps per virtual router"""
    key = 'Max route maps per virtual router'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry/protocol/redist-profile/entry')) + \
            len(config.xpath('//config/devices/entry/network/virtual-router/entry/protocol/redist-profile-ipv6/entry'))
    return (key, value, comment)


def max_routing_peers_protocol_dependent(mode, state, config, output):
    """Max routing peers (protocol dependent)"""
    key = 'Max routing peers (protocol dependent)'
    requirements = ['show routing protocol bgp peer',
                    'show routing protocol ospf neighbor',
                    'show routing protocol ospfv3 neighbor',
                    'show routing protocol rip peer',
                    'show routing multicast pim neighbor',
                    'show advanced-routing bgp peer status',
                    'show advanced-routing ospf neighbor',
                    'show advanced-routing ospfv3 neighbor',
                    'show advanced-routing rip peer',
                    'show advanced-routing multicast pim neighbor']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([len(output[cmd].xpath("/response/result/entry")) for cmd in requirements if len(output[cmd])])
    return (key, value, comment)


def static_entries__dns_proxy(mode, state, config, output):
    """Static entries - DNS proxy"""
    key = 'Static entries - DNS proxy'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/dns-proxy/entry/static-entries/entry'))
    return (key, value, comment)


def bidirectional_forwarding_detection_bfd_sessions(mode, state, config, output):
    """Bidirectional Forwarding Detection (BFD) Sessions"""
    key = 'Bidirectional Forwarding Detection (BFD) Sessions'
    requirements = ['show routing bfd summary', 'show advanced-routing bfd summary']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([len(output[cmd].xpath("/response/result/entry")) for cmd in requirements if len(output[cmd])])
    return (key, value, comment)


def arp_table_size_per_device(mode, state, config, output):
    """ARP table size per device"""
    key = 'ARP table size per device'
    requirements = ["<show><arp><entry name='all'/></arp></show>"]
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def ipv6_neighbor_table_size(mode, state, config, output):
    """IPv6 neighbor table size"""
    key = 'IPv6 neighbor table size'
    requirements = ['show neighbor interface']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def mac_table_size_per_device(mode, state, config, output):
    """MAC table size per device"""
    key = 'MAC table size per device'
    requirements = ['show mac "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def max_arp_entries_per_broadcast_domain(mode, state, config, output):
    """Max ARP entries per broadcast domain"""
    key = 'Max ARP entries per broadcast domain'
    requirements = ["<show><arp><entry name='all'/></arp></show>"]
    if mode == '__get_requirements__':
        return (key, requirements)
    arps = output[requirements[0]].xpath("/response/result/entries/entry/interface/text()")
    value = max(arps.count(x) for x in set(arps)) if arps else 0
    return (key, value, comment)


def max_mac_entries_per_broadcast_domain(mode, state, config, output):
    """Max MAC entries per broadcast domain"""
    key = 'Max MAC entries per broadcast domain'
    requirements = ['show mac "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    macs = output[requirements[0]].xpath("/response/result/entries/entry/interface/text()")
    value = max(macs.count(x) for x in set(macs)) if macs else 0
    return (key, value, comment)


def total_nat_rule_capacity(mode, state, config, output):
    """Total NAT rule capacity"""
    key = 'Total NAT rule capacity'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/nat/rules/entry'))
    return (key, value, comment)


def max_nat_rules_static(mode, state, config, output):
    """Max NAT rules (static)"""
    key = 'Max NAT rules (static)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/nat/rules/entry[source-translation or destination-translation][static-ip or translated-address]'))
    return (key, value, comment)


def max_nat_rules_dip(mode, state, config, output):
    """Max NAT rules (DIP)"""
    key = 'Max NAT rules (DIP)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/nat/rules/entry/source-translation/dynamic-ip'))
    return (key, value, comment)


def max_nat_rules_dipp(mode, state, config, output):
    """Max NAT rules (DIPP)"""
    key = 'Max NAT rules (DIPP)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/nat/rules/entry[source-translation or dynamic-destination-translation][dynamic-ip-and-port or persistent-dynamic-ip-and-port or translated-address]')) + \
            len(config.xpath('//rulebase/nat/rules/entry/source-translation/dynamic-ip/fallback'))  # Do these count?
    return (key, value, comment)


def max_translated_ips_dip(mode, state, config, output):
    """Max translated IPs (DIP)"""
    key = 'Max translated IPs (DIP)'
    requirements = ['show running ippool']
    if mode == '__get_requirements__':
        return (key, requirements)
    text = output[requirements[0]].xpath('/response/result/text()')[0]
    lines = text.split('\n')
    data_types = lines[1].split()
    indexes = {}
    for data in data_types:
        indexes[data] = [lines[1].find(data)]  # Start position
        length = 0
        for char in lines[2][indexes[data][0]:]:
            if char != '-':
                break
            length += 1
        indexes[data].append(indexes[data][0] + length)  # End position
    # We need the list of long rule names since they can offset the entire table columns that's output from API
    nat_rule_names = [x for x in config.xpath('//rulebase/nat/rules/entry/@name') if len(x) > indexes['Rule'][1]]
    rules = []
    for line in lines[3:]:
        if line:
            trimmed_line = line
            # For multivsys, header is repeated for each vsys. Skip.
            if 'Dynamic IP' not in line:
                continue
            # Find the full rule name from config file so we can trim it in the cmd output if too long
            possible_names = []
            for rule_name in nat_rule_names:
                if trimmed_line.startswith(rule_name):
                    possible_names.append(rule_name)
            # Get longest match
            rule_name = max(possible_names, key=len) if possible_names else ''
            # Trim to same length as the "--------" header so it doesn't offset anything
            trimmed_line = trimmed_line.replace(rule_name, rule_name[0:indexes['Rule'][1]])
            rule = {}
            for data in data_types:
                rule[data] = trimmed_line[indexes[data][0]:indexes[data][1]].strip()
            rules.append(rule)
    addresses_dict = {}
    for a in rules:
        addresses_dict[a['Type']] = 0
    for di in rules:
        addresses = int(di['Available'])
        addresses_dict[di['Type']] += addresses
    try:
        value = addresses_dict['Dynamic IP']
    except KeyError:
        value = 0
    return (key, value, comment)


def max_translated_ips_dipp(mode, state, config, output):
    """Max translated IPs (DIPP)"""
    key = 'Max translated IPs (DIPP)'
    requirements = ['show running ippool']
    if mode == '__get_requirements__':
        return (key, requirements)
    text = output[requirements[0]].xpath('/response/result/text()')[0]
    lines = text.split('\n')
    data_types = lines[1].split()
    indexes = {}
    for data in data_types:
        indexes[data] = [lines[1].find(data)]  # Start position
        length = 0
        for char in lines[2][indexes[data][0]:]:
            if char != '-':
                break
            length += 1
        indexes[data].append(indexes[data][0] + length)  # End position
    # We need the list of long rule names since they can offset the entire table columns that's output from API
    nat_rule_names = [x for x in config.xpath('//rulebase/nat/rules/entry/@name') if len(x) > indexes['Rule'][1]]
    rules = []
    for line in lines[3:]:
        if line:
            trimmed_line = line
            # For multivsys, header is repeated for each vsys. Skip.
            if 'Dynamic IP/Port' not in line:
                continue
            # Find the full rule name from config file so we can trim it in the cmd output if too long
            possible_names = []
            for rule_name in nat_rule_names:
                if trimmed_line.startswith(rule_name):
                    possible_names.append(rule_name)
            # Get longest match
            rule_name = max(possible_names, key=len) if possible_names else ''
            # Trim to same length as the "--------" header so it doesn't offset anything
            trimmed_line = trimmed_line.replace(rule_name, rule_name[0:indexes['Rule'][1]])
            rule = {}
            for data in data_types:
                rule[data] = trimmed_line[indexes[data][0]:indexes[data][1]].strip()
            rules.append(rule)
    addresses_dict = {}
    for a in rules:
        addresses_dict[a['Type']] = 0
    for di in rules:
        addresses = int(di['Available']) / int(di['Ratio']) / 64512  # Available source ports per IP
        addresses_dict[di['Type']] += addresses
    try:
        value = round(addresses_dict['Dynamic IP/Port'])
    except KeyError:
        value = 0
    comment = 'Sum of the "Available" ports from "show running ippool" divided by 64512 * the oversubscription ratio'
    return (key, value, comment)


def default_dipp_pool_oversubscription(mode, state, config, output):
    """Default DIPP pool oversubscription"""
    key = 'Default DIPP pool oversubscription'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = '__from_model__'
    oversubscr = config.xpath('//config/devices/entry/deviceconfig/setting/nat/dipp-oversub/text()')
    if oversubscr:
        value = int(oversubscr[0].replace('x', ''), 0)
    else:
        for line in state.split('\n'):
            if 'cfg.nat.max-range-per-ip:' in line and 'peer' not in line:
                value = int(line.split()[1], 0)
                break
    return (key, value, comment)


def dhcp_servers(mode, state, config, output):
    """DHCP servers"""
    key = 'DHCP servers'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/dhcp/interface/entry/server'))
    return (key, value, comment)


def dhcp_relays(mode, state, config, output):
    """DHCP relays"""
    key = 'DHCP relays'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/dhcp/interface/entry/relay'))
    return (key, value, comment)


def max_number_of_assigned_addresses(mode, state, config, output):
    """Max number of assigned addresses"""
    key = 'Max number of assigned addresses'
    requirements = ['show dhcp server lease interface "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = sum([int(x) for x in output[requirements[0]].xpath('/response/result/interface/@allocated')])
    return (key, value, comment)


def devices_supported(mode, state, config, output):
    """Devices supported"""
    key = 'Devices supported'
    requirements = ['show high-availability cluster state', 'show high-availability state']
    if mode == '__get_requirements__':
        return (key, requirements)
    ha_enabled = output[requirements[1]].xpath('/response/result/enabled/text()')
    value = 2 if ha_enabled == 'yes' else 1
    cluster_members = output[requirements[0]].xpath('/response/result/cluster-state/local-information/members-count/text()')
    cluster_members = int(cluster_members) if cluster_members else 0
    value = max(value, cluster_members) if cluster_members else value
    return (key, value, comment)


def max_virtual_addresses(mode, state, config, output):
    """Max virtual addresses"""
    key = 'Max virtual addresses'
    requirements = ['show high-availability virtual-address']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = output[requirements[0]].xpath('/response/result/group/virtual-address/number-of-addresses/text()')
    value = int(value[0]) if value else 0
    return (key, value, comment)


def number_of_qos_policies(mode, state, config, output):
    """Number of QoS policies"""
    key = 'Number of QoS policies'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/qos/rules/entry'))
    return (key, value, comment)


def physical_interfaces_supporting_qos(mode, state, config, output):
    """Physical interfaces supporting QoS"""
    key = 'Physical interfaces supporting QoS'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/qos/interface/entry'))
    return (key, value, comment)


def clear_text_nodes_per_physical_interface(mode, state, config, output):
    """Clear text nodes per physical interface"""
    key = 'Clear text nodes per physical interface'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/qos/interface/entry/regular-traffic/groups/entry/members/entry'))
    return (key, value, comment)


def dscp_marking_by_policy(mode, state, config, output):
    """DSCP marking by policy"""
    key = 'DSCP marking by policy'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//rulebase/security/rules/entry/qos/marking'))
    return (key, value, comment)


def subinterfaces_supported(mode, state, config, output):
    """Subinterfaces supported"""
    key = 'Subinterfaces supported'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/interface/ethernet/entry/layer3/units/entry/tag'))
    return (key, value, comment)


def max_ike_peers(mode, state, config, output):
    """Max IKE Peers"""
    key = 'Max IKE Peers'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/ike/gateway/entry'))
    return (key, value, comment)


def site_to_site_with_proxy_id(mode, state, config, output):
    """Site to site (with proxy id)"""
    key = 'Site to site (with proxy id)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/tunnel/ipsec/entry/auto-key/proxy-id/entry'))
    return (key, value, comment)


def sd_wan_ipsec_tunnels(mode, state, config, output):
    """SD-WAN IPSec tunnels"""
    key = 'SD-WAN IPSec tunnels'
    requirements = ['show sdwan connection "all"']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(set([x for x in output[requirements[0]].xpath('/response/result/entry/vifs/entry/members/entry/inner-if/text()') if x.startswith('tunnel')]))
    return (key, value, comment)


def max_tunnels_ssl_ipsec_and_ike_with_xauth(mode, state, config, output):
    """Max tunnels (SSL, IPSec, and IKE with XAUTH)"""
    key = 'Max tunnels (SSL, IPSec, and IKE with XAUTH)'
    requirements = ['show global-protect-gateway statistics']
    if mode == '__get_requirements__':
        return (key, requirements)
    comment = 'TotalPreviousUsers from command "show global-protect-gateway statistics"'
    value = int(output[requirements[0]].xpath('/response/result/TotalPreviousUsers/text()')[0])
    return (key, value, comment)


def max_ssl_tunnels(mode, state, config, output):
    """Max SSL tunnels"""
    key = 'Max SSL tunnels'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    comment = 'No equivalent command of "show global-protect-gateway statistics" is available for the Portal. Value taken from "Max Users" set in Clientless VPN Config, if present'
    value = '__not_implemented__'
    enabled = config.xpath('//global-protect/global-protect-portal/entry/clientless-vpn')
    if not enabled:
        value = 0
    max_users = 0
    for entry in config.xpath('//global-protect/global-protect-portal/entry/clientless-vpn/max-user/text()'):
        max_users += int(entry)
    if max_users > 0:
        value = max_users
    return (key, value, comment)


def replication_egress_interfaces(mode, state, config, output):
    """Replication (egress interfaces)"""
    key = 'Replication (egress interfaces)'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry/multicast/interface-group/entry/interface/member')) + \
            len(config.xpath('//config/devices/entry/network/logical-router/entry/vrf/entry/multicast/*/interface/entry'))
    comment = 'Max theoretical number based on interfaces with PIM or IGMP enabled'
    return (key, value, comment)


def routes(mode, state, config, output):
    """Routes"""
    key = 'Routes'
    requirements = []
    virtual_routers = config.xpath('//config/devices/entry/network/virtual-router/entry/@name')
    logical_routers = config.xpath('//config/devices/entry/network/logical-router/entry/@name')
    for vr in virtual_routers:
        requirements.append(f'<show><routing><multicast><fib><virtual-router>{vr}</virtual-router></fib></multicast></routing></show>')
    for lr in logical_routers:
        requirements.append(f'<show><advanced-routing><multicast><fib><logical-router>{lr}</logical-router></fib></multicast></advanced-routing></show>')
    if mode == '__get_requirements__':
        return (key, requirements)
    value = 0
    for requirement in requirements:
        out = output[requirement]
        if len(out):
            value += len(out.xpath('/response/result/entry'))
    comment = 'Multicast, "show routing multicast fib" check egress interfaces for each vr/lr'
    return (key, value, comment)


def end_of_sale(mode, state, config, output):
    """End-of-sale"""
    key = 'End-of-sale'
    requirements = ['']
    if mode == '__get_requirements__':
        return (key, requirements)
    value = '__from_model__'
    return (key, value, comment)