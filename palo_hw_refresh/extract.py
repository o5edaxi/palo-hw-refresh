"""All these functions get called automatically by main with func('___get_requirements___') to find out what API call
outputs they need. The function name is lower() of the row name from the Palo Alto website, but isn't used anywhere
else. main() provides the config and "show system state" right upfront so the function is able to use it to construct
its requirements, such as adding the vsys name in the commands it needs"""
import re
import logging
import json
from datetime import datetime
from lxml import etree

"""
Template:

def security_rule_schedules(mode, state, config, output, output_pra):
    \"""Security rule schedules\"""
    key = 'Security rule schedules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value =  # IMPLEMENT YOUR LOGIC HERE. "state" is 'show system state' as a string, "config" is the merged config XML
    # as an lxml etree, "output" is the dictionary with the xml output of the commands you requested in "requirements"
    # which you can provide either as text (it will try to xmlize them) or xml. Return "__from_model__" to copy the
    # firewall model's datasheet value. requirements_pra commands will be run on the Panoramas if available.
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
end_time = datetime.now().strftime('%Y/%m/%d %H:%M:%S')

def app_id_firewall_throughput(mode, state, config, output, output_pra):
    """App-ID firewall throughput"""
    # This and the other throughput/session checks cannot be performed without at least several weeks of
    # SNMP/Netflow/gNMI statistics from a proper monitoring solution, preferably including data from the switches
    # themselves. These metrics are also insufficient by themselves to evaluate firewall dataplane load, as a proper
    # analysis should include CPU usage, pool usage, as well as every kind of hardware and software buffer,
    # packet descriptor, and packet inspection queues. Throughput (for the worst case, i.e. not distinguishing
    # between App-ID/TP/IPSEC), port bitrate, connections, and cps, can also be somewhat approximated by looking at
    # Panorama device monitoring data, which has decent retention (default of 90 days as of April 2025) and a resolution
    # of 10 minutes. This is implemented. SCM/AIOps can also provide some of this data, but it is not exposed by its
    # API. The TSF and dp-monitor.log contain detailed metrics, but these only go back a few days.
    key = 'App-ID firewall throughput'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "throughput" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    throughputs = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        throughputs.append(int(datapoint.xpath('./throughput/text()')[0]))
    comment = (f'Maximum value of data throughput taken from Panorama device monitoring data, {len(timestamps)} datapoints '
               f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
               f'WARNING: this data refers to generic throughput and is not '
               f'sufficient to properly evaluate dataplane load.')
    value = max(throughputs) * 1000  # Panorama sends Kbps
    return (key, value, comment)


def threat_prevention_throughput(mode, state, config, output, output_pra):
    """Threat prevention throughput"""
    key = 'Threat prevention throughput'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "throughput" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    throughputs = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        throughputs.append(int(datapoint.xpath('./throughput/text()')[0]))
    comment = (
        f'Maximum value of data throughput taken from Panorama device monitoring data, {len(timestamps)} datapoints '
        f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
        f'WARNING: this data refers to generic throughput and is not '
        f'sufficient to properly evaluate dataplane load.')
    value = max(throughputs) * 1000  # Panorama sends Kbps
    return (key, value, comment)


def ipsec_vpn_throughput(mode, state, config, output, output_pra):
    """IPSec VPN throughput"""
    key = 'IPSec VPN throughput'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "throughput" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    throughputs = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        throughputs.append(int(datapoint.xpath('./throughput/text()')[0]))
    comment = (
        f'Maximum value of data throughput taken from Panorama device monitoring data, {len(timestamps)} datapoints '
        f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
        f'WARNING: this data refers to generic throughput and is not '
        f'sufficient to properly evaluate dataplane load.')
    value = max(throughputs) * 1000  # Panorama sends Kbps
    return (key, value, comment)


def connections_per_second(mode, state, config, output, output_pra):
    """Connections per second"""
    key = 'Connections per second'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "cps" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    cps = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        cps.append(int(datapoint.xpath('./cps/text()')[0]))
    comment = (
        f'Maximum value of connections per second taken from Panorama device monitoring data, {len(timestamps)} datapoints '
        f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
        f'WARNING: this data refers to generic connection rate and is not '
        f'sufficient to properly evaluate dataplane load.')
    value = max(cps)
    return (key, value, comment)


def max_sessions_ipv4_or_ipv6(mode, state, config, output, output_pra):
    """Max sessions (IPv4 or IPv6)"""
    key = 'Max sessions (IPv4 or IPv6)'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "sessions" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    sessions = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        sessions.append(int(datapoint.xpath('./sessions/text()')[0]))
    comment = (
        f'Maximum value of active sessions taken from Panorama device monitoring data, {len(timestamps)} datapoints '
        f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
        f'WARNING: this data refers to generic session table usage and is not '
        f'sufficient to properly evaluate dataplane load.')
    value = max(sessions)
    return (key, value, comment)


def security_rules(mode, state, config, output, output_pra):
    """Security rules"""
    key = 'Security rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/security/rules/entry'))
    return (key, value, comment)


def security_rule_schedules(mode, state, config, output, output_pra):
    """Security rule schedules"""
    key = 'Security rule schedules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//schedule/entry'))
    return (key, value, comment)


def nat_rules(mode, state, config, output, output_pra):
    """NAT rules"""
    key = 'NAT rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/nat/rules/entry'))
    return (key, value, comment)


def decryption_rules(mode, state, config, output, output_pra):
    """Decryption rules"""
    key = 'Decryption rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/decryption/rules/entry'))
    return (key, value, comment)


def app_override_rules(mode, state, config, output, output_pra):
    """App override rules"""
    key = 'App override rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/application-override/rules/entry'))
    return (key, value, comment)


def tunnel_content_inspection_rules(mode, state, config, output, output_pra):
    """Tunnel content inspection rules"""
    key = 'Tunnel content inspection rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/tunnel-inspect/rules/entry'))
    return (key, value, comment)


def sd_wan_rules(mode, state, config, output, output_pra):
    """SD-WAN rules"""
    key = 'SD-WAN rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/sdwan/rules/entry'))
    return (key, value, comment)


def policy_based_forwarding_rules(mode, state, config, output, output_pra):
    """Policy based forwarding rules"""
    key = 'Policy based forwarding rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/pbf/rules/entry'))
    return (key, value, comment)


def captive_portal_rules(mode, state, config, output, output_pra):
    """Captive portal rules"""
    key = 'Captive portal rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/authentication/rules/entry'))
    return (key, value, comment)


def dos_protection_rules(mode, state, config, output, output_pra):
    """DoS protection rules"""
    key = 'DoS protection rules'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/dos/rules/entry'))
    return (key, value, comment)


def max_security_zones(mode, state, config, output, output_pra):
    """Max security zones"""
    key = 'Max security zones'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//zone/entry'))
    return (key, value, comment)


def address_objects(mode, state, config, output, output_pra):
    """Address objects"""
    key = 'Address objects'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//address/entry'))
    return (key, value, comment)


def address_groups(mode, state, config, output, output_pra):
    """Address groups"""
    key = 'Address groups'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//address-group/entry'))
    return (key, value, comment)


def members_per_address_group(mode, state, config, output, output_pra):
    """Members per address group"""
    key = 'Members per address group'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def service_objects(mode, state, config, output, output_pra):
    """Service objects"""
    key = 'Service objects'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//service/entry'))
    return (key, value, comment)


def service_groups(mode, state, config, output, output_pra):
    """Service groups"""
    key = 'Service groups'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//service-group/entry'))
    return (key, value, comment)


def members_per_service_group(mode, state, config, output, output_pra):
    """Members per service group"""
    key = 'Members per service group'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def fqdn_address_objects(mode, state, config, output, output_pra):
    """FQDN address objects"""
    key = 'FQDN address objects'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//address/entry/fqdn'))
    return (key, value, comment)


def max_dag_ip_addresses(mode, state, config, output, output_pra):
    """Max DAG IP addresses"""
    key = 'Max DAG IP addresses'
    requirements = ['show object registered-ip all option "count"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    count = output['show object registered-ip all option "count"'].xpath('//count/text()')
    value = float(count[0] if count else 0)
    return (key, value, comment)


def tags_per_ip_address(mode, state, config, output, output_pra):
    """Tags per IP address"""
    key = 'Tags per IP address'
    requirements = ["<show><object><registered-ip><tag><entry name='all'/></tag></registered-ip></object></show>"]
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    tags = [len(entry.xpath('.//member')) for entry in output[requirements[0]].xpath('//entry')]
    value = max(tags) if tags else 0
    return (key, value, comment)


def security_profiles(mode, state, config, output, output_pra):
    """Security profiles"""
    key = 'Security profiles'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//profiles/*/entry'))
    return (key, value, comment)


def custom_app_id_signatures(mode, state, config, output, output_pra):
    """Custom App-ID signatures"""
    key = 'Custom App-ID signatures'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//application/entry'))
    return (key, value, comment)


def shared_custom_app_ids(mode, state, config, output, output_pra):
    """Shared custom App-IDs"""
    key = 'Shared custom App-IDs'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/shared/application/entry'))
    return (key, value, comment)


def custom_app_ids_virtual_system_specific(mode, state, config, output, output_pra):
    """Custom App-IDs (virtual system specific)"""
    key = 'Custom App-IDs (virtual system specific)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/vsys/entry/application/entry'))
    return (key, value, comment)


def ip_user_mappings_management_plane(mode, state, config, output, output_pra):
    """IP-User mappings (management plane)"""
    key = 'IP-User mappings (management plane)'
    requirements = ['show user ip-user-mapping-mp all option "count"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = float(output[requirements[0]].xpath('//count/text()')[0])
    return (key, value, comment)


def ip_user_mappings_data_plane(mode, state, config, output, output_pra):
    """IP-User mappings (data plane)"""
    key = 'IP-User mappings (data plane)'
    requirements = ['show user ip-user-mapping all option "count"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = float(output[requirements[0]].xpath('//count/text()')[0])
    return (key, value, comment)


def active_and_unique_groups_used_in_policy(mode, state, config, output, output_pra):
    """Active and unique groups used in policy"""
    key = 'Active and unique groups used in policy'
    requirements = ['show user group list']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    match = re.search(r'Total: (\d+)', output[requirements[0]])
    value = match.group(1)
    return (key, value, comment)


def number_of_user_id_agents(mode, state, config, output, output_pra):
    """Number of User-ID agents"""
    key = 'Number of User-ID agents'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//redistribution-agent/entry'))
    return (key, value, comment)


def monitored_servers_for_user_id(mode, state, config, output, output_pra):
    """Monitored servers for User-ID"""
    key = 'Monitored servers for User-ID'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//user-id-collector/server-monitor/entry'))
    return (key, value, comment)


def terminal_server_agents(mode, state, config, output, output_pra):
    """Terminal server agents"""
    key = 'Terminal server agents'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//ts-agent/entry'))
    return (key, value, comment)


def tags_per_user(mode, state, config, output, output_pra):
    """Tags per User"""
    key = 'Tags per User'
    requirements = ["<show><object><registered-user><tag><entry name='all'/></tag></registered-user></object></show>"]
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    tags = [len(entry.xpath('.//member')) for entry in output[requirements[0]].xpath('//entry')]
    value = max(tags) if tags else 0
    return (key, value, comment)


def max_ssl_inbound_certificates(mode, state, config, output, output_pra):
    """Max SSL inbound certificates"""
    key = 'Max SSL inbound certificates'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/decryption/rules/entry/type/ssl-inbound-inspection/certificates/member'))
    return (key, value, comment)


def ssl_certificate_cache_forward_proxy(mode, state, config, output, output_pra):
    """SSL certificate cache (forward proxy)"""
    key = 'SSL certificate cache (forward proxy)'
    requirements = ['show system setting ssl-decrypt certificate-cache']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    match = re.search(r'Cached (\d+) certificates', output[requirements[0]].xpath('//member/text()')[0])
    value = float(match.group(1))
    return (key, value, comment)


def max_concurrent_decryption_sessions(mode, state, config, output, output_pra):
    """Max concurrent decryption sessions"""
    key = 'Max concurrent decryption sessions'
    requirements = ['show system info']
    for line in state.split('\n'):
        if re.search(r"^cfg\.platform\.serial\: ", line):
            match = re.search(r"^cfg\.platform\.serial\: (\w+)", line)
            if match:
                serial = match.group(1)
    requirements_pra = [f'show monitoring info trend metric "decrypted-sessions" device "{serial}" from-time "1970/01/01 00:00:00" to-time "{end_time}"']
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output_pra:
        return (key, '__not_found__', 'Panorama not available')
    datapoints = []
    for panorama_ip in output_pra:
        datapoints += output_pra[panorama_ip][requirements_pra[0]].xpath('/response/result/trend/entry')
    timestamps = []
    decrypted_sessions = []
    for datapoint in datapoints:
        timestamps.append(datetime.strptime(datapoint.xpath('./timestamp/text()')[0], '%Y/%m/%d %H:%M:%S'))
        decrypted_sessions.append(int(datapoint.xpath('./decrypted-sessions/text()')[0]))
    comment = (
        f'Maximum value of active decryption sessions taken from Panorama device monitoring data, {len(timestamps)} datapoints '
        f'available starting {min(timestamps).strftime("%Y/%m/%d %H:%M:%S")} and ending {max(timestamps).strftime("%Y/%m/%d %H:%M:%S")}. '
        f'WARNING: this data refers to generic session usage and is not '
        f'sufficient to properly evaluate dataplane load.')
    value = max(decrypted_sessions)
    return (key, value, comment)


def decryption_port_mirror(mode, state, config, output, output_pra):
    """Decryption Port Mirror"""
    key = 'Decryption Port Mirror'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/interface/ethernet/entry/decrypt-mirror'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def network_packet_broker(mode, state, config, output, output_pra):
    """Network Packet Broker"""
    key = 'Network Packet Broker'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/network-packet-broker/rules/entry'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def hsm_supported(mode, state, config, output, output_pra):
    """HSM Supported"""
    key = 'HSM Supported'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/deviceconfig/system/hsm-settings'))
    value = 'Yes' if value else 'No'
    return (key, value, comment)


def total_entries_for_allow_list_block_list_and_custom_categories(mode, state, config, output, output_pra):
    """Total entries for allow list, block list and custom categories"""
    key = 'Total entries for allow list, block list and custom categories'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//profiles/custom-url-category/entry/list/member'))
    return (key, value, comment)


def max_custom_categories(mode, state, config, output, output_pra):
    """Max custom categories"""
    key = 'Max custom categories'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//profiles/custom-url-category/entry'))
    return (key, value, comment)


def max_custom_categories_virtual_system_specific(mode, state, config, output, output_pra):
    """Max custom categories (virtual system specific)"""
    key = 'Max custom categories (virtual system specific)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/vsys/entry/profiles/custom-url-category'))
    return (key, value, comment)


def dataplane_cache_size_for_url_filtering(mode, state, config, output, output_pra):
    """Dataplane cache size for URL filtering"""
    key = 'Dataplane cache size for URL filtering'
    requirements = ['show running url-cache statistics']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = float(0)
    for match in re.findall(r'number of urls\|\s+(\d+)', output[requirements[0]].xpath('//response/result/member/text()')[0]):
        value += float(match)
    return (key, value, comment)


def management_plane_dynamic_cache_size(mode, state, config, output, output_pra):
    """Management plane dynamic cache size"""
    key = 'Management plane dynamic cache size'
    requirements = ['show system setting url-cache statistics']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = float(0)
    for match in re.findall(r'number of urls\|\s+(\d+)',
                            output[requirements[0]].xpath('//response/result/member/text()')[0]):
        value += float(match)
    return (key, value, comment)


def max_number_of_custom_lists(mode, state, config, output, output_pra):
    """Max number of custom lists"""
    key = 'Max number of custom lists'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//external-list/entry'))
    return (key, value, comment)


def max_number_of_ips_per_system(mode, state, config, output, output_pra):
    """Max number of IPs per system
    This command requires write privileges"""
    key = 'Max number of IPs per system'
    requirements = ['request system external-list list-capacities']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//IP/running-cap/text()')[0])
    return (key, value, comment)


def max_number_of_dns_domains_per_system(mode, state, config, output, output_pra):
    """Max number of DNS Domains per system
    This command requires write privileges"""
    key = 'Max number of DNS Domains per system'
    requirements = ['request system external-list list-capacities']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//Domain/running-cap/text()')[0])
    return (key, value, comment)


def max_number_of_url_per_system(mode, state, config, output, output_pra):
    """Max number of URL per system
    This command requires write privileges"""
    key = 'Max number of URL per system'
    requirements = ['request system external-list list-capacities']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if output[requirements[0]] == '__unauthorized__':
        value = output[requirements[0]]
    else:
        value = float(output[requirements[0]].xpath('//URL/running-cap/text()')[0])
    return (key, value, comment)


def shortest_check_interval_min(mode, state, config, output, output_pra):
    """Shortest check interval (min)"""
    key = 'Shortest check interval (min)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def mgmt_out_of_band(mode, state, config, output, output_pra):
    """Mgmt - out-of-band"""
    key = 'Mgmt - out-of-band'
    requirements = ['show interface "management"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len([x for x in output[requirements[0]].xpath('/response/result/info/state/text()') if x == 'up'])
    return (key, value, comment)


def mgmt_10_100_1000_high_availability(mode, state, config, output, output_pra):
    """Mgmt - 10/100/1000 high availability"""
    key = 'Mgmt - 10/100/1000 high availability'
    requirements = ['show interface "hardware"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def mgmt_40gbps_high_availability(mode, state, config, output, output_pra):
    """Mgmt - 40Gbps high availability"""
    key = 'Mgmt - 40Gbps high availability'
    requirements = ['show interface "hardware"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    ifaces = output[requirements[0]].xpath("/response/result/hw/entry[(starts-with(name/text(), 'ha') or starts-with(name/text(), 'aux') or starts-with(name/text(), 'hsci')) and state/text() = 'up']")
    try:
        value = len([x for x in ifaces if int(x.xpath('speed/text()')[0]) == 40000])
    except ValueError:
        value='__unknown__'
    return (key, value, comment)


def mgmt_10gbps_high_availability(mode, state, config, output, output_pra):
    """Mgmt - 10Gbps high availability"""
    key = 'Mgmt - 10Gbps high availability'
    requirements = ['show interface "hardware"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    ifaces = output[requirements[0]].xpath("/response/result/hw/entry[(starts-with(name/text(), 'ha') or starts-with(name/text(), 'aux') or starts-with(name/text(), 'hsci')) and state/text() = 'up']")
    try:
        value = len([x for x in ifaces if int(x.xpath('speed/text()')[0]) == 10000])
    except ValueError:
        value='__unknown__'
    return (key, value, comment)


def traffic_10_100_1000(mode, state, config, output, output_pra):
    """Traffic - 10/100/1000"""
    key = 'Traffic - 10/100/1000'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_10m_100m_1g_25g_5g(mode, state, config, output, output_pra):
    """Traffic - 10M/100M/1G/2.5G/5G"""
    key = 'Traffic - 10M/100M/1G/2.5G/5G'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_100_1000_10000(mode, state, config, output, output_pra):
    """Traffic - 100/1000/10000"""
    key = 'Traffic - 100/1000/10000'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_1gbps_sfp(mode, state, config, output, output_pra):
    """Traffic - 1Gbps SFP"""
    key = 'Traffic - 1Gbps SFP'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_10gbps_sfp(mode, state, config, output, output_pra):
    """Traffic - 10Gbps SFP+"""
    key = 'Traffic - 10Gbps SFP+'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_25gbps_sfp28(mode, state, config, output, output_pra):
    """Traffic - 25Gbps SFP28"""
    key = 'Traffic - 25Gbps SFP28'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_40_100gbps_qsfp_qsfp28(mode, state, config, output, output_pra):
    """Traffic - 40/100Gbps QSFP+/QSFP28"""
    key = 'Traffic - 40/100Gbps QSFP+/QSFP28'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_100gbps_qsfp28(mode, state, config, output, output_pra):
    """Traffic - 100Gbps QSFP28"""
    key = 'Traffic - 100Gbps QSFP28'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def traffic_400gbps_qsfpdd(mode, state, config, output, output_pra):
    """Traffic - 400Gbps QSFP-DD"""
    key = 'Traffic - 400Gbps QSFP-DD'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def eight02_1q_tags_per_device(mode, state, config, output, output_pra):
    """802.1q tags per device"""
    key = '802.1q tags per device'
    requirements = ['show interface "logical"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(set(output[requirements[0]].xpath("/response/result/ifnet/entry/tag/text()")))
    return (key, value, comment)


def eight02_1q_tags_per_physical_interface(mode, state, config, output, output_pra):
    """802.1q tags per physical interface"""
    key = '802.1q tags per physical interface'
    requirements = ['show interface "logical"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = 0
    ifaces = output[requirements[0]].xpath("/response/result/ifnet/entry[starts-with(name/text(), 'ethernet')]/name/text()")
    ifaces = set([x.split('.')[0] for x in ifaces])
    for ifc in ifaces:
        ifc_subifs = len(output[requirements[0]].xpath(f"/response/result/ifnet/entry[starts-with(name/text(), '{ifc}')]/tag/text()"))
        if ifc_subifs > value:
            value = ifc_subifs
    return (key, value, comment)


def max_interfaces_logical_and_physical(mode, state, config, output, output_pra):
    """Max interfaces (logical and physical)"""
    key = 'Max interfaces (logical and physical)'
    requirements = ['show interface "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(output[requirements[0]].xpath("/response/result/ifnet/entry"))
    return (key, value, comment)


def maximum_aggregate_interfaces(mode, state, config, output, output_pra):
    """Maximum aggregate interfaces"""
    key = 'Maximum aggregate interfaces'
    requirements = ['show interface "logical"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    ifaces = output[requirements[0]].xpath(
        "/response/result/ifnet/entry[starts-with(name/text(), 'ae')]/name/text()")
    value = len(set([x.split('.')[0] for x in ifaces]))
    return (key, value, comment)


def maximum_sd_wan_virtual_interfaces(mode, state, config, output, output_pra):
    """Maximum SD-WAN virtual interfaces"""
    key = 'Maximum SD-WAN virtual interfaces'
    requirements = ['show interface "logical"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(output[requirements[0]].xpath("/response/result/ifnet/entry[starts-with(name/text(), 'sdwan')]"))
    return (key, value, comment)


def poe_enabled_interfaces(mode, state, config, output, output_pra):
    """PoE Enabled Interfaces"""
    key = 'PoE Enabled Interfaces'
    requirements = ['show poe detail']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/used-pwr/text()")
    ifaces = [int(float(x.split('/')[0])) for x in ifaces]
    value = len([x for x in ifaces if x > 0])
    return (key, value, comment)


def poe_interface_speed(mode, state, config, output, output_pra):
    """PoE Interface Speed"""
    key = 'PoE Interface Speed'
    requirements = ['show poe detail', 'show interface "hardware"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry[not(starts-with(used-pwr/text(), '0.0'))]/name/text()")
    speeds = []
    for iface in ifaces:
        speeds.append(int(output[requirements[1]].xpath(f'/response/hw/entry[name/text()="{iface}"]/speed/text()')))
    value = str(float(max(speeds)) / 1000).replace('.0', '') + 'G'
    return (key, value, comment)


def total_power_budget(mode, state, config, output, output_pra):
    """Total Power Budget"""
    key = 'Total Power Budget'
    requirements = ['show poe detail']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/alloc-pwr/text()")
    value = sum([int(float(x.split('/')[0]) + 0.9) for x in ifaces])  # Round the int up
    return (key, value, comment)


def max_power_per_single_port(mode, state, config, output, output_pra):
    """Max Power per single port"""
    key = 'Max Power per single port'
    requirements = ['show poe detail']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    if not output[requirements[0]]:  # PoE unsupported on model
        return (key, 'NA', comment)
    ifaces = output[requirements[0]].xpath("/response/result/poe/entry/alloc-pwr/text()")
    value = max([int(float(x.split('/')[0]) + 0.9) for x in ifaces])  # Round the int up
    return (key, value, comment)


def five_g(mode, state, config, output, output_pra):
    """5G"""
    key = '5G'
    requirements = ['show interface "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/interface/cellular/entry'))
    return (key, value, comment)


def virtual_routers(mode, state, config, output, output_pra):
    """Virtual routers"""
    key = 'Virtual routers'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry')) + \
            len(config.xpath('//config/devices/entry/network/logical-router/entry'))
    return (key, value, comment)


def virtual_wires(mode, state, config, output, output_pra):
    """Virtual wires"""
    key = 'Virtual wires'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/virtual-wire/entry'))
    return (key, value, comment)


def base_virtual_systems(mode, state, config, output, output_pra):
    """Base virtual systems"""
    key = 'Base virtual systems'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/vsys/entry'))
    return (key, value, comment)


def max_virtual_systems(mode, state, config, output, output_pra):
    """Max virtual systems"""
    key = 'Max virtual systems'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/vsys/entry'))
    return (key, value, comment)


def ipv4_forwarding_table_size(mode, state, config, output, output_pra):
    """IPv4 forwarding table size"""
    key = 'IPv4 forwarding table size'
    requirements = ['show routing resource', '<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>']
    requirements_pra = []
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def ipv6_forwarding_table_size(mode, state, config, output, output_pra):
    """IPv6 forwarding table size"""
    key = 'IPv6 forwarding table size'
    requirements = ['show routing resource',
                    '<show><advanced-routing><route><afi>ipv6</afi></route></advanced-routing></show>']
    requirements_pra = []
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def system_total_forwarding_table_size(mode, state, config, output, output_pra):
    """System total forwarding table size"""
    key = 'System total forwarding table size'
    requirements = ['show routing resource',
                    '<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>',
                    '<show><advanced-routing><route><afi>ipv6</afi></route></advanced-routing></show>']
    requirements_pra = []
    # "advanced-routing resource" is bugged via API 04/2025
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def max_route_maps_per_virtual_router(mode, state, config, output, output_pra):
    """Max route maps per virtual router"""
    key = 'Max route maps per virtual router'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry/protocol/redist-profile/entry')) + \
            len(config.xpath('//config/devices/entry/network/virtual-router/entry/protocol/redist-profile-ipv6/entry'))
    return (key, value, comment)


def max_routing_peers_protocol_dependent(mode, state, config, output, output_pra):
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
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([len(output[cmd].xpath("/response/result/entry")) for cmd in requirements if len(output[cmd])])
    return (key, value, comment)


def static_entries__dns_proxy(mode, state, config, output, output_pra):
    """Static entries - DNS proxy"""
    key = 'Static entries - DNS proxy'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/dns-proxy/entry/static-entries/entry'))
    return (key, value, comment)


def bidirectional_forwarding_detection_bfd_sessions(mode, state, config, output, output_pra):
    """Bidirectional Forwarding Detection (BFD) Sessions"""
    key = 'Bidirectional Forwarding Detection (BFD) Sessions'
    requirements = ['show routing bfd summary', 'show advanced-routing bfd summary']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([len(output[cmd].xpath("/response/result/entry")) for cmd in requirements if len(output[cmd])])
    return (key, value, comment)


def arp_table_size_per_device(mode, state, config, output, output_pra):
    """ARP table size per device"""
    key = 'ARP table size per device'
    requirements = ["<show><arp><entry name='all'/></arp></show>"]
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def ipv6_neighbor_table_size(mode, state, config, output, output_pra):
    """IPv6 neighbor table size"""
    key = 'IPv6 neighbor table size'
    requirements = ['show neighbor interface']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def mac_table_size_per_device(mode, state, config, output, output_pra):
    """MAC table size per device"""
    key = 'MAC table size per device'
    requirements = ['show mac "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([int(x) for x in output[requirements[0]].xpath("/response/result/total/text()")])
    return (key, value, comment)


def max_arp_entries_per_broadcast_domain(mode, state, config, output, output_pra):
    """Max ARP entries per broadcast domain"""
    key = 'Max ARP entries per broadcast domain'
    requirements = ["<show><arp><entry name='all'/></arp></show>"]
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    arps = output[requirements[0]].xpath("/response/result/entries/entry/interface/text()")
    value = max(arps.count(x) for x in set(arps)) if arps else 0
    return (key, value, comment)


def max_mac_entries_per_broadcast_domain(mode, state, config, output, output_pra):
    """Max MAC entries per broadcast domain"""
    key = 'Max MAC entries per broadcast domain'
    requirements = ['show mac "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    macs = output[requirements[0]].xpath("/response/result/entries/entry/interface/text()")
    value = max(macs.count(x) for x in set(macs)) if macs else 0
    return (key, value, comment)


def total_nat_rule_capacity(mode, state, config, output, output_pra):
    """Total NAT rule capacity"""
    key = 'Total NAT rule capacity'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/nat/rules/entry'))
    return (key, value, comment)


def max_nat_rules_static(mode, state, config, output, output_pra):
    """Max NAT rules (static)"""
    key = 'Max NAT rules (static)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/nat/rules/entry[source-translation or destination-translation][static-ip or translated-address]'))
    return (key, value, comment)


def max_nat_rules_dip(mode, state, config, output, output_pra):
    """Max NAT rules (DIP)"""
    key = 'Max NAT rules (DIP)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/nat/rules/entry/source-translation/dynamic-ip'))
    return (key, value, comment)


def max_nat_rules_dipp(mode, state, config, output, output_pra):
    """Max NAT rules (DIPP)"""
    key = 'Max NAT rules (DIPP)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/nat/rules/entry[source-translation or dynamic-destination-translation][dynamic-ip-and-port or persistent-dynamic-ip-and-port or translated-address]')) + \
            len(config.xpath('//rulebase/nat/rules/entry/source-translation/dynamic-ip/fallback'))  # Do these count?
    return (key, value, comment)


def max_translated_ips_dip(mode, state, config, output, output_pra):
    """Max translated IPs (DIP)"""
    key = 'Max translated IPs (DIP)'
    requirements = ['show running ippool']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def max_translated_ips_dipp(mode, state, config, output, output_pra):
    """Max translated IPs (DIPP)"""
    key = 'Max translated IPs (DIPP)'
    requirements = ['show running ippool']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def default_dipp_pool_oversubscription(mode, state, config, output, output_pra):
    """Default DIPP pool oversubscription"""
    key = 'Default DIPP pool oversubscription'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def dhcp_servers(mode, state, config, output, output_pra):
    """DHCP servers"""
    key = 'DHCP servers'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/dhcp/interface/entry/server'))
    return (key, value, comment)


def dhcp_relays(mode, state, config, output, output_pra):
    """DHCP relays"""
    key = 'DHCP relays'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/dhcp/interface/entry/relay'))
    return (key, value, comment)


def max_number_of_assigned_addresses(mode, state, config, output, output_pra):
    """Max number of assigned addresses"""
    key = 'Max number of assigned addresses'
    requirements = ['show dhcp server lease interface "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = sum([int(x) for x in output[requirements[0]].xpath('/response/result/interface/@allocated')])
    return (key, value, comment)


def devices_supported(mode, state, config, output, output_pra):
    """Devices supported"""
    key = 'Devices supported'
    requirements = ['show high-availability cluster state', 'show high-availability state']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    ha_enabled = output[requirements[1]].xpath('/response/result/enabled/text()')
    value = 2 if ha_enabled == 'yes' else 1
    cluster_members = output[requirements[0]].xpath('/response/result/cluster-state/local-information/members-count/text()')
    cluster_members = int(cluster_members) if cluster_members else 0
    value = max(value, cluster_members) if cluster_members else value
    return (key, value, comment)


def max_virtual_addresses(mode, state, config, output, output_pra):
    """Max virtual addresses"""
    key = 'Max virtual addresses'
    requirements = ['show high-availability virtual-address']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = output[requirements[0]].xpath('/response/result/group/virtual-address/number-of-addresses/text()')
    value = int(value[0]) if value else 0
    return (key, value, comment)


def number_of_qos_policies(mode, state, config, output, output_pra):
    """Number of QoS policies"""
    key = 'Number of QoS policies'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/qos/rules/entry'))
    return (key, value, comment)


def physical_interfaces_supporting_qos(mode, state, config, output, output_pra):
    """Physical interfaces supporting QoS"""
    key = 'Physical interfaces supporting QoS'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/qos/interface/entry'))
    return (key, value, comment)


def clear_text_nodes_per_physical_interface(mode, state, config, output, output_pra):
    """Clear text nodes per physical interface"""
    key = 'Clear text nodes per physical interface'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/qos/interface/entry/regular-traffic/groups/entry/members/entry'))
    return (key, value, comment)


def dscp_marking_by_policy(mode, state, config, output, output_pra):
    """DSCP marking by policy"""
    key = 'DSCP marking by policy'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//rulebase/security/rules/entry/qos/marking'))
    return (key, value, comment)


def subinterfaces_supported(mode, state, config, output, output_pra):
    """Subinterfaces supported"""
    key = 'Subinterfaces supported'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/interface/ethernet/entry/layer3/units/entry/tag'))
    return (key, value, comment)


def max_ike_peers(mode, state, config, output, output_pra):
    """Max IKE Peers"""
    key = 'Max IKE Peers'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/ike/gateway/entry'))
    return (key, value, comment)


def site_to_site_with_proxy_id(mode, state, config, output, output_pra):
    """Site to site (with proxy id)"""
    key = 'Site to site (with proxy id)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/tunnel/ipsec/entry/auto-key/proxy-id/entry'))
    return (key, value, comment)


def sd_wan_ipsec_tunnels(mode, state, config, output, output_pra):
    """SD-WAN IPSec tunnels"""
    key = 'SD-WAN IPSec tunnels'
    requirements = ['show sdwan connection "all"']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(set([x for x in output[requirements[0]].xpath('/response/result/entry/vifs/entry/members/entry/inner-if/text()') if x.startswith('tunnel')]))
    return (key, value, comment)


def max_tunnels_ssl_ipsec_and_ike_with_xauth(mode, state, config, output, output_pra):
    """Max tunnels (SSL, IPSec, and IKE with XAUTH)"""
    key = 'Max tunnels (SSL, IPSec, and IKE with XAUTH)'
    requirements = ['show global-protect-gateway statistics']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    comment = 'TotalPreviousUsers from command "show global-protect-gateway statistics"'
    value = int(output[requirements[0]].xpath('/response/result/TotalPreviousUsers/text()')[0])
    return (key, value, comment)


def max_ssl_tunnels(mode, state, config, output, output_pra):
    """Max SSL tunnels"""
    key = 'Max SSL tunnels'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
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


def replication_egress_interfaces(mode, state, config, output, output_pra):
    """Replication (egress interfaces)"""
    key = 'Replication (egress interfaces)'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = len(config.xpath('//config/devices/entry/network/virtual-router/entry/multicast/interface-group/entry/interface/member')) + \
            len(config.xpath('//config/devices/entry/network/logical-router/entry/vrf/entry/multicast/*/interface/entry'))
    comment = 'Max theoretical number based on interfaces with PIM or IGMP enabled'
    return (key, value, comment)


def routes(mode, state, config, output, output_pra):
    """Routes"""
    key = 'Routes'
    requirements = []
    requirements_pra = []
    virtual_routers = config.xpath('//config/devices/entry/network/virtual-router/entry/@name')
    logical_routers = config.xpath('//config/devices/entry/network/logical-router/entry/@name')
    for vr in virtual_routers:
        requirements.append(f'<show><routing><multicast><fib><virtual-router>{vr}</virtual-router></fib></multicast></routing></show>')
    for lr in logical_routers:
        requirements.append(f'<show><advanced-routing><multicast><fib><logical-router>{lr}</logical-router></fib></multicast></advanced-routing></show>')
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = 0
    for requirement in requirements:
        out = output[requirement]
        if len(out):
            value += len(out.xpath('/response/result/entry'))
    comment = 'Multicast, "show routing multicast fib" check egress interfaces for each vr/lr'
    return (key, value, comment)


def end_of_sale(mode, state, config, output, output_pra):
    """End-of-sale"""
    key = 'End-of-sale'
    requirements = ['']
    requirements_pra = []
    if mode == '__get_requirements__':
        return (key, requirements, requirements_pra)
    value = '__from_model__'
    return (key, value, comment)
