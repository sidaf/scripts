""" Example...

from nessus import Scan, Host, Event

xml = open("vulnerability-analysis/nessus/example.nessus").read()
scan = Scan(xml)

print(f"title:  {scan.title()}")
print(f"policy: {scan.policy()}")

for host in scan.hosts():
    
    print(f"name:     {host.name()}")
    print(f"hostname: {host.hostname()}")
    print(f"address:  {host.address()}")
    
    for event in host.events():
        
        print(f"plugin_name: {event.plugin_name()}")
        print(f"port:        {event.port()}")
        print(f"severity:    {event.severity()}")
        print(f"plugin_id:   {event.plugin_id()}")
        print(f"output:      {event.output()}")
"""

from lxml import etree as ElementTree

class Event:
    
    def __init__(self, element):
        self.tree = ElementTree.ElementTree(element)
    
    def port(self):
        return self.tree.xpath('@port')[0], self.tree.xpath('@protocol')[0], self.tree.xpath('@svc_name')[0]
    
    def severity(self):
         return int(self.tree.xpath('@severity')[0])
    
    def informational(self):
        return True if self.severity() == 0 else False
    
    def low(self):
        return True if self.severity() == 1 else False
    
    def medium(self):
        return True if self.severity() == 2 else False
    
    def high(self):
        return True if self.severity() == 3 else False
    
    def critical(self):
        return True if self.severity() == 4 else False
    
    def plugin_id(self):
        return int(self.tree.xpath('@pluginID')[0])
    
    def plugin_name(self):
        result = self.tree.xpath('@pluginName')
        if len(result) > 0:
            return self.tree.xpath('@pluginName')[0]
        return None
    
    def plugin_family(self):
        return self.tree.xpath('@pluginFamily')[0]
    
    def plugin_type(self):
        return self.tree.xpath('plugin_type')[0].text
    
    def plugin_version(self):
        return self.tree.xpath('script_version')[0].text
    
    def synopsis(self):
        return self.tree.xpath('synopsis')[0].text
    
    def description(self):
        return self.tree.xpath('description')[0].text
    
    def solution(self):
        return self.tree.xpath('solution')[0].text
    
    def risk(self):
        return self.tree.xpath('risk_factor')[0].text
    
    def output(self):
        return self.tree.xpath('plugin_output')[0].text
    
    def references(self):
        result = self.tree.xpath('see_also')
        if len(result) > 0:
            return self.tree.xpath('see_also')[0].text.split('\n')
        return None

    def vuln_publication_date(self):
        result = self.tree.xpath('vuln_publication_date')
        if len(result) > 0:
            return self.tree.xpath('vuln_publication_date')[0].text
        return None
    
    def patch_publication_date(self):
        result = self.tree.xpath('patch_publication_date')
        if len(result) > 0:
            return self.tree.xpath('patch_publication_date')[0].text
        return None
    
    def cvss_base_score(self):
        result = self.tree.xpath('cvss_base_score')
        if len(result) > 0:
            return float(self.tree.xpath('cvss_base_score')[0].text)
        return None
    
    def cvss_temporal_score(self):
        result = self.tree.xpath('cvss_temporal_score')
        if len(result) > 0:
            return float(self.tree.xpath('cvss_temporal_score')[0].text)
        return None
    
    def cvss_vector(self):
        result = self.tree.xpath('cvss_vector')
        if len(result) > 0:
            return self.tree.xpath('cvss_vector')[0].text
        return None
    
    def cve(self):
        cves = []
        results = self.tree.xpath('cve')
        for item in results:
            cves.append(item.text)
        if len(cves) > 0:
            return cves
        return None
    
    def bid(self):
        bids = []
        results = self.tree.xpath('bid')
        for item in results:
            bids.append(item.text)
        if len(bids) > 0:
            return bids
        return None
    
    def xref(self):
        xrefs = []
        results = self.tree.xpath('xref')
        for item in results:
            xrefs.append(item.text)
        if len(xrefs) > 0:
            return xrefs
        return None
    
    def cpe(self):
        cpes = []
        results = self.tree.xpath('cpe')
        for item in results:
            cpes.append(item.text)
        if len(cpes) > 0:
            return cpes
        return None

    def exploitability_ease(self):
        result = self.tree.xpath('exploitability_ease')
        if len(result) > 0:
            return self.tree.xpath('exploitability_ease')[0].text
        return None
    
    def exploit_available(self):
        result = self.tree.xpath('exploit_available')
        if len(result) > 0:
            return self.tree.xpath('exploit_available')[0].text == "true"
        return False
    
    def exploit_framework_canvas(self):
        result = self.tree.xpath('exploit_framework_canvas')
        if len(result) > 0:
            return self.tree.xpath('exploit_framework_canvas')[0].text == "true"
        return False
    
    def canvas_package(self):
        result = self.tree.xpath('canvas_package')
        if len(result) > 0:
            return self.tree.xpath('canvas_package')[0].text
        return None
    
    def exploit_framework_metasploit(self):
        result = self.tree.xpath('exploit_framework_metasploit')
        if len(result) > 0:
            return self.tree.xpath('exploit_framework_metasploit')[0].text == "true"
        return False
    
    def metasploit_name(self):
        result = self.tree.xpath('metasploit_name')
        if len(result) > 0:
            return self.tree.xpath('metasploit_name')[0].text
        return None
    
    def exploit_framework_core(self):
        result = self.tree.xpath('exploit_framework_core')
        if len(result) > 0:
            return self.tree.xpath('exploit_framework_core')[0].text == "true"
        return False
    
    
class Host:
    
    def __init__(self, element):
        self.tree = ElementTree.ElementTree(element)
    
    def name(self):
        return self.tree.xpath('@name')[0]
    
    def hostname(self):
        result = self.tree.xpath('//tag[@name="host-fqdn"]')
        if len(result) > 0:
            return result[0].text
        return None
    
    def address(self):
        result = self.tree.xpath('//tag[@name="host-ip"]')
        if len(result) > 0:
            return result[0].text
        return None
    
    def rdns(self):
        result = self.tree.xpath('//tag[@name="host-rdns"]')
        if len(result) > 0:
            return result[0].text
        return None
    
    def netbios_name(self):
        result = self.tree.xpath('//tag[@name="netbios-name"]')
        if len(result) > 0:
            return result[0].text
        return None
    
    def mac_addr(self):
        result = self.tree.xpath('//tag[@name="mac-address"]')
        if len(result) > 0:
            return result[0].text
        return None
    
    def os_name(self):
        result = self.tree.xpath('//tag[@name="operating-system"]')
        if len(result) > 0:
            return result[0].text.split('\n')
        return None

    def ports(self):
        result = self.tree.xpath('//ReportItem/@port')
        if len(result) > 0:
            return sorted(list(set(self.tree.xpath('//ReportItem/@port'))))
        return None
    
    def services(self):
        result = self.tree.xpath('//ReportItem/@svc_name')
        if len(result) > 0:
            return sorted(list(set(self.tree.xpath('//ReportItem/@svc_name'))))
        return None
    
    def events(self):
        return (Event(element) for element in self.tree.xpath('//ReportItem'))

    
class Scan:
    
    def __init__(self, xml):
        self.tree = ElementTree.ElementTree(ElementTree.fromstring(xml))
    
    def title(self):
        result = self.tree.xpath('Report/@name')
        if len(result) > 0:
            return result[0]
        return None
    
    def policy(self):
        result = self.tree.xpath('Policy/policyName')
        if len(result) > 0:
            return result[0].text
        return None
    
    def target_hosts(self):
        for element in self.tree.xpath('//Preferences/ServerPreferences/preference'):
            if element[0].text == 'TARGET':
                return element[1].text.split(',')
        return None
    
    def port_range(self):
        for element in self.tree.xpath('//Preferences/ServerPreferences/preference'):
            if element[0].text == 'port_range':
                return element[1].text.split(',')
        return None
    
    def hosts(self):
        return (Host(element) for element in self.tree.xpath('//ReportHost'))
