import unittest
import xml.etree.ElementTree as ET

from qnap_nas_cli.parsers import parse_network, parse_storage, parse_system
from qnap_nas_cli.redaction import redact_xml, redact_value


SYSINFO = b"""<QDocRoot>
<hostname>TS-431K</hostname><modelName>TS-431K</modelName><version>5.2.0</version><build>20261001</build>
<cpu_usage>12 %</cpu_usage><total_memory>1024 MB</total_memory><free_memory>400 MB</free_memory><sys_tempc>42 C</sys_tempc>
<uptime_day>3</uptime_day><uptime_hour>4</uptime_hour><uptime_min>5</uptime_min><uptime_sec>6</uptime_sec>
<nic_cnt>1</nic_cnt><ifname1>eth0</ifname1><dname1>Adapter 1</dname1><eth_status1>1</eth_status1>
<eth_ip1>192.168.1.10</eth_ip1><eth_max_speed1>1000</eth_max_speed1><DNS_LIST>192.168.1.1</DNS_LIST>
</QDocRoot>"""

STORAGE = b"""<QDocRoot><volume><volume_name>DataVol1</volume_name><vol_status>-5</vol_status></volume>
<disk><disk_no>2</disk_no><model>ST2000</model><serial_no>SECRET</serial_no><temperature>48 C</temperature><smart_status>Warning</smart_status></disk></QDocRoot>"""


class ParserTest(unittest.TestCase):
    def test_system_metrics(self):
        result = parse_system(ET.fromstring(SYSINFO))
        self.assertEqual(result["model"], "TS-431K")
        self.assertEqual(result["memory_used_mb"], 624)
        self.assertEqual(result["uptime"]["total_seconds"], 273906)

    def test_network(self):
        result = parse_network(ET.fromstring(SYSINFO))
        self.assertEqual(result["adapters"][0]["status"], "up")
        self.assertEqual(result["dns"], ["192.168.1.1"])
        self.assertEqual(result["dns_status"], "observed")

    def test_nested_dns_and_unknown_dns_format_degrade_explicitly(self):
        nested = parse_network(ET.fromstring("<QDocRoot><DNS_LIST><IP>1.1.1.1</IP><IP>8.8.8.8</IP></DNS_LIST></QDocRoot>"))
        unknown = parse_network(ET.fromstring("<QDocRoot><DNS_LIST><IP /></DNS_LIST></QDocRoot>"))
        self.assertEqual(nested["dns"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(nested["dns_status"], "observed")
        self.assertEqual(unknown["dns_status"], "unknown_format")

    def test_storage(self):
        result = parse_storage(ET.fromstring(STORAGE))
        self.assertEqual(result["volumes"][0]["status"], "degraded")
        self.assertEqual(result["volumes"][0]["status_semantics"], "known_bad")
        self.assertEqual(result["disks"][0]["smart"], "Warning")

    def test_dump_redaction(self):
        value = redact_xml(b"<QDocRoot><hostname>MYNAS</hostname><eth_ip1>192.168.1.2</eth_ip1><serial_number>ABC</serial_number></QDocRoot>")
        self.assertNotIn("MYNAS", value)
        self.assertNotIn("192.168.1.2", value)
        self.assertNotIn("ABC", value)

    def test_nested_redaction(self):
        value = redact_value({"serial": "ABC", "message": "from 192.168.1.2"})
        self.assertEqual(value["serial"], "REDACTED")
        self.assertEqual(value["message"], "from x.x.x.x")


if __name__ == "__main__":
    unittest.main()
