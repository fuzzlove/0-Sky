"""Exercise real tunnel ownership checks across ports and devices."""
import sys,unittest
from types import SimpleNamespace
from unittest.mock import patch
from repair_device_connection import HOST_TOOLS
sys.path.insert(0,str(HOST_TOOLS))
import pair

class TunnelPorts(unittest.TestCase):
    def present(self,line,udid='device-a',remote='22'):
        with patch.object(pair,'run',return_value=SimpleNamespace(stdout=line.encode())):
            return pair.exact_iproxy_present(udid,'2227',remote)
    def test_recovery_port_is_not_mistaken_for_port_22(self):
        line='/opt/homebrew/bin/iproxy -s 127.0.0.1 -u device-a 2227:22022'
        self.assertFalse(self.present(line))
        self.assertTrue(self.present(line,remote='22022'))
    def test_another_device_cannot_supply_the_route(self):
        line='/opt/homebrew/bin/iproxy -s 127.0.0.1 -u device-a-extra 2227:22'
        self.assertFalse(self.present(line))
    def test_existing_standard_service_remains_supported(self):
        self.assertTrue(self.present('/opt/homebrew/bin/iproxy -s 127.0.0.1 -u device-a 2227:22'))
    def test_closed_route_forwards_declared_remote_port(self):
        process=SimpleNamespace(poll=lambda:None)
        with patch.object(pair,'tcp_open',side_effect=[False,True]),patch.object(pair.shutil,'which',return_value='/usr/bin/iproxy'),patch.object(pair.subprocess,'Popen',return_value=process) as start:
            self.assertIs(pair.prepare_loopback_tunnel('127.0.0.1','2227','device-a','22022'),process)
        self.assertEqual(start.call_args.args[0],['/usr/bin/iproxy','-s','127.0.0.1','-u','device-a','2227:22022'])

if __name__=='__main__':unittest.main()
