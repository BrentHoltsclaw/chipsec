import unittest
from unittest.mock import Mock
from chipsec.utilcmd.pci_cmd import PCICommand
from tests.test_utils import MockFactory

class TestPCICommand(unittest.TestCase):
    def setUp(self):
        self.mock_cs = MockFactory.create_mock_chipsec_cs()
        self.pci_command = PCICommand(['enumerate'], cs=self.mock_cs)

    def test_initialization(self):
        self.assertIsNotNone(self.pci_command)

    def test_requirements(self):
        from chipsec.command import toLoad
        self.assertEqual(self.pci_command.requirements(), toLoad.Driver)

if __name__ == '__main__':
    unittest.main()
