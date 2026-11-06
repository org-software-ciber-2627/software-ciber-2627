import unittest

from runner import build_command, get_profiles


class TestRunner(unittest.TestCase):
    def test_perfiles_y_comando_vuln_con_limites(self):
        command = build_command("  192.0.2.10  ", "vuln", "/tmp/scan.xml")
        self.assertEqual(get_profiles(), ["vuln", "web", "quick"])
        self.assertEqual(command[0:4], ["nmap", "-sT", "-sV", "--script"])
        self.assertIn("vuln", command)
        self.assertIn("--script-timeout", command)
        self.assertIn("--host-timeout", command)
        self.assertEqual(command[-1], "192.0.2.10")

    def test_rechaza_objetivo_y_perfil_invalidos(self):
        for target in (None, "", "  ", "-oX"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                build_command(target, "vuln", "scan.xml")
        with self.assertRaises(ValueError):
            build_command("192.0.2.10", "no-existe", "scan.xml")


if __name__ == "__main__":
    unittest.main(verbosity=2)
