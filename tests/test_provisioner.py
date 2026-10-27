import unittest

import provisioner


class EntrypointTests(unittest.TestCase):
    def test_new_pipeline_is_the_public_entrypoint(self):
        self.assertTrue(callable(provisioner.main))
        self.assertTrue(hasattr(provisioner, "Provisioner"))


if __name__ == "__main__":
    unittest.main()
