# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#

"""Unit tests for the optional 'sha256_norm' field in tools.uefi.scan_image.

The additive normalized-hash field must not change the sha256-as-key schema or
the 'check' behavior. These tests instantiate scan_image without touching
hardware (BaseModule.__init__ is bypassed) and drive the callback / check logic
against synthetic EFI_SECTION objects.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import chipsec.hal.intel.spi as _intel_spi

from chipsec.library.returncode import ModuleResult
from chipsec.library.uefi.fv import EFI_SECTION, EFI_SECTION_PE32

# scan_image.py does `from chipsec.hal.intel.spi import SPI, BIOS`, but BIOS is
# not exported by that module on this branch (it is a pre-existing, feature-
# unrelated import quirk; BIOS actually lives in chipsec.module_common). Provide
# it so the module can be imported here without touching any hardware paths.
if not hasattr(_intel_spi, 'BIOS'):
    _intel_spi.BIOS = 'BIOS'

from chipsec.modules.tools.uefi import scan_image as scan_image_mod  # noqa: E402  pylint: disable=wrong-import-position
from chipsec.modules.tools.uefi.scan_image import scan_image  # noqa: E402  pylint: disable=wrong-import-position

from tests.library.test_uefi_fv_normalize import _build_pe  # noqa: E402  pylint: disable=wrong-import-position


def _make_section(image_base: int, guid: str, name: str) -> EFI_SECTION:
    sec = EFI_SECTION(0, 'S_PE32', EFI_SECTION_PE32, _build_pe(image_base, pe_plus=True), 0, 0)
    sec.calc_hashes(0, normalize=True)
    sec.parentGuid = guid
    sec.ui_string = name
    return sec


def _new_scan_image(include_norm: bool) -> scan_image:
    # Bypass BaseModule.__init__ (which reaches for chipset/logger) and set only
    # the attributes the callback / check paths use.
    module = scan_image.__new__(scan_image)
    module.logger = MagicMock()
    module.efi_list = {}
    module.suspect_modules = {}
    module.duplicate_list = []
    module.include_norm = include_norm
    return module


class TestGenlistCallbackNorm(unittest.TestCase):
    """The 'sha256_norm' value field is additive and gated on include_norm."""

    def test_norm_field_added_when_enabled(self):
        module = _new_scan_image(include_norm=True)
        sec = _make_section(0x140000000, 'GUID-A', 'ModuleA')
        module.genlist_callback(sec)
        # Keyed by sha256 (schema unchanged); sha256_norm is a value field.
        self.assertIn(sec.SHA256, module.efi_list)
        entry = module.efi_list[sec.SHA256]
        self.assertEqual(entry['sha256_norm'], sec.SHA256_NORM)
        self.assertIsNotNone(sec.SHA256_NORM)

    def test_norm_field_absent_when_disabled(self):
        module = _new_scan_image(include_norm=False)
        sec = _make_section(0x140000000, 'GUID-A', 'ModuleA')
        module.genlist_callback(sec)
        self.assertIn(sec.SHA256, module.efi_list)
        self.assertNotIn('sha256_norm', module.efi_list[sec.SHA256])


class TestCheckListUnaffectedByNorm(unittest.TestCase):
    """'check' keys on sha256, so a norm-annotated list still passes."""

    def _run_check_with_list(self, list_entries):
        module = _new_scan_image(include_norm=True)
        module.image = b''
        module.image_file = 'synthetic'
        sections = [
            _make_section(0x140000000, 'GUID-A', 'ModuleA'),
            _make_section(0x180000000, 'GUID-B', 'ModuleB'),
        ]

        def fake_search(_tree, callback, *_args, **_kwargs):
            for sec in sections:
                callback(sec)

        with tempfile.TemporaryDirectory() as tmp:
            json_pth = os.path.join(tmp, 'efilist.json')
            with open(json_pth, 'w', encoding='utf-8') as handle:
                json.dump(list_entries(sections), handle)
            with patch.object(scan_image_mod, 'build_efi_model', return_value=[]), \
                    patch.object(scan_image_mod, 'search_efi_tree', side_effect=fake_search):
                result = module.check_list(json_pth)
        return module, result

    def test_check_passes_on_norm_annotated_list(self):
        def with_norm(sections):
            return {
                sec.SHA256: {'sha1': sec.SHA1, 'sha256_norm': sec.SHA256_NORM}
                for sec in sections
            }
        module, result = self._run_check_with_list(with_norm)
        self.assertEqual(result, ModuleResult.PASSED)
        self.assertEqual(len(module.suspect_modules), 0)

    def test_check_still_flags_missing_module(self):
        # Drop the second module from the list -> it must be reported suspect,
        # proving the additive field did not weaken detection.
        def missing_one(sections):
            return {sections[0].SHA256: {'sha256_norm': sections[0].SHA256_NORM}}
        module, result = self._run_check_with_list(missing_one)
        self.assertEqual(result, ModuleResult.WARNING)
        self.assertEqual(len(module.suspect_modules), 1)


if __name__ == '__main__':
    unittest.main()
