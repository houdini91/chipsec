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

"""Unit tests for the optional rebase-0 (normalized) module hash.

These cover ``normalize_pe_rebase0`` and ``EFI_MODULE.calc_hashes(normalize=True)``
in ``chipsec.library.uefi.fv``. Synthetic PE32/PE32+ images are built in-memory so
the tests do not depend on any external firmware sample.
"""

import hashlib
import struct
import unittest

from chipsec.library.uefi.fv import (
    EFI_SECTION,
    EFI_SECTION_PE32,
    EFI_SECTION_TE,
    normalize_pe_rebase0,
)

# File layout shared by all synthetic images (see _build_pe).
E_LFANEW = 0x80
TEXT_VA = 0x1000
TEXT_RAW = 0x200
TEXT_RAWSIZE = 0x200
RELOC_VA = 0x2000
RELOC_RAW = 0x400
RELOC_RAWSIZE = 0x200
FILE_SIZE = 0x600

# Two DIR64/HIGHLOW pointers live at the start of .text; each stores
# (ImageBase + own RVA), i.e. a self-referential absolute address.
PTR_RVAS = (TEXT_VA + 0x00, TEXT_VA + 0x08)

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10


def _build_pe(image_base: int, pe_plus: bool = True, with_reloc: bool = True) -> bytes:
    """Build a minimal but valid PE32/PE32+ image with two base relocations.

    The two pointers in .text are written as (image_base + their RVA) and a
    .reloc block describes them, so applying/reversing the fixups is meaningful.
    """
    if pe_plus:
        magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC
        size_opt = 112 + 16 * 8
        imagebase_off = 24
        numrva_off = 108
        dd_off = 112
        reloc_type = IMAGE_REL_BASED_DIR64
    else:
        magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC
        size_opt = 96 + 16 * 8
        imagebase_off = 28
        numrva_off = 92
        dd_off = 96
        reloc_type = IMAGE_REL_BASED_HIGHLOW

    buf = bytearray(FILE_SIZE)

    # DOS header
    struct.pack_into('<H', buf, 0, 0x5A4D)          # 'MZ'
    struct.pack_into('<I', buf, 0x3C, E_LFANEW)     # e_lfanew

    # PE signature + COFF header
    buf[E_LFANEW:E_LFANEW + 4] = b'PE\x00\x00'
    coff = E_LFANEW + 4
    struct.pack_into('<H', buf, coff + 2, 2)                # NumberOfSections
    struct.pack_into('<H', buf, coff + 16, size_opt)        # SizeOfOptionalHeader

    # Optional header (only the fields the normalizer reads are set)
    opt = coff + 20
    struct.pack_into('<H', buf, opt, magic)
    if pe_plus:
        struct.pack_into('<Q', buf, opt + imagebase_off, image_base)
    else:
        struct.pack_into('<I', buf, opt + imagebase_off, image_base & 0xFFFFFFFF)
    struct.pack_into('<I', buf, opt + numrva_off, 16)       # NumberOfRvaAndSizes

    reloc_size = 8 + 2 * 2  # header + two 2-byte entries
    if with_reloc:
        reloc_dd = opt + dd_off + 5 * 8                     # BASERELOC directory
        struct.pack_into('<II', buf, reloc_dd, RELOC_VA, reloc_size)

    # Section table
    sec_tbl = opt + size_opt

    def _section(idx, name, va, raw_ptr, raw_size):
        base = sec_tbl + idx * 40
        buf[base:base + 8] = name.ljust(8, b'\x00')
        struct.pack_into('<I', buf, base + 8, raw_size)     # VirtualSize
        struct.pack_into('<I', buf, base + 12, va)          # VirtualAddress
        struct.pack_into('<I', buf, base + 16, raw_size)    # SizeOfRawData
        struct.pack_into('<I', buf, base + 20, raw_ptr)     # PointerToRawData

    _section(0, b'.text', TEXT_VA, TEXT_RAW, TEXT_RAWSIZE)
    _section(1, b'.reloc', RELOC_VA, RELOC_RAW, RELOC_RAWSIZE)

    # .text: two self-referential absolute pointers (ImageBase + own RVA)
    for i, rva in enumerate(PTR_RVAS):
        value = image_base + rva
        if pe_plus:
            struct.pack_into('<Q', buf, TEXT_RAW + i * 8, value)
        else:
            struct.pack_into('<I', buf, TEXT_RAW + i * 8, value & 0xFFFFFFFF)

    # .reloc: one block for page TEXT_VA describing both pointers
    struct.pack_into('<I', buf, RELOC_RAW, TEXT_VA)         # PageRVA
    struct.pack_into('<I', buf, RELOC_RAW + 4, reloc_size)  # BlockSize
    struct.pack_into('<H', buf, RELOC_RAW + 8, (reloc_type << 12) | 0x000)
    struct.pack_into('<H', buf, RELOC_RAW + 10, (reloc_type << 12) | 0x008)

    return bytes(buf)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestNormalizePeRebase0(unittest.TestCase):
    """Cover normalize_pe_rebase0 directly."""

    def test_relocated_pe32plus_stable_across_imagebase(self):
        norm_a = normalize_pe_rebase0(_build_pe(0x400000000, pe_plus=True))
        norm_b = normalize_pe_rebase0(_build_pe(0x180000000, pe_plus=True))
        self.assertIsNotNone(norm_a)
        self.assertEqual(norm_a, norm_b)

    def test_relocated_pe32_stable_across_imagebase(self):
        norm_a = normalize_pe_rebase0(_build_pe(0x00400000, pe_plus=False))
        norm_b = normalize_pe_rebase0(_build_pe(0x10000000, pe_plus=False))
        self.assertIsNotNone(norm_a)
        self.assertEqual(norm_a, norm_b)

    def test_normalized_equals_native_base0_reference(self):
        # A module built directly at ImageBase 0 is the canonical rebase-0 form;
        # normalizing a relocated copy must reproduce it byte-for-byte.
        reference = _build_pe(0, pe_plus=True)
        normalized = normalize_pe_rebase0(_build_pe(0x140000000, pe_plus=True))
        self.assertEqual(normalized, reference)

    def test_base0_module_norm_equals_as_found(self):
        # "direct / non-relocated" (already rebase-0): normalization is a no-op.
        data = _build_pe(0, pe_plus=True)
        self.assertEqual(normalize_pe_rebase0(data), data)

    def test_te_returns_none(self):
        # TE image (magic 'VZ') is not a PE and must be skipped, not faked.
        te = b'VZ' + b'\x00' * 0x100
        self.assertIsNone(normalize_pe_rebase0(te))

    def test_non_pe_returns_none(self):
        self.assertIsNone(normalize_pe_rebase0(b'\x00' * 0x100))
        self.assertIsNone(normalize_pe_rebase0(b''))


class TestCalcHashesNormalize(unittest.TestCase):
    """Cover EFI_MODULE.calc_hashes(normalize=True) via EFI_SECTION."""

    def _section(self, image, sec_type=EFI_SECTION_PE32):
        return EFI_SECTION(0, '.text', sec_type, image, 0, len(image))

    def test_sha256_norm_populated_and_layout_independent(self):
        sec_a = self._section(_build_pe(0x400000000, pe_plus=True))
        sec_b = self._section(_build_pe(0x180000000, pe_plus=True))
        sec_a.calc_hashes(0, normalize=True)
        sec_b.calc_hashes(0, normalize=True)
        self.assertIsNotNone(sec_a.SHA256_NORM)
        # As-found hashes differ (different ImageBase); normalized hashes match.
        self.assertNotEqual(sec_a.SHA256, sec_b.SHA256)
        self.assertEqual(sec_a.SHA256_NORM, sec_b.SHA256_NORM)
        self.assertEqual(sec_a.SHA256_NORM, _sha256(_build_pe(0, pe_plus=True)))

    def test_base0_norm_equals_as_found(self):
        sec = self._section(_build_pe(0, pe_plus=True))
        sec.calc_hashes(0, normalize=True)
        self.assertEqual(sec.SHA256_NORM, sec.SHA256)

    def test_te_leaves_norm_none(self):
        sec = self._section(b'VZ' + b'\x00' * 0x100, sec_type=EFI_SECTION_TE)
        sec.calc_hashes(0, normalize=True)
        self.assertIsNone(sec.SHA256_NORM)
        # The as-found SHA256 is still computed for TE sections.
        self.assertIsNotNone(sec.SHA256)

    def test_normalize_false_leaves_norm_none(self):
        sec = self._section(_build_pe(0x140000000, pe_plus=True))
        sec.calc_hashes(0)
        self.assertIsNone(sec.SHA256_NORM)
        self.assertIsNotNone(sec.SHA256)


if __name__ == '__main__':
    unittest.main()
