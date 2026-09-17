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

"""Unit tests for the rebase-0 normalization in chipsec.library.uefi.fv.

Images are built in memory: a PE32/PE32+ with two self-referential pointers in
.text and a .reloc block describing them, and a TE converted from it the way
GenFw -t does it.
"""

import hashlib
import struct
import unittest

from chipsec.library.uefi.fv import (
    EFI_SECTION_PE32,
    EFI_SECTION_PIC,
    EFI_SECTION_TE,
    normalize_pe_rebase0,
    normalize_te_rebase0,
    normalized_sha256,
)

E_LFANEW = 0x80
COFF = E_LFANEW + 4
OPT = COFF + 20
TEXT_VA = 0x1000
TEXT_RAW = 0x200
RELOC_VA = 0x2000
RELOC_RAW = 0x400
SECTION_SIZE = 0x200
FILE_SIZE = 0x600
RELOC_SIZE = 8 + 2 * 2

IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10


def _build_pe(image_base, pe_plus=True, with_reloc=True, relocs_stripped=False, text_raw_size=SECTION_SIZE,
              text_raw_ptr=TEXT_RAW, reloc_type=None):
    """A PE32+ (or PE32) whose .text holds two pointers equal to image_base + their own RVA."""
    if pe_plus:
        magic, size_opt, base_off, dir_count_off, dir_off = 0x20B, 112 + 16 * 8, 24, 108, 112
        fmt, width = '<Q', 8
        default_type = IMAGE_REL_BASED_DIR64
    else:
        magic, size_opt, base_off, dir_count_off, dir_off = 0x10B, 96 + 16 * 8, 28, 92, 96
        fmt, width = '<I', 4
        default_type = IMAGE_REL_BASED_HIGHLOW
    reloc_type = default_type if reloc_type is None else reloc_type

    buf = bytearray(FILE_SIZE)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, E_LFANEW)
    buf[E_LFANEW:E_LFANEW + 4] = b'PE\x00\x00'
    struct.pack_into('<H', buf, COFF + 2, 2)                    # NumberOfSections
    struct.pack_into('<H', buf, COFF + 16, size_opt)            # SizeOfOptionalHeader
    if relocs_stripped:
        struct.pack_into('<H', buf, COFF + 18, 0x0001)          # IMAGE_FILE_RELOCS_STRIPPED
    struct.pack_into('<H', buf, OPT, magic)
    struct.pack_into(fmt, buf, OPT + base_off, image_base)
    struct.pack_into('<I', buf, OPT + dir_count_off, 16)        # NumberOfRvaAndSizes
    if with_reloc:
        struct.pack_into('<II', buf, OPT + dir_off + 5 * 8, RELOC_VA, RELOC_SIZE)

    table = OPT + size_opt
    for i, (name, va, raw_ptr, raw_size, flags) in enumerate((
            (b'.text', TEXT_VA, text_raw_ptr, text_raw_size, 0x60000020),
            (b'.reloc', RELOC_VA, RELOC_RAW, SECTION_SIZE, 0x42000040))):
        header = table + i * 40
        buf[header:header + 8] = name.ljust(8, b'\x00')
        struct.pack_into('<IIII', buf, header + 8, SECTION_SIZE, va, raw_size, raw_ptr)
        struct.pack_into('<I', buf, header + 36, flags)

    for i in range(2):
        struct.pack_into(fmt, buf, TEXT_RAW + i * width, image_base + TEXT_VA + i * width)
    struct.pack_into('<II', buf, RELOC_RAW, TEXT_VA, RELOC_SIZE)
    for i in range(2):
        struct.pack_into('<H', buf, RELOC_RAW + 8 + i * 2, (reloc_type << 12) | (i * width))
    return bytes(buf)


def _pe_section_table():
    return OPT + 112 + 16 * 8


def _build_te(image_base, stripped_relocs=False):
    """_build_pe converted to TE: everything before the section table replaced by a 40-byte header."""
    pe = _build_pe(image_base)
    stripped_size = _pe_section_table()
    reloc = (0, 0) if stripped_relocs else (RELOC_VA, RELOC_SIZE)
    header = struct.pack('<2sHBBHIIQIIII', b'VZ', 0x8664, 2, 0, stripped_size, 0, 0, image_base, *reloc, 0, 0)
    return header + pe[stripped_size:]


def _te_adjust(te):
    return struct.unpack_from('<H', te, 6)[0] - 40


def _make_fixup_rewrite_its_own_directory(image, reloc_dir_off):
    """Point the relocation block at its own page, first entry a DIR64 onto the second entry.

    With ImageBase 0x1000 that fixup turns the second entry, 0xA008, into 0x9008: a
    type the profile does not support. Read from the image as it is being patched,
    the walk must therefore stop and produce no value. Read from the untouched
    input, it would see 0xA008 and carry on.
    """
    buf = bytearray(image)
    struct.pack_into('<I', buf, reloc_dir_off, RELOC_VA)
    struct.pack_into('<H', buf, reloc_dir_off + 8, (IMAGE_REL_BASED_DIR64 << 12) | 10)
    struct.pack_into('<H', buf, reloc_dir_off + 10, (IMAGE_REL_BASED_DIR64 << 12) | 8)
    return bytes(buf)


class TestNormalizePeRebase0(unittest.TestCase):

    def test_same_bytes_wherever_the_module_is_placed(self):
        for pe_plus, bases in ((True, (0x140000000, 0xFFE00000)), (False, (0x00400000, 0x10000000))):
            reference = _build_pe(0, pe_plus=pe_plus)
            for image_base in bases:
                self.assertEqual(normalize_pe_rebase0(_build_pe(image_base, pe_plus=pe_plus)), reference)

    def test_base0_module_is_unchanged(self):
        data = _build_pe(0)
        self.assertEqual(normalize_pe_rebase0(data), data)

    def test_timestamp_and_checksum_are_zeroed(self):
        stamped = bytearray(_build_pe(0))
        struct.pack_into('<I', stamped, COFF + 4, 0x66D1B2C3)
        struct.pack_into('<I', stamped, OPT + 64, 0xDEADBEEF)
        self.assertEqual(normalize_pe_rebase0(bytes(stamped)), _build_pe(0))

    def test_section_pointers_are_zeroed(self):
        # GenFw's rebase writes the load address across PointerToRelocations and
        # PointerToLinenumbers of the first non-code section
        rebased = bytearray(_build_pe(0x140000000))
        struct.pack_into('<Q', rebased, _pe_section_table() + 40 + 24, 0x140000000)
        self.assertEqual(normalize_pe_rebase0(bytes(rebased)), _build_pe(0))

    def test_header_fields_are_zeroed_after_the_fixups(self):
        # .text moved onto the header: the first fixup lands on ImageBase itself and
        # the second on the 8 bytes after it. Reversing gives B - B = 0 for ImageBase;
        # zeroing ImageBase first would leave 0 - B there instead.
        image_base = 0x140000000
        data = _build_pe(image_base, text_raw_ptr=OPT + 24)
        normalized = normalize_pe_rebase0(data)
        self.assertIsNotNone(normalized)
        self.assertEqual(struct.unpack_from('<Q', normalized, OPT + 24)[0], 0)
        self.assertEqual(struct.unpack_from('<Q', normalized, OPT + 32)[0], (-image_base) & 0xFFFFFFFFFFFFFFFF)

    def test_fixups_are_read_from_the_patched_image(self):
        data = _make_fixup_rewrite_its_own_directory(_build_pe(0x1000), RELOC_RAW)
        self.assertIsNone(normalize_pe_rebase0(data))

    def test_fixup_past_raw_data_emits_no_value(self):
        # the second pointer sits in .text's virtual-only tail, which has no bytes in the file
        self.assertIsNone(normalize_pe_rebase0(_build_pe(0x140000000, text_raw_size=8)))

    def test_fixup_in_section_without_raw_data_emits_no_value(self):
        self.assertIsNone(normalize_pe_rebase0(_build_pe(0x140000000, text_raw_ptr=0)))

    def test_stripped_relocations_emit_no_value(self):
        self.assertIsNone(normalize_pe_rebase0(_build_pe(0x140000000, with_reloc=False, relocs_stripped=True)))

    def test_absent_relocations_still_normalize(self):
        # a module that never had relocations: placing it changed only ImageBase
        normalized = normalize_pe_rebase0(_build_pe(0x140000000, with_reloc=False))
        self.assertIsNotNone(normalized)
        self.assertEqual(struct.unpack_from('<Q', normalized, OPT + 24)[0], 0)

    def test_stripped_flag_at_base0_still_normalizes(self):
        data = _build_pe(0, with_reloc=False, relocs_stripped=True)
        self.assertEqual(normalize_pe_rebase0(data), data)

    def test_unsupported_relocation_type_emits_no_value(self):
        self.assertIsNone(normalize_pe_rebase0(_build_pe(0x140000000, reloc_type=1)))

    def test_odd_block_size_emits_no_value(self):
        data = bytearray(_build_pe(0x140000000))
        struct.pack_into('<I', data, RELOC_RAW + 4, RELOC_SIZE - 1)
        self.assertIsNone(normalize_pe_rebase0(bytes(data)))

    def test_block_past_directory_emits_no_value(self):
        data = bytearray(_build_pe(0x140000000))
        struct.pack_into('<I', data, RELOC_RAW + 4, RELOC_SIZE + 2)
        self.assertIsNone(normalize_pe_rebase0(bytes(data)))

    def test_section_table_past_end_emits_no_value(self):
        # cut inside the last header, after every field that is read or written
        self.assertIsNone(normalize_pe_rebase0(_build_pe(0)[:_pe_section_table() + 40 + 36]))

    def test_truncated_input_never_raises(self):
        # a cut after the relocation directory can still normalize; a cut anywhere must not raise
        data = _build_pe(0x140000000)
        for length in range(len(data)):
            self.assertIn(type(normalize_pe_rebase0(data[:length])), (bytes, type(None)))
        self.assertIsNone(normalize_pe_rebase0(data[:RELOC_RAW + RELOC_SIZE - 1]))

    def test_non_pe_input_emits_no_value(self):
        self.assertIsNone(normalize_pe_rebase0(b''))
        self.assertIsNone(normalize_pe_rebase0(b'\x00' * 0x100))
        self.assertIsNone(normalize_pe_rebase0(_build_te(0)))


class TestNormalizeTeRebase0(unittest.TestCase):

    def test_same_bytes_wherever_the_module_is_placed(self):
        reference = normalize_te_rebase0(_build_te(0))
        self.assertEqual(reference, _build_te(0))
        for image_base in (0x820000, 0x140000000, 0xFFE00000):
            self.assertEqual(normalize_te_rebase0(_build_te(image_base)), reference)

    def test_section_pointers_are_zeroed(self):
        rebased = bytearray(_build_te(0x140000000))
        struct.pack_into('<Q', rebased, 40 + 40 + 24, 0x140000000)
        self.assertEqual(normalize_te_rebase0(bytes(rebased)), _build_te(0))

    def test_fixups_are_read_from_the_patched_image(self):
        te = _build_te(0x1000)
        data = _make_fixup_rewrite_its_own_directory(te, RELOC_RAW - _te_adjust(te))
        self.assertIsNone(normalize_te_rebase0(data))

    def test_stripped_relocations_emit_no_value(self):
        # no Characteristics in a TE: an all-zero directory records the stripping
        self.assertIsNone(normalize_te_rebase0(_build_te(0x140000000, stripped_relocs=True)))

    def test_sentinel_directory_still_normalizes(self):
        # non-zero VirtualAddress with Size 0: relocatable, nothing to reverse
        te = bytearray(_build_te(0x140000000))
        struct.pack_into('<I', te, 28, 0)
        normalized = normalize_te_rebase0(bytes(te))
        self.assertIsNotNone(normalized)
        self.assertEqual(struct.unpack_from('<Q', normalized, 16)[0], 0)

    def test_stripped_size_not_above_header_emits_no_value(self):
        te = bytearray(_build_te(0x140000000))
        struct.pack_into('<H', te, 6, 40)
        self.assertIsNone(normalize_te_rebase0(bytes(te)))

    def test_odd_block_size_emits_no_value(self):
        te = bytearray(_build_te(0x140000000))
        struct.pack_into('<I', te, RELOC_RAW - _te_adjust(te) + 4, RELOC_SIZE - 1)
        self.assertIsNone(normalize_te_rebase0(bytes(te)))

    def test_section_table_past_end_emits_no_value(self):
        self.assertIsNone(normalize_te_rebase0(_build_te(0)[:40 + 40 + 36]))

    def test_truncated_input_never_raises(self):
        te = _build_te(0x140000000)
        for length in range(len(te)):
            self.assertIn(type(normalize_te_rebase0(te[:length])), (bytes, type(None)))
        self.assertIsNone(normalize_te_rebase0(te[:RELOC_RAW - _te_adjust(te) + RELOC_SIZE - 1]))

    def test_non_te_input_emits_no_value(self):
        self.assertIsNone(normalize_te_rebase0(b''))
        self.assertIsNone(normalize_te_rebase0(b'VZ'))
        self.assertIsNone(normalize_te_rebase0(_build_pe(0)))


class TestNormalizedSha256(unittest.TestCase):

    def test_pe32_section_is_labelled_with_the_pe_profile(self):
        expected = 'uefi-pe-rebase0.v1:sha256:' + hashlib.sha256(_build_pe(0)).hexdigest()
        self.assertEqual(normalized_sha256(EFI_SECTION_PE32, _build_pe(0x140000000)), expected)

    def test_te_section_is_labelled_with_the_te_profile(self):
        expected = 'uefi-te-rebase0.v1:sha256:' + hashlib.sha256(_build_te(0)).hexdigest()
        self.assertEqual(normalized_sha256(EFI_SECTION_TE, _build_te(0x140000000)), expected)

    def test_profile_follows_the_section_type(self):
        self.assertIsNone(normalized_sha256(EFI_SECTION_PIC, _build_pe(0)))
        self.assertIsNone(normalized_sha256(EFI_SECTION_PE32, _build_te(0)))
        self.assertIsNone(normalized_sha256(EFI_SECTION_TE, _build_pe(0)))

    def test_unnormalizable_payload_has_no_value(self):
        self.assertIsNone(normalized_sha256(EFI_SECTION_PE32, _build_pe(0x140000000, reloc_type=1)))


if __name__ == '__main__':
    unittest.main()
