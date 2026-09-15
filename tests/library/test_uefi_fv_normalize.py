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
    NORM_PROFILE_PE,
    NORM_PROFILE_TE,
    normalize_pe_rebase0,
    normalize_te_rebase0,
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


def _build_te(image_base: int = 0, with_reloc: bool = True, strip_relocs: bool = False) -> bytes:
    """A TE image, built from _build_pe the way GenFw -t builds one.

    GenFw discards the bytes before the section table and prepends a 40-byte
    EFI_TE_IMAGE_HEADER, so StrippedSize is the section table's offset in the PE
    and every RVA then resolves (StrippedSize - 40) lower than it did.
    """
    pe = _build_pe(image_base, pe_plus=True, with_reloc=with_reloc)
    e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
    fh = e_lfanew + 4
    oh = fh + 20
    num_sections = struct.unpack_from('<H', pe, fh + 2)[0]
    stripped = oh + struct.unpack_from('<H', pe, fh + 16)[0]
    machine = struct.unpack_from('<H', pe, fh)[0]
    entry = struct.unpack_from('<I', pe, oh + 16)[0]
    base_of_code = struct.unpack_from('<I', pe, oh + 20)[0]
    num_rva = struct.unpack_from('<I', pe, oh + 108)[0]
    if num_rva > 5 and not strip_relocs:
        reloc = struct.unpack_from('<II', pe, oh + 112 + 5 * 8)
    else:
        reloc = (0, 0)
    debug = (0, 0)

    hdr = struct.pack('<HHBBHIIQ', 0x5A56, machine, num_sections, 0,
                      stripped, entry, base_of_code, image_base)
    hdr += struct.pack('<II', *reloc) + struct.pack('<II', *debug)
    assert len(hdr) == 40
    return hdr + pe[stripped:]


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

    def test_timestamp_and_checksum_are_zeroed(self):
        """TimeDateStamp and CheckSum are build-incidental, not code.

        A PE carrying either of them un-zeroed must normalize to the same bytes
        as one carrying zeros, or the "identity depends only on the code" claim
        is false: two builds of identical source at different times would hash
        differently. Note _build_pe leaves both fields zero, so nothing else in
        this file can distinguish an implementation that skips them.
        """
        coff = E_LFANEW + 4
        opt = coff + 20
        for pe_plus in (True, False):
            clean = _build_pe(0, pe_plus=pe_plus, with_reloc=False)
            stamped = bytearray(clean)
            struct.pack_into('<I', stamped, coff + 4, 0x66D1B2C3)   # FileHeader.TimeDateStamp
            struct.pack_into('<I', stamped, opt + 64, 0xDEADBEEF)   # OptionalHeader.CheckSum
            self.assertNotEqual(bytes(stamped), clean)

            norm = normalize_pe_rebase0(bytes(stamped))
            self.assertIsNotNone(norm)
            self.assertEqual(struct.unpack_from('<I', norm, coff + 4)[0], 0)
            self.assertEqual(struct.unpack_from('<I', norm, opt + 64)[0], 0)
            # and the two builds converge on one identity
            self.assertEqual(norm, normalize_pe_rebase0(clean))

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

    def test_malformed_te_leaves_norm_none(self):
        # StrippedSize of 0 cannot be right -- the section table alone sits above it
        sec = self._section(b'VZ' + b'\x00' * 0x100, sec_type=EFI_SECTION_TE)
        sec.calc_hashes(0, normalize=True)
        self.assertIsNone(sec.SHA256_NORM)
        self.assertIsNone(sec.SHA256_NORM_PROFILE)
        # The as-found SHA256 is still computed for TE sections.
        self.assertIsNotNone(sec.SHA256)

    def test_te_section_is_normalized_and_labelled(self):
        sec = self._section(_build_te(0x140000000), sec_type=EFI_SECTION_TE)
        sec.calc_hashes(0, normalize=True)
        self.assertIsNotNone(sec.SHA256_NORM)
        self.assertEqual(sec.SHA256_NORM_PROFILE, NORM_PROFILE_TE)

    def test_pe_section_carries_the_pe_profile(self):
        sec = self._section(_build_pe(0x140000000, pe_plus=True))
        sec.calc_hashes(0, normalize=True)
        self.assertEqual(sec.SHA256_NORM_PROFILE, NORM_PROFILE_PE)

    def test_normalize_false_leaves_norm_none(self):
        sec = self._section(_build_pe(0x140000000, pe_plus=True))
        sec.calc_hashes(0)
        self.assertIsNone(sec.SHA256_NORM)
        self.assertIsNotNone(sec.SHA256)


if __name__ == '__main__':
    unittest.main()


class TestNormalizeTeRebase0(unittest.TestCase):
    """uefi-te-rebase0.v1: the TE sibling of the PE normalization."""

    def test_stable_across_imagebase(self):
        # the whole point: the same module placed anywhere normalizes identically
        base0 = normalize_te_rebase0(_build_te(0))
        self.assertIsNotNone(base0)
        for image_base in (0x820000, 0x140000000, 0xFFE00000):
            self.assertEqual(normalize_te_rebase0(_build_te(image_base)), base0)

    def test_imagebase_is_zeroed(self):
        norm = normalize_te_rebase0(_build_te(0x140000000))
        self.assertEqual(struct.unpack_from('<Q', norm, 16)[0], 0)

    def test_stripped_relocations_emit_no_value(self):
        # a TE has no Characteristics, so an all-zero relocation directory is how
        # "the table was applied and discarded" is expressed. It cannot be reversed.
        self.assertIsNone(normalize_te_rebase0(_build_te(0x140000000, strip_relocs=True)))

    def test_sentinel_directory_still_normalizes(self):
        # non-zero VirtualAddress with Size 0 is GenFw's marker for "relocatable,
        # no fixups", which is an absence rather than a removal
        te = bytearray(_build_te(0x140000000))
        struct.pack_into('<I', te, 28, 0)          # Size = 0, VirtualAddress kept
        norm = normalize_te_rebase0(bytes(te))
        self.assertIsNotNone(norm)
        self.assertEqual(struct.unpack_from('<Q', norm, 16)[0], 0)

    def test_strippedsize_not_greater_than_header_emits_no_value(self):
        te = bytearray(_build_te(0x140000000))
        struct.pack_into('<H', te, 6, 40)
        self.assertIsNone(normalize_te_rebase0(bytes(te)))

    def test_odd_blocksize_emits_no_value(self):
        te = bytearray(_build_te(0x140000000))
        stripped = struct.unpack_from('<H', te, 6)[0]
        tso = stripped - 40
        rva = struct.unpack_from('<I', te, 24)[0]
        # the section table keeps original-PE coordinates, so the directory's own
        # RVA resolves through it before the TE adjustment
        off = None
        for i in range(te[4]):
            sh = 40 + i * 40
            vaddr, rsize, praw = (struct.unpack_from('<I', te, sh + 12)[0],
                                  struct.unpack_from('<I', te, sh + 16)[0],
                                  struct.unpack_from('<I', te, sh + 20)[0])
            if praw and rsize and vaddr <= rva < vaddr + rsize:
                off = praw + (rva - vaddr) - tso
                break
        self.assertIsNotNone(off, 'could not locate the relocation directory')
        # relocation blocks hold uint16 entries, so an odd size cannot be well formed
        blk = struct.unpack_from('<I', te, off + 4)[0]
        struct.pack_into('<I', te, off + 4, blk - 1)
        self.assertIsNone(normalize_te_rebase0(bytes(te)))

    def test_pe_input_returns_none(self):
        self.assertIsNone(normalize_te_rebase0(_build_pe(0, pe_plus=True)))

    def test_short_and_empty_input_return_none(self):
        self.assertIsNone(normalize_te_rebase0(b''))
        self.assertIsNone(normalize_te_rebase0(b'VZ'))


class TestSectionPointerNormalization(unittest.TestCase):
    """s4.2: a rebase leaves a copy of the load address in the section table."""

    def test_pe_section_pointers_are_zeroed(self):
        pe = bytearray(_build_pe(0x140000000, pe_plus=True))
        e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
        fh = e_lfanew + 4
        sec = fh + 20 + struct.unpack_from('<H', pe, fh + 16)[0]
        # GenFw's rebase writes the load address across PointerToRelocations and
        # PointerToLinenumbers of the first non-code section (GenFw.c:966-972)
        for i in range(struct.unpack_from('<H', pe, fh + 2)[0]):
            sh = sec + i * 40
            if not (struct.unpack_from('<I', pe, sh + 36)[0] & 0x20):
                struct.pack_into('<Q', pe, sh + 24, 0x140000000)
                break
        else:
            self.skipTest('synthetic image has no non-code section')
        norm = normalize_pe_rebase0(bytes(pe))
        self.assertIsNotNone(norm)
        self.assertEqual(norm, normalize_pe_rebase0(_build_pe(0x140000000, pe_plus=True)))
