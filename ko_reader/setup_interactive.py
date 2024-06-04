from glob import glob
from pwn import *
from elftools.elf.elffile import ELFFile

context(arch="amd64")

#chall, = glob("/challenge/*.ko")
chall = "2.1.stripped.ko"
f = open(chall, "rb")
e = ELFFile(f)

get_sec = lambda name: e.get_section_by_name(name)

symtab = get_sec(".symtab")
get_sym = lambda name: symtab.get_symbol_by_name(name)
get_sym_i = lambda name: [
    i for i in range(symtab.num_symbols()) if symtab.get_symbol(i).name == name
]
sym_i = lambda i: symtab.get_symbol(i)

text = get_sec(".text")
trela = get_sec(".rela.text")
textu = get_sec(".text.unlikely")
turela = get_sec(".rela.text.unlikely")
data = get_sec(".data")
drela = get_sec(".rela.data")
mod = get_sec(".gnu.linkonce.this_module")
mrela = get_sec(".rela.gnu.linkonce.this_module")

base = 0x00100000
start_offset = next(
    filter(lambda sec: sec["sh_type"] != "SHT_NULL", e.iter_sections())
)["sh_offset"]
offset_to_addr = lambda offset: offset + base - start_offset
addr_to_offset = lambda addr: addr - base + start_offset
addresses = {
    sec.name: offset_to_addr(sec["sh_offset"]) for sec in e.iter_sections()
}
if len(addresses) != e.num_sections():
    raise AssertionError("duplicate section names")

h = hex
real_unhex = unhex
unhex = lambda d, **kw: real_unhex(d.replace(" ", "") if isinstance(d, str) else d, **kw)

from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
