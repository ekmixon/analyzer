'''
    __G__ = "(G)bd249ce4"
    modules -> linux
'''

from copy import deepcopy
from hashlib import md5
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_symbol_type
from elftools.elf.sections import SymbolTableSection
from analyzer.logger.logger import verbose
from analyzer.mics.funcs import get_entropy, get_words, get_entropy_float_ret
from analyzer.intell.qbdescription import add_description


class LinuxELF:
    '''
    HTMLParser extract artifacts from linux
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting LinuxELF")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"General": {},
                           "Sections": [],
                           "Dynamic": [],
                           "Symbols": [],
                           "Relocations": [],
                           "_General": {},
                           "_Sections": ["Section", "Suspicious", "Size", "Entropy", "MD5", "Description"],
                           "_Dynamic": ["Needed", "Description"],
                           "_Symbols": ["Type", "Symbol", "Description"],
                           "_Relocations": ["Section", "Name", "Description"]}

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_relocations(self, elf) -> list:
        '''
        get symbols locations
        '''
        temp_list = []
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                symboltable = elf.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    symbol = symboltable.get_symbol(relocation['r_info_sym'])
                    # address = hex(relocation['r_offset']) section['sh_flags']  section['sh_type']
                    # some have no names, need to check this out
                    if symbol.name != "":
                        temp_list.append({"Section": section.name,
                                          "Name": symbol.name,
                                          "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_symbols(self, elf) -> list:
        '''
        get symbols and types
        '''
        temp_list = []
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            temp_list.extend(
                {
                    "Type": describe_symbol_type(symbol['st_info']['type']),
                    "Symbol": symbol.name,
                    "Description": "",
                }
                for symbol in section.iter_symbols()
                if len(symbol.name) > 0
            )

            return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_dynamic(self, elf) -> list:
        '''
        get dynamic libraries
        '''
        temp_list = []
        section = elf.get_section_by_name('.dynamic')
        if section is not None:
            temp_list.extend(
                {"Needed": tag.needed, "Description": ""}
                for tag in section.iter_tags()
                if tag.entry.d_tag == "DT_NEEDED"
            )

        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_section(self, elf) -> list:
        '''
        get all sections of elf
        '''
        temp_list = []
        for section in elf.iter_sections():
            if section.name != "":
                sus = "No"
                entropy = get_entropy_float_ret(section.data())
                if entropy > 6 or (0 <= entropy <= 1):
                    sus = f"True, {entropy}"
                elif section.data_size == 0:
                    sus = "True, section size 0"
                temp_list.append({"Section": section.name,
                                  "Suspicious": sus,
                                  "Size": section.data_size,
                                  "MD5": md5(section.data()).hexdigest(),
                                  "Entropy": get_entropy(section.data()),
                                  "Description": ""})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_iter(self, elf) -> str:
        '''
        get run-time linker
        '''
        return next(
            (
                segment.get_interp_name()
                for segment in elf.iter_segments()
                if segment['p_type'] == 'PT_INTERP'
            ),
            "",
        )

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if mime is linux type
        '''
        return data["Details"]["Properties"]["mime"] in [
            "application/x-pie-executable",
            "application/x-sharedlib",
            "application/x-executable",
        ]

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing ELF file")
    def analyze(self, data):
        '''
        start analyzing elf logic, add description to strings and get words and wordsstripped from the file
        '''
        with open(data["Location"]["File"], 'rb') as file_1, open(data["Location"]["File"], 'rb') as file_2:
            data["ELF"] = deepcopy(self.datastruct)
            elf = ELFFile(file_1)
            data["ELF"]["General"] = {"ELF Type": elf.header.e_type,
                                      "ELF Machine": elf.header.e_machine,
                                      "Entropy": get_entropy(file_2.read()),
                                      "Entrypoint": hex(elf.header.e_entry),
                                      "Interpreter": self.get_iter(elf)}
            data["ELF"]["Sections"] = self.get_section(elf)
            data["ELF"]["Dynamic"] = self.get_dynamic(elf)
            data["ELF"]["Symbols"] = self.get_symbols(elf)
            data["ELF"]["Relocations"] = self.get_relocations(elf)
            add_description("ManHelp", data["ELF"]["Symbols"], "Symbol")
            add_description("LinuxSections", data["ELF"]["Sections"], "Section")
            get_words(data, data["Location"]["File"])
