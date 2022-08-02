'''
    __G__ = "(G)bd249ce4"
    modules -> apk
'''

from re import sub
from xml.dom.minidom import parseString
from r2pipe import open as r2open
from analyzer.logger.logger import ignore_excpetion, verbose
from analyzer.modules.archive import check_packed_files, unpack_file
from analyzer.mics.funcs import get_words_multi_files, get_words
from analyzer.intell.qbdescription import add_description


class ApkParser:
    '''
    ApkParser extract artifacts from apk files
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting ApkParser")
    def __init__(self):
        '''
        initialize class, this has to pass
        '''
        self.sus = ["encrypt", "decrypt", "http:", "https", "sudo", "password", "pass", "admin", "loadLibrary", "isEmulator"]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def execute_with_swtich(self, r2p, switch, _str) -> list:
        '''
        wrapper
        '''
        if _str == "":
            return r2p.cmd(f"{switch}~+{_str}").split("\n")
        temp_string = "".join(r2p.cmd(f"{switch}~+{_}") for _ in _str)
        return temp_string.split("\n")

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def xref(self, r2p, line) -> list:
        '''
        get refes
        '''
        temp_string = ""
        with ignore_excpetion(Exception):
            add = line.split(" ")[0]
            int(add, 0)
            temp_string = r2p.cmd(f"pd 1 @  {add}~XREF")
        return temp_string.split("\n")

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_all_classes(self, r2p) -> list:
        '''
        get all classes from dex using icq command
        '''
        return [
            {"Type": "Class", "Name": _}
            for _ in self.execute_with_swtich(r2p, "icq", "")
            if _ != ""
        ]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_all_externals(self, r2p) -> list:
        '''
        get all externals from dex using iiq command
        '''
        return [
            {"Type": "External", "Name": _}
            for _ in self.execute_with_swtich(r2p, "iiq", "")
            if _ != ""
        ]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_all_symbols(self, r2p) -> list:
        '''
        get all symbols from dex using isq command
        '''
        temp_list = []
        for _ in self.execute_with_swtich(r2p, "isq", ""):
            if _ != "":
                add, temp_x, name = _.split(" ")
                temp_list.append({"Type": "Symbol", "Address": add, "X": temp_x, "Name": name})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def big_functions(self, r2p) -> list:
        '''
        get all big functions from dex using aflj command
        '''
        return [
            {"Size": item["size"], "Name": item["name"]}
            for item in r2p.cmdj("aflj")
            if item["size"] > 64
        ]

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sus(self, r2p) -> list:
        '''
        check if suspicious strings in class, externals or symbols
        '''
        temp_list = []
        for _ in self.execute_with_swtich(r2p, "icq", self.sus):
            for __ in self.xref(r2p, _):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ') + 1:]
                    temp_list.append({"Location": "Classes", "Function": _, "Xrefs": xref})
        for _ in self.execute_with_swtich(r2p, "iiq", self.sus):
            for __ in self.xref(r2p, _):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ') + 1:]
                    temp_list.append({"Location": "Externals", "Function": _, "Xrefs": xref})
        for _ in self.execute_with_swtich(r2p, "isq", self.sus):
            for __ in self.xref(r2p, _):
                if _ != "" and __ != "":
                    xref = __[__.rfind(' from ') + 1:]
                    temp_list.append({"Location": "Symbols", "Function": _, "Xrefs": xref})
        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def read_apk_package(self, _path) -> str:
        '''
        read apk permission by by xml (if xml is not compressed)
        '''
        with open(_path, 'r', encoding="utf-8") as file:
            data = file.read()
            dom = parseString(data)
            nodes = dom.getElementsByTagName('manifest')
            return nodes[0].getAttribute("package")

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def read_permissions(self, data, _path) -> list:
        '''
        read apk permission by regex..
        '''
        temp_list = []
        temp_f = data["FilesDumps"][_path]
        text = sub(rb'[^\x20-\x7e]{2,}', b' ', temp_f)
        text = sub(rb'[^\x20-\x7e]{1,}', b'', text)
        text = sub(rb'[^\w\. ]', b'', text)
        if words := text.decode("utf-8", errors="ignore").split(" "):
            temp_list.extend(
                {"Permission": item, "Description": ""}
                for item in words
                if "permission." in item
            )

        return temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig_apk(self, data) -> bool:
        '''
        check if mime is an apk type or if file contains Androidmanifest in packed files
        '''
        if data["Details"]["Properties"]["mime"] in [
            "application/java-archive",
            "application/zip",
        ] and check_packed_files(
            data["Location"]["File"], ["Androidmanifest.xml"]
        ):
            unpack_file(data, data["Location"]["File"])
            return True
        return False

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig_dex(self, data) -> bool:
        '''
        check if mime is a dex
        '''
        return bool(
            data["Details"]["Properties"]["mime"] == "application/octet-stream"
            and data["Location"]["Original"].endswith(".dex")
        )

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing DEX file")
    def dex_wrapper(self, data, r2p, index):
        data[index] = {"Classes": [],
                       "Externals": [],
                       "Symbols": [],
                       "Bigfunctions": [],
                       "Suspicious": [],
                       "_Classes": ["Type", "Name"],
                       "_Externals": ["Type", "Name"],
                       "_Symbols": ["Type", "Address", "X", "Name"],
                       "_Bigfunctions": ["Size", "Name"],
                       "_Suspicious": ["Location", "Function", "Xrefs"]}
        data[index]["Classes"] = self.get_all_classes(r2p)
        data[index]["Externals"] = self.get_all_externals(r2p)
        data[index]["Symbols"] = self.get_all_symbols(r2p)
        data[index]["Bigfunctions"] = self.big_functions(r2p)
        data[index]["Suspicious"] = self.check_sus(r2p)

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing DEX file")
    def analyze_dex(self, data):
        '''
        start analyzing dex logic (r2p timeout = 10) for individual dex
        add description to strings, get words and wordsstripped from the dex
        '''
        r2p = r2open(data["Location"]["File"], flags=['-2'])
        r2p.cmd("e anal.timeout = 5")
        r2p.cmd("aaaa;")
        self.dex_wrapper(data, r2p, 'APK_DEX_1')
        get_words(data, data["Location"]["File"])
        r2p.quit()

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing APK file")
    def analyze_apk(self, data):
        '''
        start analyzing apk logic (r2p timeout = 10) for all dex files
        add description to strings, get words and wordsstripped from the packed files
        '''
        data["APK"] = {"General": {},
                       "Permissions": [],
                       "_General": {},
                       "_Permissions": ["Permission", "Description"]}
        for index, item in enumerate(data["Packed"]["Files"]):
            if item["Name"].lower() == "androidmanifest.xml":
                # self.readpepackage(v["Path"])
                data["APK"]["Permissions"] = self.read_permissions(data, item["Path"])
            if "classes" in item["Name"].lower() and item["Name"].lower().endswith(".dex"):
                r2p = r2open(item["Path"], flags=['-2'])
                r2p.cmd("e anal.timeout = 5")
                r2p.cmd("aaaa;")
                self.dex_wrapper(data, r2p, f'APK_DEX_{index}')
        add_description("AndroidPermissions", data["APK"]["Permissions"], "Permission")
        get_words_multi_files(data, data["Packed"]["Files"])
        r2p.quit()
