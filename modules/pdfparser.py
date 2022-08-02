'''
    __G__ = "(G)bd249ce4"
    modules -> pdf
'''

from zlib import decompress
from copy import deepcopy
from re import DOTALL, MULTILINE, findall
from re import compile as rcompile
from magic import from_buffer
from analyzer.logger.logger import verbose
from analyzer.mics.funcs import get_words_multi_filesarray, get_words


class PDFParser:
    '''
    PDFParser extracts artifacts from pdf files
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting PDFParser")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"Count": {},
                           "Object": [],
                           "Stream": [],
                           "JS": [],
                           "Javascript": [],
                           "OpenAction": [],
                           "Launch": [],
                           "URI": [],
                           "Action": [],
                           "GoTo": [],
                           "RichMedia": [],
                           "AA": [],
                           "_Count": {},
                           "_Object": ["Object", "Value"],
                           "_Stream": ["Stream", "Parsed", "Value"],
                           "_JS": ["Key", "Value"],
                           "_Javascript": ["Key", "Value"],
                           "_Launch": ["Key", "Value"],
                           "_OpenAction": ["Key", "Value"],
                           "_URI": ["Key", "Value"],
                           "_Action": ["Key", "Value"],
                           "_GoTo": ["Key", "Value"],
                           "_RichMedia": ["Key", "Value"],
                           "_AA": ["Key", "Value"]}

        self.objectsdetection = rcompile(br'(\d+\s\d)+\sobj([\s\S]*?\<\<([\s\S]*?))endobj', DOTALL | MULTILINE)
        self.streamdetection = rcompile(br'.*?FlateDecode.*?stream(.*?)endstream', DOTALL | MULTILINE)
        self.jsdetection = rcompile(br'/JS([\S][^>]+)', DOTALL | MULTILINE)
        self.javascriptdetection = rcompile(br'/JavaScript([\S][^>]+)', DOTALL | MULTILINE)
        self.openactiondetection = rcompile(br'/OpenAction([\S][^>]+)', DOTALL | MULTILINE)
        self.launchdetection = rcompile(br'/Launch([\S][^>]+)', DOTALL | MULTILINE)
        self.uridetection = rcompile(br'/URI([\S][^>]+)', DOTALL | MULTILINE)
        self.actiondetection = rcompile(br'/Action([\S][^>]+)', DOTALL | MULTILINE)
        self.gotodetection = rcompile(br'/GoTo([\S][^>]+)', DOTALL | MULTILINE)
        self.richmediadetection = rcompile(br'/RichMedia([\S][^>]+)', DOTALL | MULTILINE)
        self.aadetection = rcompile(br'/AA([\S][^>]+)', DOTALL | MULTILINE)

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_object(self, pdf) -> (str, list):
        '''
        get objects from pdf by regex
        '''
        objects_list = findall(self.objectsdetection, pdf)
        temp_list = [
            {
                "Object": _[0].decode("utf-8", errors="ignore"),
                "Value": _[1].decode('utf-8', errors="ignore"),
            }
            for _ in objects_list
        ]

        return len(objects_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_stream(self, pdf) -> (str, list, list):
        '''
        get streams from pdf by regex
        '''
        temp_list = []
        streams_list = []
        streams = findall(self.streamdetection, pdf)
        for _ in streams:
            parsed = None
            parseddecode = None
            temp_x = _.strip(b"\r").strip(b"\n")
            mime = from_buffer(temp_x, mime=True)
            if mime == "application/zlib":
                parsed = decompress(temp_x)
                parseddecode = parsed.decode("utf-8", errors="ignore")
                streams_list.append(parsed)
            temp_list.append({"Stream": mime, "Parsed": parseddecode, "Value": temp_x.decode('utf-8', errors="ignore")})
        return len(streams), temp_list, streams_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_js(self, pdf) -> (str, list):
        '''
        get JS from pdf by regex
        '''
        jslist = findall(self.jsdetection, pdf)
        temp_list = [
            {"Key": "/JS", "Value": _.decode("utf-8", errors="ignore")}
            for _ in jslist
        ]

        return len(jslist), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_javascript(self, pdf) -> (str, list):
        '''
        get JavaScript from pdf by regex
        '''
        javascript_list = findall(self.javascriptdetection, pdf)
        temp_list = [
            {"Key": "/JavaScript", "Value": _.decode("utf-8", errors="ignore")}
            for _ in javascript_list
        ]

        return len(javascript_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_openaction(self, pdf) -> (str, list):
        '''
        get openactions from pdf by regex
        '''
        open_action_list = findall(self.openactiondetection, pdf)
        temp_list = [
            {"Key": "/OpenAction", "Value": _.decode("utf-8", errors="ignore")}
            for _ in open_action_list
        ]

        return len(open_action_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_lunch(self, pdf) -> (str, list):
        '''
        get Launch from pdf by regex
        '''
        launch_list = findall(self.launchdetection, pdf)
        temp_list = [
            {"Key": "/Launch", "Value": _.decode("utf-8", errors="ignore")}
            for _ in launch_list
        ]

        return len(launch_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_uri(self, pdf) -> (str, list):
        '''
        get URI from pdf by regex
        '''
        uri_list = findall(self.uridetection, pdf)
        temp_list = [
            {"Key": "/URI", "Value": _.decode("utf-8", errors="ignore")}
            for _ in uri_list
        ]

        return len(uri_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_action(self, pdf) -> (str, list):
        '''
        get Action from pdf by regex
        '''
        action_list = findall(self.actiondetection, pdf)
        temp_list = [
            {"Key": "/Action", "Value": _.decode("utf-8", errors="ignore")}
            for _ in action_list
        ]

        return len(action_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_gotor(self, pdf) -> (str, list):
        '''
        get GoToR from pdf by regex
        '''
        goto_list = findall(self.gotodetection, pdf)
        temp_list = [
            {"Key": "/GoToR", "Value": _.decode("utf-8", errors="ignore")}
            for _ in goto_list
        ]

        return len(goto_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_richmedia(self, pdf) -> (str, list):
        '''
        get RichMedia from pdf by regex
        '''
        richmedia_list = findall(self.richmediadetection, pdf)
        temp_list = [
            {"Key": "/RichMedia", "Value": _.decode("utf-8", errors="ignore")}
            for _ in richmedia_list
        ]

        return len(richmedia_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def get_aa(self, pdf) -> (str, list):
        '''
        get AA from pdf by regex
        '''
        aa_list = findall(self.aadetection, pdf)
        temp_list = [
            {"Key": "/AA", "Value": _.decode("utf-8", errors="ignore")}
            for _ in aa_list
        ]

        return len(aa_list), temp_list

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def check_sig(self, data) -> bool:
        '''
        check if mime is pdf
        '''
        return data["Details"]["Properties"]["mime"] == "application/pdf"

    @verbose(True, verbose_output=False, timeout=None, _str="Analyzing PDF file")
    def analyze(self, data):
        '''
        start analyzing pdf logic, get pdf objects,
        get words and wordsstripped from buffers if streams exist
        otherwise get words and wordsstripped from file
        '''
        streams_list = []
        data["PDF"] = deepcopy(self.datastruct)
        temp_f = data["FilesDumps"][data["Location"]["File"]]
        objlen, objs = self.get_object(temp_f)
        strlen, strs, streams_list = self.get_stream(temp_f)
        jslen, jslist = self.get_js(temp_f)
        jalen, jaslist = self.get_javascript(temp_f)
        oalen, oalist = self.get_openaction(temp_f)
        llen, llist = self.get_lunch(temp_f)
        ulen, ulist = self.get_uri(temp_f)
        alen, alist = self.get_action(temp_f)
        gtrlen, gtrlist = self.get_gotor(temp_f)
        rmlen, rmlist = self.get_richmedia(temp_f)
        aalen, aalist = self.get_aa(temp_f)

        data["PDF"]["Count"] = {"Object": objlen,
                                "Stream": strlen,
                                "JS": jslen,
                                "Javascript": jalen,
                                "OpenAction": oalen,
                                "Launch": llen,
                                "URI": ulen,
                                "Action": alen,
                                "GoTo": gtrlen,
                                "RichMedia": rmlen,
                                "AA": aalen}

        data["PDF"]["Object"] = objs
        data["PDF"]["JS"] = jslist
        data["PDF"]["Javascript"] = jaslist
        data["PDF"]["OpenAction"] = oalist
        data["PDF"]["Launch"] = llist
        data["PDF"]["URI"] = ulist
        data["PDF"]["Action"] = alist
        data["PDF"]["GoTo"] = gtrlist
        data["PDF"]["RichMedia"] = rmlist
        data["PDF"]["AA"] = aalist
        data["PDF"]["Stream"] = strs

        if len(streams_list) > 0:
            get_words_multi_filesarray(data, streams_list)
        else:
            get_words(data, streams_list)
