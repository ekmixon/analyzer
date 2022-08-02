'''
    __G__ = "(G)bd249ce4"
    yara -> yara
'''

from os import path
from glob import glob
from copy import deepcopy
from yara import compile as ycompile
from analyzer.logger.logger import log_string, verbose, ignore_excpetion
from analyzer.settings import default_colors


class YaraParser:
    '''
    YaraParser for running and handling yara rules
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting YaraParser")
    def __init__(self):
        '''
        initialize class and datastruct, this has to pass
        '''
        self.datastruct = {"Matches": [],
                           "Tags": [],
                           "_Matches": ["Count", "Offset", "Rule", "Patteren", "Parsed", "Condition"],
                           "__Tags": ["namespace", "rule", "meta"]}

        self.yarapath = path.abspath(path.join(path.dirname(__file__), 'rules'))
        if not self.yarapath.endswith(path.sep):
            self.yarapath = self.yarapath + path.sep
        self.yararules = glob(f"{self.yarapath}*.yar")
        self.yararulenamelist = {}
        self._set = {}
        for rule in self.yararules:
            head, tail = path.split(rule)
            self._set[tail.split(".")[0]] = rule
        self.rules = ycompile(filepaths=self._set)
        for rule in self.yararules:
            temp_x = [line.strip() for line in open(rule, 'r')]
            for i in range(len(temp_x)):
                if temp_x[i].startswith("rule ") and temp_x[i + 1] == "{":
                    rule = temp_x[i].split(" ")[1]
                elif temp_x[i] == "condition:" and rule != "":
                    self.yararulenamelist.update({rule: temp_x[i + 1]})
                    rule = ""

        self.yara_path_tags = path.abspath(path.join(path.dirname(__file__), 'rules-master'))
        if not self.yara_path_tags.endswith(path.sep):
            self.yara_path_tags = self.yara_path_tags + path.sep
        self.yara_rules_tags = glob(f"{self.yara_path_tags}*.yar")
        self._set_tags = {}
        for rule in self.yara_rules_tags:
            head, tail = path.split(rule)
            self._set_tags[tail.split(".")[0]] = rule
        self.rules_tags = ycompile(filepaths=self._set_tags)

    @verbose(True, verbose_output=False, timeout=None, _str="Checking with yara rules")
    def checkwithyara(self, data, parsed, check=""):
        '''
        check file with compiled yara detection and append results into list
        '''
        data["Yara"] = deepcopy(self.datastruct)
        if parsed.full or parsed.tags:
            log_string("Finding yara tags", "Green")
            matches = self.rules_tags.match(data["Location"]["File"])
            if len(matches) > 0:
                list_of_matches = []
                for match in matches:
                    full_rule = f"{match.namespace}:{match.rule}"
                    if full_rule not in list_of_matches:
                        list_of_matches.append(full_rule)
                        color = None
                        with ignore_excpetion(Exception):
                            color = default_colors[match.namespace]
                        data["Yara"]["Tags"].append(
                            {
                                "fullrule": full_rule,
                                "namespace": match.namespace,
                                "color": color,
                                "rule": match.rule,
                                "meta": '\n'.join(
                                    f"{key}: {match.meta[key]}"
                                    for key in match.meta
                                ),
                            }
                        )


        if parsed.full or parsed.yara:
            matches = self.rules.match(data["Location"]["File"])
            log_string("Finding yara matches", "Green")
            if len(matches) > 0:
                for match in matches:
                    temp = {}
                    for _match in match.strings:
                        key = f"{match.namespace}:{match}"
                        ppattern = "None"
                        good_exe = False
                        with ignore_excpetion(Exception):
                            pattern = _match[2].decode("utf-8", errors="ignore")
                            good_exe = True
                        if not good_exe:
                            with ignore_excpetion(Exception):
                                pattern = ''.join('\\x{:02x}'.format(x) for x in _match[2])
                                ppattern = _match[2].decode("ascii", "replace")
                        if pattern in temp:
                            temp[pattern][0] += 1
                            temp[pattern][1].append(hex(_match[0]))
                        elif match.rule in self.yararulenamelist:
                            temp[pattern] = [
                                0,
                                [hex(_match[0])],
                                str(match),
                                ppattern,
                                self.yararulenamelist[match.rule],
                            ]

                    for item, value in temp.items():
                        data["Yara"]["Matches"].append(
                            {
                                "Count": value[0],
                                "Offset": " ".join(temp[item][1]),
                                "Rule": temp[item][2],
                                "Patteren": item,
                                "Parsed": temp[item][3],
                                "Condition": temp[item][4],
                            }
                        )
