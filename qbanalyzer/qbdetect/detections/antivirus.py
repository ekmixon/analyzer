__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from re import I, compile, finditer

detections = {"Antimalware" : [r"360hotfix\.exe|360rpt\.exe|360safe\.exe|360safebox\.exe|360tray\.exe|agentsvr\.exe|apvxdwin\.exe|ast\.exe|avcenter\.exe|avengine\.exe|avgnt\.exe|avguard\.exe|avltmain\.exe|avp\.exe|avp32\.exe|avtask\.exe|bdagent\.exe|bdwizreg\.exe|boxmod\.exe|ccapp\.exe|ccenter\.exe|ccevtmgr\.exe|ccregvfy\.exe|ccsetmgr\.exe|egui\.exe|ekrn\.exe|extdb\.exe|frameworkservice\.exe|frwstub\.exe|guardfield\.exe|iparmor\.exe|kaccore\.exe|kasmain\.exe|kav32\.exe|kavstart\.exe|kavsvc\.exe|kavsvcui\.exe|kislnchr\.exe|kissvc\.exe|kmailmon\.exe|knownsvr\.exe|kpfw32\.exe|kpfwsvc\.exe|kregex\.exe|kvfw\.exe|kvmonxp\.exe|kvol\.exe|kvprescan\.exe|kvsrvxp\.exe|kvwsc\.exe|kwatch\.exe|livesrv\.exe|makereport\.exe|mcagent\.exe|mcdash\.exe|mcdetect\.exe|mcshield\.exe|mctskshd\.exe|mcvsescn\.exe|mcvsshld\.exe|mghtml\.exe|naprdmgr\.exe|navapsvc\.exe|navapw32\.exe|navw32\.exe|nmain\.exe|nod32\.exe|nod32krn\.exe|nod32kui\.exe|npfmntor\.exe|oasclnt\.exe|pavsrv51\.exe|pfw\.exe|psctrls\.exe|psimreal\.exe|psimsvc\.exe|qqdoctormain\.exe|ras\.exe|ravmon\.exe|ravmond\.exe|ravstub\.exe|ravtask\.exe|rfwcfg\.exe|rfwmain\.exe|rfwproxy\.exe|rfwsrv\.exe|rsagent\.exe|rsmain\.exe|rsnetsvr\.exe|rssafety\.exe|rstray\.exe|safebank\.exe|safeboxtray\.exe|scan32\.exe|scanfrm\.exe|sched\.exe|seccenter\.exe|secnotifier\.exe|SetupLD\.exe|shstat\.exe|smartup\.exe|sndsrvc\.exe|spbbcsvc\.exe|symlcsvc\.exe|tbmon\.exe|uihost\.exe|ulibcfg\.exe|updaterui\.exe|uplive\.exe|vcr32\.exe|vcrmon\.exe|vptray\.exe|vsserv\.exe|vstskmgr\.exe|webproxy\.exe|xcommsvr\.exe|xnlscn\.exe|Application Data\\Agnitum|Application Data\\avg10|Application Data\\avg8|Application Data\\avg9|Application Data\\Avira|Application Data\\Doctor Web|Application Data\\ESET|Application Data\\f-secure|Application Data\\G DATA|Application Data\\Kaspersky Lab|Application Data\\McAfee|Application Data\\Microsoft\\Microsoft Antimalware|Application Data\\PC Tools|Application Data\\Symantec|Application Data\\Trend Micro|All Users\\AVAST Software|Local SettingsApplication Data\\F-Secure|Program Files\\Agnitum|Program Files\\Alwil Software|Program Files\\AVAST Software|Program Files\\AVG|Program Files\\Avira|Program Files\\BitDefender9|Program Files\\Common Files\\Doctor Web|Program Files\\Common Files\\G DATA|Program Files\\Common Files\\PC Tools|Program Files\\DrWeb|Program Files\\ESET|Program Files\\F-Secure Internet Security|Program Files\\FRISK Software|Program Files\\Kaspersky Lab|Program Files\\McAfee|Program Files\\Microsoft Security Essentials|Program Files\\Norton AntiVirus|Program Files\\Panda Security|Program Files\\PC Tools Internet Security|Program Files\\Symantec|Program Files\\Trend Micro|Program Files\\Vba32|Program Files (x86)\\Agnitum|Program Files (x86)\\Alwil Software|Program Files (x86)\\AVAST Software|Program Files (x86)\\AVG|Program Files (x86)\\Avira|Program Files (x86)\\BitDefender9|Program Files (x86)\\Common Files\\Doctor Web|Program Files (x86)\\Common Files\\G DATA|Program Files (x86)\\Common Files\\PC Tools|Program Files (x86)\\DrWeb|Program Files (x86)\\ESET|Program Files (x86)\\F-Secure Internet Security|Program Files (x86)\\Kaspersky Lab|Program Files (x86)\\McAfee|Program Files (x86)\\Microsoft Security Essentials|Program Files (x86)\\Norton AntiVirus|Program Files (x86)\\Panda Security|Program Files (x86)\\PC Tools Internet Security|Program Files (x86)\\Symantec|Program Files (x86)\\Trend Micro|Program Files (x86)\\Vba32"]}

@progressbar(True,"Check Anti-Malware")
def startanalyzing(data):
	for detectonroot in detections:
		for detection in detections[detectonroot]:
			temp = {}
			for match in finditer(compile(detection,I), data["StringsRAW"]["wordsstripped"]):
				if match.group() in temp:
					temp[match.group()][0] += 1
				else:
					temp.update({match.group():[1,[]]})
				temp[match.group()][1].append("{}-{}".format(hex(match.span()[0]),hex(match.span()[1])))
			for match in temp:
				data["QBDETECT"]["Detection"].append({"Count":temp[match][0],"Offset":" ".join(temp[match][1]),"Rule":"Anti-Malware","Match":match,"Parsed":None})