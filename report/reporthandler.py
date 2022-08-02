'''
    __G__ = "(G)bd249ce4"
    reports -> report
'''

from datetime import datetime
from analyzer.logger.logger import log_string, verbose
from analyzer.mics.funcs import open_in_browser, serialize_obj
from analyzer.report.htmlmaker import HtmlMaker
from analyzer.report.jsonmaker import JSONMaker
from analyzer.intell.qbimage import QBImage
from analyzer.intell.qbicons import QBIcons
from analyzer.connections.mongodbconn import add_item_fs
from analyzer.settings import defaultdb


class ReportHandler:
    '''
    ReportHandler for handling final reports
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting ReportHandler")
    def __init__(self):
        '''
        initialize html and json report classes, this has to pass
        '''
        self.htmlmaker = HtmlMaker(QBImage, QBIcons)
        self.jsonmaker = JSONMaker()

    @verbose(True, verbose_output=False, timeout=None, _str=None)
    def save_output(self, data, renderedhtml, parsed):
        '''
        save output to file or database
        '''
        if len(data) <= 0:
            return
        if parsed.db_result:
            serialize_obj(data)
            #temp_id = add_item("tasks", "results", dataserialized)
            # if temp_id:
            #    log_string("JSON result added to db", "Yellow")
            # else:
            #    log_string("Unable to add JSON result to db", "Red")
        temp_id = None
        if parsed.db_dump_json:
            datajson = self.jsonmaker.dump_json_and_return(data)
            if temp_id := add_item_fs(
                defaultdb["dbname"],
                defaultdb["reportscoll"],
                datajson,
                data["Details"]["Properties"]["md5"],
                data["Details"]["Properties"],
                parsed.uuid,
                "application/json",
                datetime.now(),
            ):
                log_string("JSON result dumped into db", "Yellow")
            else:
                log_string("Unable to dump JSON result to db", "Red")
            temp_es = None
            if temp_es:
                log_string("JSON result dumped into elastic", "Yellow")
            else:
                log_string("Unable to dump JSON result to elastic", "Red")
        if parsed.db_dump_html:
            datajson = self.jsonmaker.dump_json_and_return(data)
            if temp_id := add_item_fs(
                defaultdb["dbname"],
                defaultdb["reportscoll"],
                renderedhtml,
                data["Details"]["Properties"]["md5"],
                data["Details"]["Properties"],
                parsed.uuid,
                "text/html",
                datetime.now(),
            ):
                log_string("HTML result dumped into db", "Yellow")
            else:
                log_string("Unable to dump HTML result to db", "Red")

    @verbose(True, verbose_output=False, timeout=None, _str="Parsing and cleaning output")
    def check_output(self, data, parsed):
        '''
        start saving output logic
        '''
        renderedhtml = "Error"
        if parsed.db_dump_html or parsed.disk_dump_html:
            renderedhtml = self.htmlmaker.render_template(data, None, None, parsed, True)
            log_string(f'Generated Html file {data["Location"]["html"]}', "Yellow")
        if parsed.db_dump_json or parsed.disk_dump_json or parsed.print_json:
            data = serialize_obj(data)  # force this <--- incase some value returned with object of type 'NoneType' has no len
            self.jsonmaker.clean_data(data)
        if parsed.disk_dump_json and self.jsonmaker.dump_json(data):
            log_string(f'Generated JSON file {data["Location"]["json"]}', "Yellow")
            if parsed.open:
                open_in_browser(data["Location"]["json"])
        if parsed.print_json:
            self.jsonmaker.print_json(data)
        self.save_output(data, renderedhtml, parsed)
