####################################################
## tsa4ida.py - rule based function profiler
## Created by alexander<dot>hanel<at>gmail<dot>com
## Version 1.0 - Thanks to PNX, Kernel Sanders and CB. 
## To do 
## Use Yara to replace ConfigParer
##     [status] - Yara can not sucessefully be imported via IDAPython
####################################################

import ConfigParser
import idautils
import idc
import os
import re

class Profiler():    
    def __init__(self, config_filename=None):
        self.config_filename = "sigs.ini"
        if config_filename:
            self.config_filename = config_filename
        self.script_file_path = \
            os.path.realpath(__file__)[:os.path.realpath(__file__).rfind(os.sep) + 1]
        self.error = False
        self.function_eas = []
        self.getFunctions()
        self.parser = ConfigParser.SafeConfigParser()
        self.comment = False
        self.rename = False
        self.parseConfig()

    def getFunctions(self):
        'get a lit of function addresses'
        for func in idautils.Functions():
            # Ignore Library Code
            flags = GetFunctionFlags(func)
            if flags & FUNC_LIB:
                continue
            self.function_eas.append(func)

    def getInstructions(self, function):
        'get all instruction in a function'
        buff = ''
        for x in idautils.FuncItems(function):
            buff = buff + idc.GetDisasm(x) + '\n'
        return buff

    def addToFunction(self, address, comment):
        'add comment to function or rename function'
        if self.rename == True:
            if comment not in idc.GetFunctionName(address):
                idc.MakeNameEx(address, str(comment) + str('_') + idc.GetFunctionName(address), idc.SN_NOWARN)
        if self.comment == True:
            curCmt = idc.GetFunctionCmt(address,1)
            if comment not in curCmt:
                comment = comment + ' ' + curCmt
                idc.SetFunctionCmt(address, comment, 1)
        return

    def parseConfig(self):
        'parse the the configs file'
        try:
            with open(self.script_file_path + os.sep + self.config_filename) as f: pass
        except IOError as e:
            print 'Error: Could not find sigs.ini'
            self.error = True
            return 
        if not os.path.isfile(self.script_file_path + os.sep + self.config_filename):
            print 'Error: Could not find sigs.ini'
            self.error = True
            return
        try:
            self.parser.read(self.script_file_path + os.sep + self.config_filename)
        except ConfigParser.ParsingError, err:
            print 'Error: Could not parse %s', err
            self.error = True
            return

    def getRuleNames(self):
        'gets name of all the rules in the config'  
        rules = []
        for rule in self.parser.sections():
            rules.append(rule)
        return rules

    def checkValues(self, buffer, section_name): 
        'run rules against instruction buffer'
        is_value_present = False
        values = []
        regexs = []
        # Get values from the rules
        for x, value in self.parser.items(section_name):
            if 'regex' in x:
                regexs.append(value)
            else:
                values.append(value)
        # check if values are in the instruction buffer
        for item in values:
            if item in buffer:   
                is_value_present = True
            else:
                return False
            if not item in values:
                return False
        # We can return because there are no regexs 
        if len(regexs) == 0:
            return True
        for item in regexs:
            try:
                regex = re.compile(item,re.S)
            except Exception:
                print "Error: Invalid Regular Expression Pattern"
                continue 
            test =  re.search(regex, buffer) 
            if re.search(regex, buffer) == None:
                return False    
        return True

    def run(self):
        'showtime..'
        if self.error is True:
            return
        print '_Status: Started'
        # loop through each function
        for function_addr in self.function_eas:
            instBuffer = self.getInstructions(function_addr)
            # loop through each rule
            for section_name in self.parser.sections():
                status = self.checkValues(instBuffer, section_name)
                if status == True:
                    self.addToFunction(function_addr, section_name)
                    print "Rule:", section_name, "found at", hex(function_addr)
        print '_Status: Completed'
        return

if __name__ == '__main__':
    profiler = Profiler()
    profiler.comment = True
    profiler.rename = False
    profiler.run()
