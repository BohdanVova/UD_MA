#in this script
#i store in json file the following information:
#file type, all sections, all infotmation about headers and all strings

import pefile
import os
import json
import sys
from pathlib import Path
path =  "C:\\NewTest"
result = {}
result['Name directory'] = path
def check(path):
    results = []
    for i in os.listdir(path): #start recursive scan
        if os.path.isdir(path+'\\'+i):
            print("let's go down")
        if os.path.isfile(path+'\\'+i):
            if Path(path+'\\'+i).suffix == '.exe': #check if the file is exe
                pe = pefile.PE(path+'\\'+i) 
                results.append({ 
                i : Path(path+'\\'+i).suffix,
                }) #save file type information
                for section in pe.sections:
                    results.append({section.Name.decode().rstrip('\x00') : #save all information about sections
                    "\n|\n|---- Vitual Size : " 
                    + hex(section.Misc_VirtualSize) 
                    + "\n|\n|---- VirutalAddress : " 
                    + hex(section.VirtualAddress)
                    + "\n|\n|---- SizeOfRawData : " 
                    + hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " 
                    + hex(section.PointerToRawData) + "\n|\n|---- Characterisitcs : "
                    + hex(section.Characteristics)+'\n',})
                results.append({"all headers information" : str(pe)})  #save all information about headers
    result['data about files'] = results
    with open('C:\\NewTest\data.json', 'w') as jsonFile:
        json.dump(result, jsonFile)
    for i in os.listdir(path):
        if os.path.isfile(path+'\\'+i):
            if Path(path+'\\'+i).suffix == '.exe':
                stringsData = os.system(r"strings "+ (path+'\\'+i) + r">> data.json") #save all information about strings
check(path)