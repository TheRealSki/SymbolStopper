#!/usr/bin/env python3

import argparse
import lief
from pathlib import Path

InvalidFileTypes = [".map", ".dmp", ".o", ".obj", ".pdb"]

def ParseArgs():
    parser = argparse.ArgumentParser(prog='SymbolStopper', description='Checks to see if the provided file has debug information.')

    parser.add_argument('Filepath')

    return parser.parse_args()

def DoesPEFileHaveDebugInfo(peFile : lief.PE.Binary | None):
    if peFile == None:
        return False
    
    if peFile.has_debug:
        return True
    
    diSec = peFile.get_section('.debug_info')
    if diSec != None and diSec.sizeof_raw_data > 0:
        return True
    
    dSec = peFile.get_section('.debug')
    if dSec != None and dSec.sizeof_raw_data > 0:
        return True
    
    # If the size of the optional header is 0, then the file is an object file.
    if peFile.header.sizeof_optional_header == 0:
        return True

    # 0x0200 is IMAGE_FILE_DEBUG_STRIPPED
    if peFile.header.characteristics & 0x0200 != 0:
        return True
    
    return False

def DoesELFFileHaveDebugInfo(elfFile):
    if elfFile.has_debug:
        return True
    
    if any(section.name.startswith('.debug') and section.size > 0 for section in elfFile.sections):
        return True

    return False

def CrackFile(file, byteCount):
    byteList = []
    with file.open('rb') as f:
        for _ in range(byteCount):
            byteList.append(f.read(1))
        return byteList

def DoesFileHaveDebugInfo(inFile):
    if any(inFile.name.endswith(ext) for ext in InvalidFileTypes):
        return True

    byteStr = str(CrackFile(inFile, 100))
    if "Microsoft C/C++" in byteStr and ("MSF 7.00" in byteStr or "program database 2.00" in byteStr):
        return True    #Likely a PDB file
    
    liefFile = lief.parse(inFile)
    if liefFile == None:
        return False
    elif liefFile.format == lief.PE:
        return DoesPEFileHaveDebugInfo(lief.PE.parse(inFile))
    elif liefFile.format == lief.ELF:
        return DoesELFFileHaveDebugInfo(lief.ELF.parse(inFile))
    elif liefFile.format == lief.dwarf:
        return True
    
    #If we get here, then we need to check if the file is an object file (COFF) but not named as one.
    COFFMagic = int.from_bytes(CrackFile(inFile, 4), 'little')
    if COFFMagic == 332 or COFFMagic == 34404 or COFFMagic == 512:
        return True
    
    return False

if __name__ == "__main__":
    args = ParseArgs()
    file = Path(args.Filepath)
    if file.is_file():
        if DoesFileHaveDebugInfo(file):
            quit(-3)
    else:
        quit(-2)
else:
    quit(-1)
