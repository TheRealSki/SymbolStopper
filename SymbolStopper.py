#!/usr/bin/env python3

import argparse
import pefile
from pathlib import Path
import elftools.elf.elffile as elffile
import elftools.dwarf.dwarfinfo as dwarfinfo

def ParseArgs():
    parser = argparse.ArgumentParser(prog='SymbolStopper', description='Checks to see if the provided file has debug information.')

    parser.addargument('Filepath')

    return parser.parse_args()

def DoesPEFileHaveDebugInfo(peFile):
    return True

def DoesCOFFFileHaveDebugInfo(coffFile):
    return True

def DoesELFFileHaveDebugInfo(elfFile):
    return True

def CrackFile(file, byteCount):
    byteList = []
    with file.open('rb') as f:
        for 0 to byteCount:
            byteList.push_back(f.readbyte())
        return byteList.to_array()

def DoesFileHaveDebugInfo(inFile):
    pe = pefile.PE(inFile, fast_load=True)
    if pe.is_exe() or pe.is_dll() or pe.is_driver():
        return DoesPEFileHaveDebugInfo(pe)
    
    byteStr = str(CrackFile(inFile, 4))
    if "Microsoft C/C++" in byteStr and ("MSF 7.00" in byteStr or "program database 2.00" in byteStr):
        return True    #Likely a PDB file
    COFFMagic = int(CrackFile(inFile, 4))
    if COFFMagic == 332 or COFFMagic == 34404 or COFFMagic == 512:
        return DoesCOFFFileHaveDebugInfo(inFile)
    if ".map" in inFile.name or ".dmp" in inFile.name:
        return True
    ELFMagic = int(CrackFile(inFile, 8))
    if ELFMagic == 1179403647:
        return DoesELFFileHaveDebugInfo(inFile)
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
