#!/usr/bin/env python3

import argparse
import pefile
import lief
from pathlib import Path
import elftools.elf.elffile as elffile
import elftools.dwarf.dwarfinfo as dwarfinfo

def ParseArgs():
    parser = argparse.ArgumentParser(prog='SymbolStopper', description='Checks to see if the provided file has debug information.')

    parser.add_argument('Filepath')

    return parser.parse_args()

def DoesPEFileHaveDebugInfo(peFile):
    if hasattr(peFile, 'DIRECTORY_ENTRY_DEBUG'):
        return True

def DoesCOFFFileHaveDebugInfo(coffFile):
    return False

def DoesELFFileHaveDebugInfo(elfFile):
    return True

def CrackFile(file, byteCount):
    byteList = []
    with file.open('rb') as f:
        for _ in range(byteCount):
            byteList.append(f.read(1))
        return byteList

def DoesFileHaveDebugInfo(inFile):
    if ".map" in inFile.name or ".dmp" in inFile.name:
        return True

    pe = pefile.PE(inFile, fast_load=True)
    if pe.is_exe() or pe.is_dll() or pe.is_driver():
        return DoesPEFileHaveDebugInfo(pe)
    
    byteStr = str(CrackFile(inFile, 100))
    if "Microsoft C/C++" in byteStr and ("MSF 7.00" in byteStr or "program database 2.00" in byteStr):
        return True    #Likely a PDB file
    
    COFFMagic = int.from_bytes(CrackFile(inFile, 4), 'little')
    if COFFMagic == 332 or COFFMagic == 34404 or COFFMagic == 512:
        return DoesCOFFFileHaveDebugInfo(inFile)
    
    ELFMagic = int.from_bytes(CrackFile(inFile, 8), 'little')
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
