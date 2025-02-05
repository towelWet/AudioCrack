#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tkinter as tk
from tkinter import filedialog, messagebox
import binascii
import platform
import pefile
import lief
from capstone import *
from keystone import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
import struct
import shutil
import difflib
import subprocess

# ------------------
# 🆕 BEGIN PATCH
# ------------------
import torch
import torch.serialization
import numpy as np

# Safelist the scalar global from older NumPy
torch.serialization.add_safe_globals({np.core.multiarray.scalar})

# Monkey-patch torch.load to revert the default to full unpickling
_old_load = torch.load

def _new_load(*args, **kwargs):
    if 'weights_only' not in kwargs:
        kwargs['weights_only'] = False
    return _old_load(*args, **kwargs)

torch.load = _new_load
# ------------------
# 🆕 END PATCH
# ------------------

import obfuscation_detection as od


############################################################
#                   REGISTRATION .REG LOGIC
############################################################

def expected_reg(file_path):
    """
    Generates a mock .reg content for demonstration.
    Works primarily with PE-based files (EXE, DLL, VST3, AAX).
    For Mach-O (AU / .component on macOS), does a partial fallback.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Attempt to parse with pefile (Windows/PE-based)
        # If it fails, we catch the error and try LIEF for Mach-O
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()
        except pefile.PEFormatError:
            # If it's not a valid PE, see if it's Mach-O
            # We'll do only minimal info
            binary = lief.parse(file_path)
            # The below is just a fallback for Mach-O / .component
            return f"REG_ADD UnknownAudioPlugin MachOFileVersion {binary.name}\n"

        # Attempt to retrieve "ProductName" and "ProductVersion" from VS_VERSIONINFO
        product_name = None
        product_version = None
        if hasattr(pe, 'VS_VERSIONINFO') and pe.VS_VERSIONINFO:
            for fileinfo in pe.FileInfo:
                if hasattr(fileinfo, 'StringTable'):
                    for st in fileinfo.StringTable:
                        if 'ProductName' in st.entries:
                            product_name = st.entries['ProductName']
                        if 'ProductVersion' in st.entries:
                            product_version = st.entries['ProductVersion']
                        if product_name and product_version:
                            break

        if not product_name:
            product_name = "UnknownProduct"
        if not product_version:
            product_version = "0.0.0"

        # Identify keys for registration. As an example, check PE sections containing "REG_"
        keys = []
        if hasattr(pe, 'sections'):
            for entry in pe.sections:
                if entry.Name.startswith(b"REG_"):
                    raw_key = entry.Name.decode(errors='ignore').strip('\x00')
                    key_part = raw_key[4:]
                    if key_part:
                        keys.append(key_part)

        reg_file = ""
        for key in keys:
            reg_file += f"REG_ADD {key} {product_name} {product_version}\n"

        if not reg_file:
            reg_file = f"No registration keys found for {product_name} {product_version}."

        return reg_file

    except Exception as e:
        print(e)
        return None


def generate_expected_reg(file_path):
    """Generates the expected format for a valid .reg file based on the target plugin/software's registration scheme."""
    reg_file = expected_reg(file_path)
    if reg_file is not None:
        with open(file_path + ".reg", "w") as f:
            f.write(reg_file)
        messagebox.showinfo("Expected Reg", "The expected .reg file has been generated.")
    else:
        messagebox.showinfo("Expected Reg", "The target software does not have a valid registration scheme.")


############################################################
#                 RARUN2 CONFIG LOGIC
############################################################

def create_rarun2_config(args, env_vars, config_file_name):
    """
    Creates a rarun2 configuration file.

    Parameters:
        args (list of str): A list of arguments for the program.
        env_vars (dict): A dictionary of environment variables for the program.
        config_file_name (str): The name of the configuration file to be saved.

    Returns:
        None
    """
    program_path = os.path.realpath(__file__)
    config_file_path = os.path.join(os.path.dirname(program_path), config_file_name)

    with open(config_file_path, 'w') as file:
        file.write(f"#!/usr/bin/rarun2\nprogram={program_path}\n")

        for i, arg in enumerate(args):
            file.write(f"arg{i + 1}={arg}\n")

        for var, value in env_vars.items():
            file.write(f"setenv={var}={value}\n")


# Example usage of create_rarun2_config
args = ["arg1", "arg2"]
env_vars = {"ENV_VAR": "value"}
config_file_name = "config.rr2"
create_rarun2_config(args, env_vars, config_file_name)


############################################################
#                  OBFUSCATION / DEOBFUSCATION
############################################################

def run_radare2_command(binary_file, command):
    radare2_command = f"r2 -q0 {binary_file} -c '{command};q'"
    result = subprocess.run(radare2_command, shell=True, capture_output=True)
    return result.stdout.decode()


def automatic_deobfuscation(binary_file):
    """
    Automatically detects and reports common obfuscation techniques in the provided binary or plugin file.

    Parameters:
        binary_file (str): The path to the file to be analyzed.

    Returns:
        result (str): The analysis result.
    """
    disassembly = run_radare2_command(binary_file, 'aaa;pdf')

    result = ""
    if 'jmp eax' in disassembly or 'jmp [eax]' in disassembly:
        result += "Potential control flow obfuscation detected: computed jump.\n"
    if 'add eax,' in disassembly and 'sub eax,' in disassembly:
        result += "Potential data obfuscation detected: sequences of arithmetic operations.\n"
    if 'xlat' in disassembly:
        result += "Potential instruction obfuscation detected: rarely used instructions.\n"

    if result == "":
        result = "No common obfuscation techniques detected."

    messagebox.showinfo("Deobfuscation", result)
    return result


############################################################
#                      BINARY DIFFING
############################################################

def binary_diffing(binary_file_1, binary_file_2):
    """
    Compares two binary/plugin files and finds differences between them.

    Parameters:
        binary_file_1 (str): The path to the first file.
        binary_file_2 (str): The path to the second file.
    """
    cmd = ["diffoscope", binary_file_1, binary_file_2]
    result = subprocess.run(cmd, capture_output=True, text=True)
    differences = result.stdout

    if result.stderr.strip() != "":
        differences += "\nErrors or warnings:\n" + result.stderr

    if not differences.strip():
        differences = "The files are identical."

    message_window = tk.Toplevel()
    message_window.title("Binary Diffing Results")

    text_widget = tk.Text(message_window)
    text_widget.pack(fill='both', expand=True)
    text_widget.insert('1.0', differences)


############################################################
#               BINARY / PLUGIN ANALYSIS REPORT
############################################################

def binary_analysis_report(file_path, root):
    """
    Generates a simple analysis report of the file. 
    Supports .exe, .dll, .vst3, .aax (PE-based), .component (Mach-O), .app, etc.
    """
    report_window = tk.Toplevel(root)
    report_window.title("Binary Analysis Report")
    report = ""

    # Parsers keyed by extension
    # .component / .app / .au -> typically Mach-O. .aax could be PE or Mach-O. 
    # We'll attempt to parse with LIEF and see if we get a valid object.
    parsers = {
        '.exe': lief.PE.parse,
        '.dll': lief.PE.parse,
        '.vst3': lief.PE.parse,
        '.aax': lief.PE.parse,   # Some AAX may be Mach-O if on mac. We'll attempt PE first.
        '.component': lief.MachO.parse,  # Audio Unit on mac
        '.app': lief.MachO.parse,
    }

    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in parsers:
            binary = parsers[ext](file_path)
            parts = [str(binary.header)]
            if hasattr(binary, 'sections'):
                parts.extend(str(s) for s in binary.sections)
            if hasattr(binary, 'symbols'):
                parts.extend(str(sym) for sym in binary.symbols)
            report = "\n".join(parts)
        else:
            # Fallback: try LIEF parse
            try:
                fallback_bin = lief.parse(file_path)
                parts = [str(fallback_bin.header)]
                if hasattr(fallback_bin, 'sections'):
                    parts.extend(str(s) for s in fallback_bin.sections)
                if hasattr(fallback_bin, 'symbols'):
                    parts.extend(str(sym) for sym in fallback_bin.symbols)
                report = "\n".join(parts)
            except Exception:
                report = "Unsupported file type or parse error."
    except Exception as e:
        report = f"Failed to generate report: {str(e)}"

    report_label = tk.Label(report_window, text=report)
    report_label.pack()


############################################################
#               CODE CAVES: FIND & CREATE
############################################################

def find_code_cave(file_path, entry_widget):
    """
    Finds a 100-byte code cave in a PE-based file. If not PE, returns 'No code cave found.'
    """
    try:
        pe = pefile.PE(file_path)
        desired_size = 100
        found_offset = None

        for section in pe.sections:
            data = section.get_data()
            counter = 0
            start_index = None
            for i in range(len(data)):
                if data[i:i+1] in [b'\x00', b'\x90']:
                    counter += 1
                    if start_index is None:
                        start_index = i
                else:
                    counter = 0
                    start_index = None
                if counter == desired_size:
                    section_start_in_file = section.PointerToRawData
                    found_offset = section_start_in_file + (i - desired_size + 1)
                    break
            if found_offset is not None:
                break

        if found_offset is None:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, "No code cave found.")
        else:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, hex(found_offset))
    except Exception as e:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, "Error: " + str(e))


def create_code_cave(file_path, entry_widget):
    """
    Appends 100 NOP instructions to the end of the file.
    """
    try:
        with open(file_path, "ab") as file:
            file.write(b"\x90" * 100)
        if entry_widget:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, "Code cave created at EOF.")
    except Exception as e:
        if entry_widget:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, "Error: " + str(e))


############################################################
#                 ANTI-DEBUGGING DETECTION
############################################################

def identify_anti_debugging_techniques(file_path):
    """
    Searches for known anti-debugging imports (e.g. IsDebuggerPresent) in PE files.
    For Mach-O, returns partial message.
    """
    results = []
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name == b'IsDebuggerPresent':
                        results.append("IsDebuggerPresent detected in imports.")
    except pefile.PEFormatError:
        try:
            lief.parse(file_path)
            results.append("Mach-O or other format - anti-debug checks not implemented.")
        except Exception:
            results.append("File is neither valid PE nor parseable by LIEF.")
    except Exception as e:
        results.append(f"Error scanning for anti-debugging: {str(e)}")

    if not results:
        results.append("No known anti-debugging techniques found.")
    return results


def display_results(results):
    new_window = tk.Toplevel()
    new_window.title("Anti-Debugging Techniques")

    text_widget = tk.Text(new_window)
    text_widget.insert(tk.END, '\n'.join(results))
    text_widget.pack()
    new_window.focus_set()


############################################################
#                    TLS CALLBACKS
############################################################

def interact_tls_callbacks(file_path, tls_callbacks_entry):
    try:
        pe = pefile.PE(file_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            tls_callbacks_entry.delete(0, tk.END)
            tls_callbacks_entry.insert(0, "No TLS section found.")
            return

        callback_array_rva = pe.get_rva_from_offset(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
        index = 0
        results = []
        while True:
            data_bytes = pe.get_data(callback_array_rva + index * 4, 4)
            if not data_bytes:
                break
            callback_rva = pe.get_dword_from_data(data_bytes, 0)
            if callback_rva == 0:
                break
            results.append(f"TLS callback at RVA {hex(callback_rva)}")
            index += 1

        if results:
            tls_callbacks_entry.delete(0, tk.END)
            tls_callbacks_entry.insert(0, "; ".join(results))
        else:
            tls_callbacks_entry.delete(0, tk.END)
            tls_callbacks_entry.insert(0, "No TLS callbacks found.")
    except Exception as e:
        tls_callbacks_entry.delete(0, tk.END)
        tls_callbacks_entry.insert(0, "Error: " + str(e))


############################################################
#                    EXPORT TABLE
############################################################

def interact_export_table(file_path, export_table_entry):
    """
    Tries to parse as PE, gather exports, and display them.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(f"{exp.name} at {hex(exp.address)}")
            export_table_entry.delete(0, tk.END)
            export_table_entry.insert(0, "; ".join(str(e) for e in exports if e))
        else:
            export_table_entry.delete(0, tk.END)
            export_table_entry.insert(0, "No export table found.")
    except pefile.PEFormatError:
        export_table_entry.delete(0, tk.END)
        export_table_entry.insert(0, "Invalid PE file.")
    except Exception as e:
        export_table_entry.delete(0, tk.END)
        export_table_entry.insert(0, "Error: " + str(e))


############################################################
#                    RESOURCE TABLE
############################################################

def interact_resource_table(file_path, resource_table_entry):
    """
    Lists resource table contents (PE only).
    """
    try:
        pe = pefile.PE(file_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_table_entry.delete(0, tk.END)
            resource_table_entry.insert(0, "No resource table found.")
            return

        results = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = None
            if resource_type.name is not None:
                type_name = resource_type.name
            else:
                type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if resource_type.directory is not None:
                for resource_id in resource_type.directory.entries:
                    if resource_id.name is not None:
                        results.append(f"{type_name} -> {resource_id.name}")
                    else:
                        results.append(f"{type_name} -> ID {resource_id.struct.Id}")
        if results:
            resource_table_entry.delete(0, tk.END)
            resource_table_entry.insert(0, "; ".join(results))
        else:
            resource_table_entry.delete(0, tk.END)
            resource_table_entry.insert(0, "No entries in resource table.")
    except Exception as e:
        resource_table_entry.delete(0, tk.END)
        resource_table_entry.insert(0, "Error: " + str(e))


############################################################
#                   SECTION TABLE
############################################################

def interact_section_table(file_path, section_table_entry):
    """
    Displays a list of PE sections.
    """
    try:
        pe = pefile.PE(file_path)
        results = []
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            size = section.SizeOfRawData
            results.append(f"Section: {name}, Size: {size}")
        if results:
            section_table_entry.delete(0, tk.END)
            section_table_entry.insert(0, "; ".join(results))
        else:
            section_table_entry.delete(0, tk.END)
            section_table_entry.insert(0, "No sections found.")
    except Exception as e:
        section_table_entry.delete(0, tk.END)
        section_table_entry.insert(0, "Error: " + str(e))


############################################################
#                  RELOCATION TABLE
############################################################

def interact_relocation_table(file_path, relocation_table_entry):
    """
    Shows relocation table for PE files.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            relocs = []
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in base_reloc.entries:
                    relocs.append(hex(entry.rva))
            if relocs:
                relocation_table_entry.delete(0, tk.END)
                relocation_table_entry.insert(0, ", ".join(relocs))
            else:
                relocation_table_entry.delete(0, tk.END)
                relocation_table_entry.insert(0, "No relocation entries found.")
        else:
            relocation_table_entry.delete(0, tk.END)
            relocation_table_entry.insert(0, "No relocation table found.")
    except pefile.PEFormatError:
        relocation_table_entry.delete(0, tk.END)
        relocation_table_entry.insert(0, "Invalid PE file.")
    except Exception as e:
        relocation_table_entry.delete(0, tk.END)
        relocation_table_entry.insert(0, "Error: " + str(e))


############################################################
#                       OVERLAY
############################################################

def interact_overlay(file_path, overlay_entry):
    """
    Attempts to locate and extract the overlay data from a PE file.
    """
    try:
        pe = pefile.PE(file_path)
        offset = pe.get_overlay_data_start_offset()
        if offset is not None:
            overlay = pe.get_overlay()
            out_file = f"{file_path}_overlay"
            with open(out_file, "wb") as overlay_file:
                overlay_file.write(overlay)
            overlay_entry.delete(0, tk.END)
            overlay_entry.insert(0, f"Overlay found at offset {hex(offset)}. Extracted to {out_file}")
        else:
            overlay_entry.delete(0, tk.END)
            overlay_entry.insert(0, "No overlay found.")
    except pefile.PEFormatError:
        overlay_entry.delete(0, tk.END)
        overlay_entry.insert(0, "Invalid PE file.")
    except Exception as e:
        overlay_entry.delete(0, tk.END)
        overlay_entry.insert(0, "Error: " + str(e))


############################################################
#                ENTRY POINT, OEP, ETC.
############################################################

def identify_entry_point(binary, root):
    """
    Identifies the entry point of a PE file. 
    If Mach-O/AAX/.component, won't do anything (placeholder).
    """
    try:
        pe = pefile.PE(binary)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        root.delete(0, tk.END)
        root.insert(0, hex(entry_point))
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file or non-PE plugin.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_oep(file_path, oep_entry):
    """
    Original Entry Point detection for a typical PE. 
    Not strictly accurate for a packed file, but workable placeholder.
    """
    try:
        pe = pefile.PE(file_path)
        oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        oep_entry.delete(0, tk.END)
        oep_entry.insert(tk.END, hex(oep))
    except Exception as e:
        oep_entry.delete(0, tk.END)
        oep_entry.insert(tk.END, "Error: " + str(e))


############################################################
#                 DUMP & UNPACK LOGIC
############################################################

def dump_unpacked_executable(file_path, unpacked_file_path_entry):
    """
    Reads the file, does a placeholder "unpacking", 
    and saves the result to <file_path>_unpacked.
    """
    try:
        with open(file_path, "rb") as packed_file:
            packed_data = packed_file.read()

        # Replace with real unpack logic
        unpacked_data = packed_data

        unpacked_file_path = file_path + "_unpacked"
        with open(unpacked_file_path, "wb") as unpacked_file:
            unpacked_file.write(unpacked_data)

        unpacked_file_path_entry.delete(0, tk.END)
        unpacked_file_path_entry.insert(0, f"Dumped to {unpacked_file_path}")
    except Exception as e:
        unpacked_file_path_entry.delete(0, tk.END)
        unpacked_file_path_entry.insert(0, "Error: " + str(e))


def unpack_binary(file_path, root):
    """
    Placeholder for an actual unpacking routine. 
    Just copies the file to a new location for demonstration.
    """
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "The specified file does not exist.")
        return

    root.withdraw()
    export_folder = filedialog.askdirectory(title="Select folder")
    root.deiconify()

    if not os.path.isdir(export_folder):
        messagebox.showerror("Error", "The specified export folder does not exist.")
        return

    base_name, ext = os.path.splitext(os.path.basename(file_path))
    new_name = base_name + "_unpacked" + ext
    new_path = os.path.join(export_folder, new_name)
    shutil.copy2(file_path, new_path)
    print("Binary unpacked successfully.")


############################################################
#                 IMPORT TABLE ADDRESSES
############################################################

def identify_import_table_rva(file_path, import_table_rva_entry):
    """
    Attempts to parse a PE file and show the import table RVA.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            import_rva = pe.DIRECTORY_ENTRY_IMPORT.struct.VirtualAddress
            import_table_rva_entry.delete(0, tk.END)
            import_table_rva_entry.insert(tk.END, hex(import_rva))
        else:
            import_table_rva_entry.delete(0, tk.END)
            import_table_rva_entry.insert(tk.END, "No import table found.")
    except Exception as e:
        import_table_rva_entry.delete(0, tk.END)
        import_table_rva_entry.insert(0, "Error: " + str(e))


def fix_dump(file_path):
    """
    Example fix for a dumped PE, tries to fill missing import addresses.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.address == 0:
                        print(f"Fixing import: {imp.name}")
                        imp.address = 0x1000
        out_path = f"{file_path}_fixed"
        pe.write(out_path)
        messagebox.showinfo("Fix Dump", f"Saved fixed dump to {out_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


############################################################
#             IDENTIFY IMPORT TABLE / FIRST THUNK
############################################################

def identify_import_table(binary, root):
    """
    Lists the DLL names from the import table of a PE.
    """
    try:
        pe = pefile.PE(binary)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            names = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT]
            root.delete(0, tk.END)
            root.insert(0, ", ".join(names))
        else:
            messagebox.showwarning("Warning", "No import table found.")
    except pefile.PEFormatError:
        messagebox.showerror("Error", "Invalid PE file or non-PE plugin.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def identify_import_descriptor(file_path, root):
    """
    Lists function names from all import descriptors in a PE.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            all_imports = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.imports:
                    for i in entry.imports:
                        if i.name:
                            all_imports.append(i.name.decode('utf-8'))
            if all_imports:
                root.delete(0, tk.END)
                root.insert(0, ", ".join(all_imports))
            else:
                root.delete(0, tk.END)
                root.insert(0, "No imports found in descriptor.")
        else:
            root.delete(0, tk.END)
            root.insert(0, "No import table found.")
    except Exception as e:
        root.delete(0, tk.END)
        root.insert(0, f"Error: {str(e)}")


def identify_first_thunk(file_path, root):
    """
    Shows the 'thunk' values in the import table.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            first_thunk_entries = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    first_thunk_entries.append(hex(imp.thunk))
            root.delete(0, tk.END)
            root.insert(0, ", ".join(first_thunk_entries))
        else:
            root.delete(0, tk.END)
            root.insert(0, "No import table found.")
    except Exception as e:
        root.delete(0, tk.END)
        root.insert(0, "Error: " + str(e))


def identify_original_first_thunk(file_path, root):
    """
    Shows the 'original_first_thunk' values in the import table.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            of_t_entries = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    of_t_entries.append(hex(imp.original_first_thunk))
            root.delete(0, tk.END)
            root.insert(0, ", ".join(of_t_entries))
        else:
            root.delete(0, tk.END)
            root.insert(0, "No import table found.")
    except Exception as e:
        root.delete(0, tk.END)
        root.insert(0, "Error: " + str(e))


def identify_ilt(file_path, ilt_entry):
    """
    Quickly tries to show the first original_first_thunk from the import table.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            rva = pe.DIRECTORY_ENTRY_IMPORT[0].original_first_thunk
            ilt_entry.delete(0, tk.END)
            ilt_entry.insert(tk.END, hex(rva))
        else:
            ilt_entry.delete(0, tk.END)
            ilt_entry.insert(tk.END, "No import table found.")
    except Exception as e:
        ilt_entry.delete(0, tk.END)
        ilt_entry.insert(tk.END, "Error: " + str(e))


############################################################
#               MODIFY UNPACKING STUB / RESTORE IAT
############################################################

def modify_unpacking_stub(file_path, entry_widget):
    """
    Example: modifies first byte of file to 0x90 (NOP).
    """
    try:
        with open(file_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x90")
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, "Unpacking stub modified (first byte -> NOP).")
    except Exception as e:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, "Error: " + str(e))


def restore_iat(file_path, entry_widget):
    """
    Sets all 'thunk' addresses to 'original_first_thunk'.
    """
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imp.thunk = imp.original_first_thunk
            output = file_path + "_iat_restored"
            pe.write(output)
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, f"IAT restored -> {output}")
        else:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, "No import table found.")
    except Exception as e:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, "Error: " + str(e))


############################################################
#                      OFFSET CALCS
############################################################

def calculate_rva(file_path, entry):
    """
    Example: RVA = entry_point - image_base for a PE file.
    """
    try:
        pe = pefile.PE(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        rva = entry_point - pe.OPTIONAL_HEADER.ImageBase
    except Exception as e:
        rva = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, rva)


def calculate_iat(file_path, entry):
    """
    Gets the IAT RVA and size from the data directory if present.
    """
    try:
        pe = pefile.PE(file_path)
        iat_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].VirtualAddress
        iat_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]].Size
    except Exception as e:
        iat_rva = str(e)
        iat_size = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, f"RVA: {iat_rva}, Size: {iat_size}")


def calculate_ita(file_path, entry):
    """
    Gets the Import Table Address and size from the data directory if present.
    """
    try:
        pe = pefile.PE(file_path)
        ita_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].VirtualAddress
        ita_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]].Size
    except Exception as e:
        ita_rva = str(e)
        ita_size = str(e)

    entry.delete(0, tk.END)
    entry.insert(0, f"RVA: {ita_rva}, Size: {ita_size}")


def calculate_import_table(file_path, entry):
    """
    Gets the import table's DLL list.
    """
    try:
        pe = pefile.PE(file_path)
        import_table = [en.dll for en in pe.DIRECTORY_ENTRY_IMPORT]
    except Exception as e:
        import_table = str(e)

    entry.delete(0, tk.END)
    if isinstance(import_table, list):
        entry.insert(0, ", ".join(i.decode() for i in import_table))
    else:
        entry.insert(0, import_table)


############################################################
#                SEARCH STRING IN BINARY
############################################################

def get_code_section_start_offset(file_path):
    """
    Attempts to get the start offset of the first code section in a file 
    (for demonstration).
    """
    if platform.system() == "Windows":
        pe = pefile.PE(file_path)
        return pe.sections[0].VirtualAddress
    elif platform.system() == "Darwin":
        binary = lief.parse(file_path)
        return binary.segments[0].virtual_address
    else:
        raise NotImplementedError("Unsupported OS.")


def find_conditional_jump_offset(data, string_offset, code_section_start_offset):
    cs = Cs(CS_ARCH_X86, CS_MODE_32)  # Switch to 64-bit if needed
    cs.detail = True
    jmp_instructions = [
        "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jmp"
    ]

    for i in range(string_offset, code_section_start_offset, -1):
        instruction_bytes = data[i - 15 : i]
        instructions = list(cs.disasm(instruction_bytes, i - 15))
        if instructions:
            last_instruction = instructions[-1]
            if last_instruction.mnemonic in jmp_instructions:
                return last_instruction.address
    return None


def search_string_in_binary(file_path, string_to_search, bad_boy_offset_entry, output_text):
    """
    Searches for a given string in both UTF-8 and UTF-16 inside the file.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        string_to_search_bytes_utf8 = string_to_search.encode("utf-8")
        string_to_search_bytes_utf16 = string_to_search.encode("utf-16")[2:]  # skip BOM

        for encoding, string_to_search_bytes in [
            ("utf-8", string_to_search_bytes_utf8),
            ("utf-16", string_to_search_bytes_utf16),
        ]:
            start_index = 0
            found_indices = []
            while start_index < len(data):
                index = data.find(string_to_search_bytes, start_index)
                if index != -1:
                    found_indices.append(hex(index))
                    start_index = index + 1
                else:
                    break

            output_text.insert(tk.END, f"Search results for '{string_to_search}' in {encoding}:\n")
            if found_indices:
                for offset_str in found_indices:
                    offset = int(offset_str, 16)
                    terminator = b"\x00\x00" if encoding == "utf-16" else b"\x00"
                    end_of_string = data.find(terminator, offset)
                    if end_of_string == -1:
                        end_of_string = len(data)
                    string_contents = data[offset:end_of_string]
                    try:
                        string_contents = string_contents.decode(encoding, errors="replace")
                    except:
                        pass
                    output_text.insert(tk.END, f"Found at offset: {offset_str}\n", "hex")
                    output_text.insert(tk.END, f"String Contents: {string_contents}\n")

                    bad_boy_offset_entry.delete(0, tk.END)
                    bad_boy_offset_entry.insert(0, offset_str)

                    code_section_start = get_code_section_start_offset(file_path)
                    jmp_offset = find_conditional_jump_offset(data, offset, code_section_start)
                    if jmp_offset is not None:
                        output_text.insert(tk.END, f"Found conditional jump at offset: {hex(jmp_offset)}\n", "hex")
            else:
                output_text.insert(tk.END, "String not found.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")


############################################################
#                   PATCH BINARY
############################################################

def patch_binary(file_path, offset, new_instruction, offset_base, arch_mode, root):
    """
    Uses Keystone to assemble new_instruction and patch the file at 'offset'.
    """
    if arch_mode == "32-bit":
        mode = KS_MODE_32
    elif arch_mode == "64-bit":
        mode = KS_MODE_64
    else:
        raise ValueError("Invalid architecture mode")

    offset = int(offset, offset_base)

    try:
        ks = Ks(KS_ARCH_X86, mode)
        encoding, _ = ks.asm(new_instruction)
        new_instruction_machine_code = bytes(encoding)

        with open(file_path, "rb") as f:
            data = bytearray(f.read())

        for i, byte_val in enumerate(new_instruction_machine_code):
            data[offset + i] = byte_val

        with open(file_path, "wb") as f:
            f.write(data)

        messagebox.showinfo("Success", "File patched successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=root)


############################################################
#              BROWSE FILES (Add AAX / COMPONENT)
############################################################

def browse_files(file_path_entry):
    """
    Lets the user browse for a file. Supports .exe, .dll, .vst3, .aax, .component, etc.
    """
    try:
        file_path_entry.delete(0, tk.END)
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Executable Files", "*.exe"),
                ("DLL Files", "*.dll"),
                ("VST3 Files", "*.vst3"),
                ("AAX Files", "*.aax"),
                ("AU Component Files", "*.component"),
                ("App Files", "*.app"),
                ("All Files", "*.*"),
            ]
        )
        file_path_entry.insert(0, file_path)

        _, file_extension = os.path.splitext(file_path)
        file_extension = file_extension.lower()

        # Attempt to parse or at least check validity
        if file_extension in [".exe", ".dll", ".vst3", ".aax"]:
            # Typically PE-based on Windows, or could be Mach-O if on mac (AAX).
            # We'll attempt pefile if on Windows, else we do a quick fallback
            try:
                if platform.system() == "Windows":
                    pe = pefile.PE(file_path)
                    print("Loaded PE successfully, sections:")
                    for sec in pe.sections:
                        print(sec.Name)
                else:
                    # macOS fallback for AAX
                    binary = lief.parse(file_path)
                    print("Loaded file on non-Windows system (maybe Mach-O).")
            except Exception as e:
                print("An error occurred:", str(e))
        elif file_extension == ".component":
            # Typically an Audio Unit (Mach-O)
            try:
                binary = lief.parse(file_path)
                print("Loaded Mach-O .component")
            except Exception as e:
                print("Unable to parse .component:", e)
        elif file_extension == ".app":
            # macOS .app
            if platform.system() == "Darwin":
                app_name = os.path.splitext(os.path.basename(file_path))[0]
                executable_path = os.path.join(file_path, "Contents", "MacOS", app_name)
                file_path_entry.delete(0, tk.END)
                file_path_entry.insert(0, executable_path)
                try:
                    binary = lief.parse(executable_path)
                    print("Loaded Mach-O from .app")
                except Exception as e:
                    print("Unable to parse .app:", e)
            else:
                print(".app files are typically for macOS only.")
        else:
            print("Generic or unsupported file extension chosen.")
    except Exception as e:
        print("An error occurred:", str(e))


############################################################
#                READ INSTRUCTION (CAPSTONE)
############################################################

def read_instruction(
    file_path,
    offset,
    instruction,
    bin_entry,
    hex_entry,
    dec_entry,
    offset_base,
    arch_mode
):
    """
    Reads and disassembles the instruction at the specified offset.
    """
    try:
        with open(file_path, "rb") as f:
            offset = int(offset, offset_base)
            f.seek(offset)
            raw_bytes = f.read(16)
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
        return
    except ValueError:
        messagebox.showerror("Error", "Invalid offset.")
        return
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    if arch_mode == "32-bit":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch_mode == "64-bit":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        messagebox.showerror("Error", "Invalid architecture mode.")
        return

    found_instruction = False
    for ins in md.disasm(raw_bytes, 0x1000):
        instruction.delete(0, tk.END)
        instruction.insert(0, f"{ins.mnemonic} {ins.op_str}")
        found_instruction = True
        # Convert to binary/decimal/hex
        binary_str = " ".join(f"{b:08b}" for b in raw_bytes)
        decimal_str = " ".join(str(b) for b in raw_bytes)
        hex_str = " ".join(f"{b:02x}" for b in raw_bytes)

        bin_entry.delete(0, tk.END)
        bin_entry.insert(0, binary_str)

        dec_entry.delete(0, tk.END)
        dec_entry.insert(0, decimal_str)

        hex_entry.delete(0, tk.END)
        hex_entry.insert(0, hex_str)
        break

    if not found_instruction:
        messagebox.showerror("Error", "Unable to disassemble instruction.")


############################################################
#                 OFFSET CALCULATOR
############################################################

def calculate_offset(base_virt_addr_entry, base_file_offset_entry, instr_virt_addr_entry):
    """
    Example method for calculating file offsets given base addresses.
    """
    try:
        base_virt_addr = base_virt_addr_entry.get().strip()
        base_file_offset = base_file_offset_entry.get().strip()
        if not base_virt_addr or not base_file_offset:
            raise ValueError("Base Virtual Address and Base File Offset fields must be filled in")

        base_virt_addr = int(base_virt_addr, 16)
        base_file_offset = int(base_file_offset, 16)
        instr_virt_addr = base_virt_addr + base_file_offset

        instr_virt_addr_entry.delete(0, tk.END)
        instr_virt_addr_entry.insert(tk.END, hex(instr_virt_addr))
    except Exception as e:
        messagebox.showerror("Error", str(e))


def calculate_base_va(file_path, base_va_entry):
    """
    Example: get the ImageBase from a PE's optional header.
    """
    try:
        pe = pefile.PE(file_path)
        base_va = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        base_va_entry.delete(0, tk.END)
        base_va_entry.insert(tk.END, hex(base_va))
    except Exception as e:
        base_va_entry.delete(0, tk.END)
        base_va_entry.insert(tk.END, "Error: " + str(e))


def calculate_base_offset(file_path, base_offset_entry):
    """
    Example: get the PointerToRawData from the first section in a PE file.
    """
    try:
        pe = pefile.PE(file_path)
        section = pe.sections[0]
        base_offset = section.PointerToRawData
        pe.close()
        base_offset_entry.delete(0, tk.END)
        base_offset_entry.insert(tk.END, hex(base_offset))
    except Exception as e:
        base_offset_entry.delete(0, tk.END)
        base_offset_entry.insert(tk.END, "Error: " + str(e))


def open_offset_calculator(file_path_entry):
    new_window = tk.Toplevel()
    new_window.title("Offset Calculator")
    new_window.geometry("1300x300")

    tk.Label(
        new_window,
        text=(
            "Base Virtual Address: The starting memory address of the section. "
            "You can find this in the section headers in Ghidra."
        ),
    ).grid(row=0, column=0, columnspan=2)

    tk.Label(
        new_window,
        text=(
            "Base File Offset: The starting file offset of the section. "
            "You can find this in the section headers in Ghidra."
        ),
    ).grid(row=1, column=0, columnspan=2)

    tk.Label(
        new_window,
        text=(
            "Instruction Virtual Address: The memory address of the instruction. "
            "Found when identifying the instruction in Ghidra."
        ),
    ).grid(row=2, column=0, columnspan=2)

    base_virt_addr = tk.Entry(new_window)
    base_file_offset = tk.Entry(new_window)
    instr_virt_addr = tk.Entry(new_window)

    base_virt_addr.grid(row=0, column=2)
    base_file_offset.grid(row=1, column=2)
    instr_virt_addr.grid(row=2, column=2)

    tk.Button(
        new_window,
        text="Calculate",
        command=lambda: calculate_offset(
            base_virt_addr, base_file_offset, instr_virt_addr
        ),
    ).grid(row=3, column=0, columnspan=2)

    tk.Button(
        new_window,
        text="Find Base Virtual Address",
        command=lambda: calculate_base_va(file_path_entry.get(), base_virt_addr),
    ).grid(row=0, column=3)

    tk.Button(
        new_window,
        text="Find Base File Offset",
        command=lambda: calculate_base_offset(file_path_entry.get(), base_file_offset),
    ).grid(row=1, column=3)


############################################################
#                 CONVERSION TOOL
############################################################

def convert_value(value, from_base, to_base, output_entry):
    try:
        from_base_int = int(from_base.split(" - ")[0])
        to_base_int = int(to_base.split(" - ")[0])

        converted_value = int(value, from_base_int)
        if to_base_int == 2:
            formatted_value = bin(converted_value)
        elif to_base_int == 10:
            formatted_value = str(converted_value)
        elif to_base_int == 16:
            formatted_value = hex(converted_value)
        else:
            raise ValueError("Unsupported base.")

        output_entry.delete(0, tk.END)
        output_entry.insert(0, formatted_value)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def open_conversion_tool():
    new_window = tk.Toplevel()
    new_window.title("Conversion Tool")

    tk.Label(new_window, text="Value:").grid(row=0, column=0)
    tk.Label(new_window, text="From:").grid(row=1, column=0)
    tk.Label(new_window, text="To:").grid(row=2, column=0)

    value = tk.Entry(new_window)
    value.grid(row=0, column=1)

    from_base = tk.StringVar(new_window)
    from_base.set("16 - HEX")
    tk.OptionMenu(new_window, from_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=1, column=1)

    to_base = tk.StringVar(new_window)
    to_base.set("10 - DEC")
    tk.OptionMenu(new_window, to_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=2, column=1)

    output_entry = tk.Entry(new_window)
    output_entry.grid(row=3, column=0, columnspan=2)

    tk.Button(
        new_window,
        text="Convert",
        command=lambda: convert_value(value.get(), from_base.get(), to_base.get(), output_entry),
    ).grid(row=4, column=0, columnspan=2, sticky=tk.W)


############################################################
#                   HELP BOX LOGIC
############################################################

def update_help_text(event, help_text, help_entry, widget):
    widget_name = str(widget)
    if widget_name in help_text:
        help_entry["state"] = "normal"
        help_entry.delete(1.0, tk.END)
        help_entry.insert(tk.END, help_text[widget_name])
        help_entry["state"] = "disabled"


def create_help_box(root, help_text, pages):
    help_entry = tk.Text(root, state="disabled", width=50, height=10)
    help_entry.grid(row=0, column=3, rowspan=7, sticky=(tk.N, tk.S, tk.W, tk.E))

    for page in pages:
        for widget in page.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.bind(
                    "<FocusIn>",
                    lambda event, widget=widget: update_help_text(event, help_text, help_entry, widget),
                )
    return help_entry


def raise_frame(frame):
    frame.tkraise()


############################################################
#                         KEYGEN
############################################################

def keygen(name=""):
    """
    Simple placeholder for key generation logic.
    """
    return f"KEY-{name.upper()}-12345"


def open_keygen_window():
    keygen_window = tk.Toplevel()
    keygen_window.title("Keygen")

    tk.Label(keygen_window, text="Enter your name:").grid(row=0, column=0)
    name_entry = tk.Entry(keygen_window)
    name_entry.grid(row=0, column=1)

    tk.Label(keygen_window, text="Generated key:").grid(row=1, column=0)
    key_entry = tk.Entry(keygen_window)
    key_entry.grid(row=1, column=1)

    tk.Button(
        keygen_window,
        text="Generate Key",
        command=lambda: key_entry.insert(0, keygen(name_entry.get())),
    ).grid(row=2, column=0, columnspan=2)


############################################################
#                         MAIN GUI
############################################################

def main():
    root = tk.Tk()
    root.title("Binary / Plugin Patching Tool")

    page1 = tk.Frame(root)
    page2 = tk.Frame(root)

    for frame in (page1, page2):
        frame.grid(row=0, column=0, sticky='news')

    # Navigation
    tk.Button(page1, text="Next Page", command=lambda: raise_frame(page2)).grid(row=100, column=0)
    tk.Button(page2, text="Previous Page", command=lambda: raise_frame(page1)).grid(row=100, column=0)

    # Arch mode
    tk.Label(page1, text="Architecture Mode").grid(row=10)
    arch_mode = tk.StringVar(root)
    arch_mode.set("64-bit")
    tk.OptionMenu(page1, arch_mode, "32-bit", "64-bit").grid(row=10, column=1)

    # File selection
    tk.Label(page1, text="File Path").grid(row=0)
    tk.Label(page1, text="Offset").grid(row=1)
    tk.Label(page1, text="Offset Base").grid(row=2)
    tk.Label(page1, text="Current Instruction").grid(row=3)
    tk.Label(page1, text="New Instruction").grid(row=4)

    file_path = tk.Entry(page1)
    offset = tk.Entry(page1)
    instruction = tk.Entry(page1)
    new_instruction = tk.Entry(page1)

    file_path.grid(row=0, column=1)
    offset.grid(row=1, column=1)
    instruction.grid(row=3, column=1)
    new_instruction.grid(row=4, column=1)

    offset_base = tk.StringVar(page1)
    offset_base.set("16 - HEX")
    tk.OptionMenu(page1, offset_base, "16 - HEX", "10 - DEC", "2 - BIN").grid(row=2, column=1)

    # Binary
    tk.Label(page1, text="Binary:", fg="red").grid(row=7, column=0)
    bin_entry = tk.Entry(page1, fg="red")
    bin_entry.grid(row=7, column=1)

    # Decimal
    tk.Label(page1, text="Decimal:", fg="green").grid(row=8, column=0)
    dec_entry = tk.Entry(page1, fg="green")
    dec_entry.grid(row=8, column=1)

    # Hexadecimal
    tk.Label(page1, text="Hexadecimal:", fg="blue").grid(row=9, column=0)
    hex_entry = tk.Entry(page1, fg="blue")
    hex_entry.grid(row=9, column=1)

    tk.Button(page1, text="Browse", command=lambda: browse_files(file_path)).grid(row=0, column=2)

    tk.Button(
        page1,
        text="Read",
        command=lambda: read_instruction(
            file_path.get(),
            offset.get(),
            instruction,
            bin_entry,
            hex_entry,
            dec_entry,
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
        ),
    ).grid(row=1, column=2)

    tk.Button(
        page1,
        text="Patch",
        command=lambda: patch_binary(
            file_path.get(),
            offset.get(),
            new_instruction.get(),
            int(offset_base.get().split(" ")[0]),
            arch_mode.get(),
            page1,
        ),
    ).grid(row=5, column=1, sticky=tk.W)

    tk.Button(
        page1,
        text="Offset Calculator",
        command=lambda: open_offset_calculator(file_path),
    ).grid(row=6, column=1, sticky=tk.W)

    tk.Button(page1, text="Conversion Tool", command=open_conversion_tool).grid(row=10, column=3, sticky=tk.W)

    # Badboy offset
    tk.Label(page1, text="Badboy Offset").grid(row=13)
    bad_boy_offset_entry = tk.Entry(page1)
    bad_boy_offset_entry.grid(row=13, column=1)

    # Search string
    tk.Label(page1, text="String to Search").grid(row=11)
    search_string_entry = tk.Entry(page1)
    search_string_entry.grid(row=11, column=1)
    output_text = tk.Text(page1, state="normal", width=40, height=10)
    output_text.grid(row=12, column=0, columnspan=3)

    output_text.tag_configure("binary", foreground="red")
    output_text.tag_configure("decimal", foreground="green")
    output_text.tag_configure("hex", foreground="blue")

    tk.Button(
        page1,
        text="Search String",
        command=lambda: search_string_in_binary(
            file_path.get(),
            search_string_entry.get(),
            bad_boy_offset_entry,
            output_text,
        ),
    ).grid(row=11, column=2)

    # RVA, IAT, ITA
    tk.Label(page1, text="Relative Virtual Address (RVA)").grid(row=14)
    rva_entry = tk.Entry(page1)
    rva_entry.grid(row=14, column=1)

    tk.Label(page1, text="Import Address Table (IAT)").grid(row=15)
    iat_entry = tk.Entry(page1)
    iat_entry.grid(row=15, column=1)

    tk.Label(page1, text="Import Table Address (ITA)").grid(row=16)
    ita_entry = tk.Entry(page1)
    ita_entry.grid(row=16, column=1)

    tk.Button(
        page1,
        text="Get RVA",
        command=lambda: calculate_rva(file_path.get(), rva_entry),
    ).grid(row=14, column=2)

    tk.Button(
        page1,
        text="Get IAT",
        command=lambda: calculate_iat(file_path.get(), iat_entry),
    ).grid(row=15, column=2)

    tk.Button(
        page1,
        text="Get ITA",
        command=lambda: calculate_ita(file_path.get(), ita_entry),
    ).grid(row=16, column=2)

    tk.Button(
        page1,
        text="Unpack PE",
        command=lambda: unpack_binary(file_path.get(), page1),
    ).grid(row=19, column=2)

    # ILT
    tk.Label(page1, text="Import Lookup Table (ILT)").grid(row=17)
    ilt_entry = tk.Entry(page1)
    ilt_entry.grid(row=17, column=1)
    tk.Button(
        page1,
        text="Identify ILT",
        command=lambda: identify_ilt(file_path.get(), ilt_entry),
    ).grid(row=17, column=2)

    # Fix Dump
    tk.Label(page1, text="Fix Dump").grid(row=12, column=10)
    fix_dump_entry = tk.Entry(page1)
    fix_dump_entry.grid(row=12, column=11)
    tk.Button(
        page1,
        text="Fix Dump",
        command=lambda: fix_dump(file_path.get()),
    ).grid(row=12, column=12)

    # Page2 Components
    entry_point_entry = tk.Entry(page2)
    entry_point_entry.grid(row=0, column=1)
    tk.Button(
        page2,
        text="Identify Entry Point",
        command=lambda: identify_entry_point(file_path.get(), entry_point_entry),
    ).grid(row=0, column=0)

    unpacking_stub_entry = tk.Entry(page2)
    unpacking_stub_entry.grid(row=1, column=1)
    tk.Button(
        page2,
        text="Locate Unpacking Stub",
        command=lambda: locate_unpacking_stub(file_path.get(), unpacking_stub_entry),
    ).grid(row=1, column=0)

    import_table_entry = tk.Entry(page2)
    import_table_entry.grid(row=2, column=1)
    tk.Button(
        page2,
        text="Identify Import Table",
        command=lambda: identify_import_table(file_path.get(), import_table_entry),
    ).grid(row=2, column=0)

    image_import_descriptor_entry = tk.Entry(page2)
    image_import_descriptor_entry.grid(row=3, column=1)
    tk.Button(
        page2,
        text="Identify IMAGE_IMPORT_DESCRIPTOR",
        command=lambda: identify_import_descriptor(file_path.get(), image_import_descriptor_entry),
    ).grid(row=3, column=0)

    first_thunk_entry = tk.Entry(page2)
    first_thunk_entry.grid(row=4, column=1)
    tk.Button(
        page2,
        text="Identify First Thunk",
        command=lambda: identify_first_thunk(file_path.get(), first_thunk_entry),
    ).grid(row=4, column=0)

    original_first_thunk_entry = tk.Entry(page2)
    original_first_thunk_entry.grid(row=5, column=1)
    tk.Button(
        page2,
        text="Identify Original First Thunk",
        command=lambda: identify_original_first_thunk(file_path.get(), original_first_thunk_entry),
    ).grid(row=5, column=0)

    modify_unpacking_stub_entry = tk.Entry(page2)
    modify_unpacking_stub_entry.grid(row=6, column=1)
    tk.Button(
        page2,
        text="Modify Unpacking Stub",
        command=lambda: modify_unpacking_stub(file_path.get(), modify_unpacking_stub_entry),
    ).grid(row=6, column=0)

    restore_iat_entry = tk.Entry(page2)
    restore_iat_entry.grid(row=7, column=1)
    tk.Button(
        page2,
        text="Restore IAT",
        command=lambda: restore_iat(file_path.get(), restore_iat_entry),
    ).grid(row=7, column=0)

    oep_entry = tk.Entry(page2)
    oep_entry.grid(row=8, column=1)
    tk.Button(
        page2,
        text="Identify OEP",
        command=lambda: identify_oep(file_path.get(), oep_entry),
    ).grid(row=8, column=0)

    dump_entry = tk.Entry(page2)
    dump_entry.grid(row=9, column=1)
    tk.Button(
        page2,
        text="Dump Unpacked",
        command=lambda: dump_unpacked_executable(file_path.get(), dump_entry),
    ).grid(row=9, column=0)

    import_table_rva_entry = tk.Entry(page2)
    import_table_rva_entry.grid(row=10, column=1)
    tk.Button(
        page2,
        text="Identify Import Table RVA",
        command=lambda: identify_import_table_rva(file_path.get(), import_table_rva_entry),
    ).grid(row=10, column=0)

    # Code cave logic on page2
    find_code_cave_entry = tk.Entry(page2)
    find_code_cave_entry.grid(row=2, column=4)
    tk.Button(
        page2,
        text="Find Code Cave",
        command=lambda: find_code_cave(file_path.get(), find_code_cave_entry),
    ).grid(row=2, column=3)

    code_cave_entry = tk.Entry(page2)
    code_cave_entry.grid(row=3, column=4)
    tk.Button(
        page2,
        text="Create Code Cave",
        command=lambda: create_code_cave(file_path.get(), code_cave_entry),
    ).grid(row=3, column=3)

    tls_callbacks_entry = tk.Entry(page2)
    tls_callbacks_entry.grid(row=4, column=4)
    tk.Button(
        page2,
        text="Interact TLS Callbacks",
        command=lambda: interact_tls_callbacks(file_path.get(), tls_callbacks_entry),
    ).grid(row=4, column=3)

    tk.Button(
        page2,
        text="Identify Anti-Debugging Techniques",
        command=lambda: display_results(identify_anti_debugging_techniques(file_path.get())),
    ).grid(row=1, column=3)

    tk.Button(
        page2,
        text="Open Keygen Window",
        command=open_keygen_window,
    ).grid(row=0, column=3)

    # Export Table
    tk.Label(page2, text="Export Table").grid(row=13, column=0)
    export_table_entry = tk.Entry(page2)
    export_table_entry.grid(row=13, column=1)
    tk.Button(
        page2,
        text="Interact Export Table",
        command=lambda: interact_export_table(file_path.get(), export_table_entry),
    ).grid(row=13, column=0)

    # Resource Table
    tk.Label(page2, text="Resource Table").grid(row=14, column=0)
    resource_table_entry = tk.Entry(page2)
    resource_table_entry.grid(row=14, column=1)
    tk.Button(
        page2,
        text="Interact Resource Table",
        command=lambda: interact_resource_table(file_path.get(), resource_table_entry),
    ).grid(row=14, column=0)

    # Section Table
    tk.Label(page2, text="Section Table").grid(row=15, column=0)
    section_table_entry = tk.Entry(page2)
    section_table_entry.grid(row=15, column=1)
    tk.Button(
        page2,
        text="Interact Section Table",
        command=lambda: interact_section_table(file_path.get(), section_table_entry),
    ).grid(row=15, column=0)

    # Relocation Table
    tk.Label(page2, text="Relocation Table").grid(row=16, column=0)
    relocation_table_entry = tk.Entry(page2)
    relocation_table_entry.grid(row=16, column=1)
    tk.Button(
        page2,
        text="Interact Relocation Table",
        command=lambda: interact_relocation_table(file_path.get(), relocation_table_entry),
    ).grid(row=16, column=0)

    # Overlay
    tk.Label(page2, text="Overlay").grid(row=17, column=0)
    overlay_entry = tk.Entry(page2)
    overlay_entry.grid(row=17, column=1)
    tk.Button(
        page2,
        text="Interact Overlay",
        command=lambda: interact_overlay(file_path.get(), overlay_entry),
    ).grid(row=17, column=0)

    # Automatic Deobfuscation
    tk.Label(page2, text="Automatic Deobfuscation").grid(row=18, column=0, columnspan=2)
    tk.Button(
        page2,
        text="Execute",
        command=lambda: automatic_deobfuscation(file_path.get()),
    ).grid(row=18, column=2)

    # Binary Diffing
    tk.Label(page2, text="Binary Diffing - File 1").grid(row=19, column=0)
    binary_diffing_entry_1 = tk.Entry(page2)
    binary_diffing_entry_1.grid(row=19, column=1)
    tk.Button(
        page2,
        text="Browse",
        command=lambda: browse_files(binary_diffing_entry_1),
    ).grid(row=19, column=2)

    tk.Label(page2, text="Binary Diffing - File 2").grid(row=20, column=0)
    binary_diffing_entry_2 = tk.Entry(page2)
    binary_diffing_entry_2.grid(row=20, column=1)
    tk.Button(
        page2,
        text="Browse",
        command=lambda: browse_files(binary_diffing_entry_2),
    ).grid(row=20, column=2)

    tk.Button(
        page2,
        text="Compare",
        command=lambda: binary_diffing(
            binary_diffing_entry_1.get(),
            binary_diffing_entry_2.get()
        ),
    ).grid(row=21, column=0, columnspan=3)

    tk.Button(
        page2,
        text="Binary Analysis Report",
        command=lambda: binary_analysis_report(file_path.get(), root),
    ).grid(row=22, column=2)

    # Obfuscation Detection
    oc = od.ObfuscationClassifier(od.PlatformType.ALL)

    def check_obfuscation(command):
        result = oc([command])
        return bool(result[0])

    def detect():
        command = obfuscation_entry.get()
        if check_obfuscation(command):
            messagebox.showinfo("Obfuscation Detection", "The command is obfuscated.")
        else:
            messagebox.showinfo("Obfuscation Detection", "The command is not obfuscated.")

    tk.Label(page2, text="Obfuscation Detection - Command").grid(row=23, column=0)
    obfuscation_entry = tk.Entry(page2)
    obfuscation_entry.grid(row=23, column=1)
    tk.Button(
        page2,
        text="Detect Obfuscation",
        command=detect,
    ).grid(row=23, column=2)

    tk.Button(
        page2,
        text="Expected Reg",
        command=lambda: generate_expected_reg(file_path.get()),
    ).grid(row=24, column=2)

    # Optional help text dictionary
    help_text = {
        ".!frame.!entry": "Enter the path to the plugin file (.dll, .vst3, .aax, .component, etc.). Click 'Browse' to select it.",
        ".!frame.!entry2": "Enter the offset where you want to read or patch instructions.",
        ".!frame.!entry3": "Current instruction disassembly will appear here after clicking 'Read'.",
        ".!frame.!entry4": "Enter the new assembly instruction you want to patch in.",
    }

    create_help_box(root, help_text, [page1, page2])

    root.minsize(1400, 720)
    root.geometry("1400x720")

    raise_frame(page1)
    root.mainloop()


if __name__ == "__main__":
    main()

print("Do you want me to doublecheck?")
