"""
Add GoReSym symbols to an x(64|32)dbg debug session, using x64dbg_automate.
"""
import json
from pathlib import Path
import shutil

import typer
import pefile

from x64dbg_automate import X64DbgClient


app = typer.Typer(name="GoReSym x(64|32)dbg", 
                  help="Add GoReSym symbols to an x(64|32)dbg debug session.")


def main(
    target_exe: str = typer.Argument(..., help="Path to the target executable."),
    syms_json_file: str = typer.Argument(..., help="Path to the symbols JSON file."),
    x64dbg_path: str = typer.Option(
        shutil.which("x64dbg") or shutil.which("x32dbg") or "",
        help="Path to the x(64|32)dbg executable. Defaults to the first found in PATH."
    ),
):
    if not Path(target_exe).is_file():
        raise typer.BadParameter(f"Target executable {target_exe} does not exist.")
    target_pe = pefile.PE(target_exe)
    
    dbg_path = Path(x64dbg_path)
    if not dbg_path.is_file():
        raise typer.BadParameter(f"x(64|32)dbg executable could not be found, add it to PATH or explicitly provide the path.")
    
    plug_arch = "dp64" if x64dbg_path.lower().replace(".exe", "").endswith("x64dbg") else "dp32"
    if not (dbg_path.parent / "plugins" / f"x64dbg-automate.{plug_arch}").is_file():
        raise typer.BadParameter(f"x64dbg_automate plugin not found in {dbg_path.parent / 'plugins'}, "
                                 "please install it before using this script.")

    print(f"Loading {target_exe}...")
    client = X64DbgClient(r"C:\re\x64dbg_dev\release\x64\x64dbg.exe")
    client.start_session(target_exe)

    # try to negotiate text encoding, this varies when terminal redirection is used to save JSON
    with Path(syms_json_file).open("rb") as f:
        syms_json = f.read()
    if syms_json.startswith(b"\xff\xfe"):
        syms_json = syms_json.decode("utf-16-le")
    elif '\0' in syms_json:
        syms_json = syms_json.decode("utf-16")
    else:
        syms_json = syms_json.decode("utf-8")
    # remove BOMs
    while not syms_json.startswith("{") :
        syms_json = syms_json[1:]
    syms_json = json.loads(syms_json)

    mod_base, _ = client.eval_sync('mod.main()')
    print(f'Adding {len(syms_json["UserFunctions"] or [])} user functions...')
    for sym in syms_json["UserFunctions"] or []:
        rva = sym["Start"] - target_pe.OPTIONAL_HEADER.ImageBase
        addr = mod_base + rva
        client.set_label_at(addr, sym["FullName"])

    print(f'Adding {len(syms_json["StdFunctions"] or [])} std functions...')
    for sym in syms_json["StdFunctions"] or []:
        rva = sym["Start"] - target_pe.OPTIONAL_HEADER.ImageBase
        addr = mod_base + rva
        client.set_label_at(addr, sym["FullName"])

    print('Done!')
    client.log("GoReSym symbols added!")
    client.detach_session()


if __name__ == "__main__":
    typer.run(main)