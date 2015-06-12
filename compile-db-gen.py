#! /usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import itertools
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import types

compilers = [
    re.compile(r'^([^/]*/)*([^-]*-)*c(c|\+\+)$'),
    re.compile(r'^([^/]*/)*([^-]*-)*g(cc|\+\+)(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^/]*/)*([^-]*-)*clang(\+\+)?(-\d+(\.\d+){0,2})?$'),
    re.compile(r'^([^/]*/)*llvm-g(cc|\+\+)$'),
]
accepted = {'.c', '.C', '.cc', '.CC', '.cxx', '.cp', '.cpp', '.c++',
            '.m', '.mm',
            '.i', '.ii', '.mii'}
include_file = []
exclude_file = []
include_dir  = []
exclude_dir  = []

def compiler_call(executable):
    """ A predicate to decide the entry is a compiler call or not. """
    return any((pattern.match(executable) for pattern in compilers))

def is_source_file(filename):
    """ A predicate to decide the filename is a source file or not. """
    __, ext = os.path.splitext(filename)
    return ext in accepted

def shell_escape(arg):
    """ Create a single string from list.

    The major challenge, to deal with white spaces. Which are used by
    the shell as separator. (Eg.: -D_KEY="Value with spaces") """
    def quote(arg):
        table = {'\\': '\\\\', '"': '\\"', "'": "\\'"}
        return '"' + ''.join([table.get(c, c) for c in arg]) + '"'

    return quote(arg) if len(shlex.split(arg)) > 1 else arg

def join_command(args):
    return ' '.join([shell_escape(arg) for arg in args])

chdir_re = re.compile (r"^(\d+) +chdir\((.*)\)\s+= 0")
exec_re  = re.compile (r"^(\d+) +execve(\(.*\))\s+= 0")
child_re = re.compile (r"^(\d+) .*SIGCHLD.*si_pid=(\d+).*")
ccache_re = re.compile(r'^([^/]*/)*([^-]*-)*ccache(-\d+(\.\d+){0,2})?$')
def parse_exec_trace(proc_run, fname):
    """Construct the compile tree, and the key is pid, the node contain
proc_run[pid] = {
'cwd':'',   # the last chdir, the child process depend on this value
'child':[], # the child node
'cmds': []  # the commands
}"""
    with open(fname, 'r') as fd:
        for line in fd:
            m = chdir_re.match(line)
            if m is not None:   # chdir, record this
                pid = m.group(1)
                wd  = eval(m.group(2))
                if not pid in proc_run:
                    proc_run[pid] = {"cwd":"", "child":[], "cmds": []}
                proc_run[pid]["cwd"] = os.path.join(proc_run[pid]["cwd"], wd)
                # print pid + " chdir:" + proc_run[pid]["cwd"]
                continue

            m = child_re.match(line)
            if m is not None:   # the child process end, move it to it's parent
                pid = m.group(1)
                cid = m.group(2)
                if cid in proc_run:
                    item = proc_run[cid]
                    del proc_run[cid] # remove from 'running' process list

                    if not pid in proc_run: # this process end, append it to it's parent
                        proc_run[pid] = {"cwd":"", "child":[], "cmds": []}
                    item["cwd"] = proc_run[pid]["cwd"] # use the parent directory
                    # print pid + " child_end:" + item["cwd"]
                    proc_run[pid]["child"].append({cid:item})
                continue

            m = exec_re.match(line)
            if m is not None:   # execve, get the compiler
                pid = m.group(1)
                line = re.sub(", \[/\* [^*]+ \*/\]", "", m.group(2))
                (programName, command) = eval(line)
                if ccache_re.match(programName) is not None:
                    programName = command[1] # for "ccache", drop first slot (which is "ccache")
                    del command[0]
                if compiler_call(programName):
                    for f in command: # make item for each
                        if is_source_file(f):
                            if not pid in proc_run:
                                proc_run[pid] = {"cwd":"", "child":[], "cmds": []}

                            # print pid + " execv:" + proc_run[pid]["cwd"]
                            proc_run[pid]["cmds"].append({"directory":proc_run[pid]["cwd"],
                                                         "command": join_command(command),
                                                         "file": f})

def print_exec_trace(proc_run, cwd, fs):
    """Print the execute trace in compile data json format."""
    for pid in proc_run:
        proc = proc_run[pid]
        wd = os.path.join(cwd, proc["cwd"])

        for child in proc["child"]:
            print_exec_trace(child, wd, fs)
        for cmd in proc_run[pid]["cmds"]:
            d = wd; #os.path.join(wd, cmd["directory"])
            cmd["directory"] = d
            f = cmd["file"]
            if len(include_file) > 0 and not(any((r.search(f) for r in include_file))):
                continue
            if len(exclude_file) > 0 and any((r.search(f) for r in exclude_file)):
                continue
            if len(include_dir) > 0 and not(any((r.search(d) for r in include_dir))):
                continue
            if len(exclude_dir) > 0 and any((r.search(d) for r in exclude_dir)):
                continue
            print(cmd, file=fs)


def trace(args):
    "Trace the compile command and get the raw compile log."
    # request strace-4.8 or higher
    p = subprocess.Popen(["strace", "-V"], stdout = subprocess.PIPE)
    p.wait();
    sVer = p.stdout.readline()
    rVer = re.compile(".*(\d+)\.(\d+)")
    mVer = rVer.match(sVer)
    major = int(mVer.group(1))
    if major < 4 or (major == 4 and int(mVer.group(2))  < 8):
        print("strace version should high than 4.8")
        print("Current:" + sVer)
        sys.exit(1)
    p = subprocess.Popen(["getconf", "ARG_MAX"], stdout = subprocess.PIPE)
    p.wait()
    arg_max = str(int(p.stdout.readline ()))
    command  = ["strace", "-f", "-s" + arg_max, "-etrace=execve,chdir", "-o", args.output]
    command += args.command
    p = subprocess.Popen(command, stderr = subprocess.PIPE);
    p.wait();
    if p.returncode != 0:
        print(p.stdout.read())

def parse(args):
    proc_end = {}
    proc_run = {}
    fname= args.raw_database
    if args.startup_dir is not None:
        cwd = os.path.abspath(args.startup_dir)
    else:
        cwd = os.path.dirname(os.path.abspath(fname))
    parse_exec_trace(proc_run, fname)
    fs = sys.stdout
    if args.output != "" and args.output != "-":
        fs = open(args.output, "w")

    for i in args.include:
        include_file.append(re.compile(i))
    for e in args.exclude:
        exclude_file.append(re.compile(e))
    for i in args.include_dir:
        include_dir.append(re.compile(i))
    for e in args.exclude_dir:
        exclude_dir.append(re.compile(e))
    print_exec_trace(proc_run, cwd, fs)

def main():
    "The main function"

    parser = argparse.ArgumentParser(description = "Generate the compile database from build")
    subparsers = parser.add_subparsers(metavar = "SUBCOMMAND")

    # trace
    s = subparsers.add_parser (
        "trace",
        help = "trace build command",
        description = "Create a compilation database by tracing a build command.")
    s.add_argument (
        "--output", "-o",
        default = "./compile_commands.raw",
        help = "the strace output file")
    s.add_argument (
        "command",
        metavar = "COMMAND",
        nargs = argparse.REMAINDER,
        help = "build command line")
    s.set_defaults (sourceType = "trace")
    s.set_defaults (fun = trace)

    # parse
    s = subparsers.add_parser (
        "parse",
        help = "parse the strace file",
        description = "Create a compilation database from the result by tracing a build command.")
    s.add_argument (
        "raw_database",
        default = "./compile_commands.raw",
        help = "the raw database from strace")
    s.add_argument (
        "--startup-dir", "-s",
        default = None,
        help = "the startup directory")
    s.add_argument (
        "output",
        default = "./compile_commands.json",
        help = "the output compilor database")
    s.add_argument (
        "--include", "-i",
        metavar = "REGEX",
        default = [],
        action = "append",
        help = "include the file parten")
    s.add_argument (
        "--exclude", "-e",
        metavar = "REGEX",
        default = [],
        action = "append",
        help = "exclude the file patten")
    s.add_argument (
        "--include-dir", "-I",
        metavar = "REGEX",
        default = [],
        action = "append",
        help = "include the dir parten")
    s.add_argument (
        "--exclude-dir", "-E",
        metavar = "REGEX",
        default = [],
        action = "append",
        help = "exclude the dir patten")
    s.set_defaults (sourceType = "parse")
    s.set_defaults (fun = parse)

    args = parser.parse_args ()
    return args.fun (args)

if __name__ == "__main__":
    try:
        import argparse
    except ImportError:
        import arg2opt as argparse
    sys.exit(main())
