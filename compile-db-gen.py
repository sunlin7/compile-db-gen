#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
import copy
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
include_dir  = []
exclude_file = []
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
    """Join the command with escaped options."""
    return ' '.join([shell_escape(arg) for arg in args])

g_sys_inc = {}
def get_sys_inc(compiler):
    """return a list of compiler system include dir."""
    if compiler in g_sys_inc:
        return g_sys_inc[compiler]

    lang = "c"
    if re.compile(r"\+\+|pp$").findall(compiler):
        lang = "c++"
    p = subprocess.Popen([compiler, "-x", lang, "-E", "-v", "-"], stderr = subprocess.PIPE, stdin = subprocess.PIPE)
    info = p.communicate(input='')[1]
    raw_inc = re.compile(r"^.*starts here:((?:.|\n)*?)End of search list.", re.MULTILINE).findall(info.decode('utf-8'))
    if len(raw_inc) > 0:
        incs = re.compile("/.*$", re.MULTILINE).findall(raw_inc[0])
        g_sys_inc[compiler] = [ "-I%s"%x for x in incs]
    return g_sys_inc[compiler]

class OType:
    CHILD = 1
    CHDIR = 2
    EXEC = 3

chdir_re = re.compile (r"^(\d+) +chdir\((.*)\)\s+= 0")
exec_re  = re.compile (r"^(\d+) +execve(\(.*\))\s+= 0")
child_re = re.compile (r"^(\d+) .*SIGCHLD.*si_pid=(\d+).*")
ccache_re = re.compile(r'^([^/]*/)*([^-]*-)*ccache(-\d+(\.\d+){0,2})?$')
def genlineobjs(fname):
    """Parse the lines into objects."""
    objList = []
    with open(fname, 'r') as fd:  # pre process to sensitive objects
        for line in fd:
            m = chdir_re.match(line)
            if m is not None:   # chdir, record this
                pid = m.group(1)
                wd  = eval(m.group(2))
                objList.append({'type':OType.CHDIR, 'pid':pid, 'wd':wd})
                # print (pid + " chdir:" + proc_run[pid]["cwd"])
                continue

            m = child_re.match(line)
            if m is not None:   # the child process end, move it to it's parent
                pid = m.group(1)
                cid = m.group(2)
                objList.append({'type':OType.CHILD, 'pid':pid, 'cid':cid})
                continue

            m = exec_re.match(line)
            if m is not None:   # execve, get the compiler
                pid = m.group(1)
                # for strace <=4.11, format: 012 execve("PATH", ["E", "..."], [/* N vars */]) = 0
                # for strace 2018, format:   012 execve("PATH", ["E", "..."], 0xM /* N vars */) = 0
                # remove the tail of execve()
                line = re.sub(", \[/\* [^*]+ \*/\]", "", m.group(2))
                line = re.sub(', 0x[^\)]+', '', line)
                (programName, command) = eval(line)
                if ccache_re.match(programName) is not None \
                   or compiler_call(programName):
                   objList.append({'type':OType.EXEC, 'pid':pid, 'progName':programName, 'command': command}) 

    return objList


def getParentPid(itrPidObj, pid):
    for itr in itrPidObj:
        if itr['type'] == OType.CHILD:
            if itr['cid'] == pid:
                return itr['pid']

    return None


def parse_exec_trace(proc_run, fname, auto_sys_inc = False):
    """Construct the compile tree, and the key is pid, the node contain
proc_run[pid] = {
'cwd':'',   # the last chdir, the child process depend on this value
'child':[], # the child node
'cmds': []  # the commands
}"""
    objList = genlineobjs(fname)
    itr = iter(objList)
    while True:
        item = None
        try:
            item = next(itr)
        except StopIteration:
            break

        pid = item['pid']
        if pid not in proc_run:           # first ocurr in the lines, new child process, get the dir
            ppid = getParentPid(copy.copy(itr), pid)  # try to find the child end log to get its parent
            cwd = proc_run[ppid]['cwd'] if ppid in proc_run else ""
            proc_run[pid] = {"cwd":cwd, "child":[], "cmds":[]}

        if item['type'] == OType.CHDIR:   # chdir, record this
            proc_run[pid]["cwd"] = os.path.join(proc_run[pid]["cwd"], item['wd'])
            # print(pid + " chdir:" + proc_run[pid]["cwd"]) 
            continue

        if item['type'] == OType.CHILD:   # the child process end, move it to it's parent
            pid = item['pid']
            cid = item['cid']
            if cid in proc_run:
                item = proc_run[cid]
                del proc_run[cid] # remove from 'running' process list

                if not pid in proc_run: # this process end, append it to it's parent
                    proc_run[pid] = {"cwd":"", "child":[], "cmds": []}
                # print(pid + " child_end:" + item["cwd"])
                proc_run[pid]["child"].append({cid:item})
            continue

        if item['type'] == OType.EXEC:   # execve, get the compiler
            pid = item['pid']
            programName, command = item['progName'], item['command']
            if ccache_re.match(programName) is not None:
                programName = command[1] # for "ccache", drop first slot (which is "ccache")
                del command[0]
 
            if compiler_call(programName):
                if len(command) >= 2 and command[1] == "-cc1": # ignore the "clang -cc1 ..." call
                    continue

                sys_inc = []
                if auto_sys_inc:
                    sys_inc = get_sys_inc(command[0])

                for f in command: # make item for each
                    if is_source_file(f):
                        if not pid in proc_run:
                            proc_run[pid] = {"cwd":"", "child":[], "cmds": []}

                        # print pid + " execv:" + proc_run[pid]["cwd"]
                        proc_run[pid]["cmds"].append({"directory":proc_run[pid]["cwd"],
                                                     "command": join_command(command  + sys_inc),
                                                     "file": f})

def print_exec_trace(proc_run, cwd, proc_res):
    """Print the execute trace in compile data json format."""
    for pid in proc_run:
        proc = proc_run[pid]
        wd = os.path.join(cwd, proc["cwd"])

        for child in proc["child"]:
            print_exec_trace(child, wd, proc_res)
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
            proc_res.append(cmd)

def trace(args):
    """Trace the compile command and get the raw compile log."""
    # request strace-4.8 or higher
    p = subprocess.Popen(["strace", "-V"], stdout = subprocess.PIPE)
    p.wait();
    sVer = p.stdout.read().decode('utf-8')
    # for Ubuntu 18.04, the ver string is "version UNKNOWN"
    mVer = re.match("strace -- version (\d+)\.(\d+)", sVer)
    if mVer:
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
    #TBD: the output of stdin/stderr maybe very large, hangup happend when try
    # to grabe them, refer the manual of .wait() for detail.
    p = subprocess.Popen(command);
    p.wait();

    return p.returncode

def parse(args):
    """Parse the output from trace and generate the compile_commands.json."""
    proc_end = {}
    proc_run = {}
    fname= args.raw_database
    if args.startup_dir is not None:
        cwd = os.path.abspath(args.startup_dir)
    else:
        cwd = os.path.dirname(os.path.abspath(fname))
    parse_exec_trace(proc_run, fname, args.auto_sys_inc)
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
    proc_res = []
    print_exec_trace(proc_run, cwd, proc_res)
    json.dump(proc_res, fs, indent=4)

def run(args):
    """run the build command and generate the compilation database."""
    raw_database = "./compile_commands.raw"
    output = args.output
    args.output = raw_database
    if trace (args) == 0:
        args.output = output    # restore the value
        args.raw_database = raw_database
        parse (args)

def add_common_opts_parse(s):
    """add the opts for subcommand "parse" """
    s.add_argument (
        "--startup-dir", "-s",
        default = None,
        help = "the startup directory")
    s.add_argument (
        "--auto-sys-inc", "-a",
        default = True,
        action = "store_true",
        help = "auto detect the system include path")
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

def add_common_opts_trace(s):
    """add the opts for subcommand "trace" """
    s.add_argument (
        "command",
        metavar = "COMMAND",
        nargs = argparse.REMAINDER,
        help = "build command line")

def main():
    "The main function"

    parser = argparse.ArgumentParser(description = "Generate the compile database from build")
    subparsers = parser.add_subparsers(metavar = "SUBCOMMAND")

    # run the compile command and generate the JSON compilation database
    s = subparsers.add_parser (
        "run",
        help = "(Default) trace build command, and parse result ",
        description = "Create a compilation database by tracing a build command.")
    add_common_opts_parse (s)
    add_common_opts_trace (s)
    s.add_argument (
        "--output", "-o",
        default = "./compile_commands.json",
        help = "the strace output file")
    s.set_defaults (sourceType = "run")
    s.set_defaults (fun = run)

    # trace
    s = subparsers.add_parser (
        "trace",
        help = "trace build command",
        description = "Create a compilation database by tracing a build command.")
    s.add_argument (
        "--output", "-o",
        default = "./compile_commands.raw",
        help = "the strace output file")
    add_common_opts_trace (s)
    s.set_defaults (sourceType = "trace")
    s.set_defaults (fun = trace)

    # parse
    s = subparsers.add_parser (
        "parse",
        help = "parse the strace file",
        description = "Create a compilation database from the result by tracing a build command.")
    add_common_opts_parse (s)
    s.add_argument (
        "raw_database",
        default = "./compile_commands.raw",
        nargs = '?',
        help = "the raw database from strace")
    s.add_argument (
        "output",
        default = "./compile_commands.json",
        nargs = '?',
        help = "the output compilor database")
    s.set_defaults (sourceType = "parse")
    s.set_defaults (fun = parse)

    parser.set_default_subparser(len(os.sys.argv) <= 1 and "-h" or "run") # set default subcommand after all subcommand ready
    args = parser.parse_args ()
    return args.fun (args)

# from http://stackoverflow.com/questions/6365601/default-sub-command-or-handling-no-sub-command-with-argparse
def set_default_subparser(self, name, args=None):
    """default subparser selection. Call after setup, just before parse_args()
    name: is the name of the subparser to call by default
    args: if set is the argument list handed to parse_args()

    , tested with 2.7, 3.2, 3.3, 3.4
    it works with 2.6 assuming argparse is installed
    """
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

if __name__ == "__main__":
    try:
        import argparse
        argparse.ArgumentParser.set_default_subparser = set_default_subparser
    except ImportError:
        import arg2opt as argparse
    sys.exit(main())
