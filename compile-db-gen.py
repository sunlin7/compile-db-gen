#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import copy
import json
import os
import re
import subprocess
import sys
from enum import IntEnum


include_file = []
include_dir = []
exclude_file = []
exclude_dir = []


def compiler_call(executable):
    """ A predicate to decide the entry is a compiler call or not. """
    compilers = [
        re.compile(r'^([^/]*/)*([^-]*-)*c(c|\+\+)$'),
        re.compile(r'^([^/]*/)*([^-]*-)*g(cc|\+\+)(-\d+(\.\d+){0,2})?$'),
        re.compile(r'^([^/]*/)*([^-]*-)*clang(\+\+)?(-\d+(\.\d+){0,2})?$'),
        re.compile(r'^([^/]*/)*llvm-g(cc|\+\+)$'),
    ]
    return any((pattern.match(executable) for pattern in compilers))


def is_source_file(filename):
    """ A predicate to decide the filename is a source file or not. """
    accepted = {
        '.c', '.C', '.cc', '.CC', '.cxx', '.cp', '.cpp', '.c++', '.m', '.mm',
        '.i', '.ii', '.mii'
    }
    __, ext = os.path.splitext(filename)
    return ext in accepted


def shell_quote(arg):
    '''Quote the shell arguments'''
    table = {'\\': '\\\\', '"': '\\"', "'": "\\'"}
    return ''.join([table.get(c, c) for c in arg])


def shell_escape(arg):
    """ Create a single string from list.

    The major challenge, to deal with white spaces. Which are used by
    the shell as separator. (Eg.: -D_KEY="Value with spaces") """
    # rtags have bug to deal "-D_KEY=\"V S\"", it only support -D_KEY="\"V S\""
    res = re.search(r'([^\'\"\\]+)([\'\"\\].*)', arg)
    if res:
        return '%s"%s"' % (res.group(1), shell_quote(res.group(2)))
    return arg


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

    p = subprocess.Popen([compiler, "-x", lang, "-E", "-v", "-"],
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    info = p.communicate(input='')[1].decode('utf-8')
    raw_inc = re.compile(r"^.*starts here:((?:.|\n)*?)End of search list.",
                         re.MULTILINE).findall(info)
    if len(raw_inc) > 0:
        incs = re.compile("/.*$", re.MULTILINE).findall(raw_inc[0])
        g_sys_inc[compiler] = ["-I%s" % x for x in incs]
    return g_sys_inc[compiler]


class OType:
    CHILD = 1
    CHDIR = 2
    EXEC = 3


chdir_re = re.compile(r"^(\d+) +chdir\((.*)\)\s+= 0")
exec_re = re.compile(r"^(\d+) +execve(\(.*\))\s+= 0")
child_re = re.compile(r"^(\d+) .*SIGCHLD.*si_pid=(\d+).*")
ccache_re = re.compile(r'^([^/]*/)*([^-]*-)*ccache(-\d+(\.\d+){0,2})?$')


def genlineobjs(fname):
    """Parse the lines into objects."""
    obj_list = []
    with open(fname, 'r') as fd:  # pre process to sensitive objects
        for line in fd:
            m = chdir_re.match(line)
            if m is not None:  # chdir, record this
                pid = m.group(1)
                wdir = eval(m.group(2))
                obj_list.append({'type': OType.CHDIR, 'pid': pid, 'wd': wdir})
                # print (pid + " chdir:" + proc_run[pid]["cwd"])
                continue

            m = child_re.match(line)
            if m is not None:  # the child process end, move it to it's parent
                pid = m.group(1)
                cid = m.group(2)
                obj_list.append({'type': OType.CHILD, 'pid': pid, 'cid': cid})
                continue

            m = exec_re.match(line)
            if m is not None:  # execve, get the compiler
                pid = m.group(1)
                # for strace <=4.11, format:
                #  012 execve("PATH", ["E", "..."], [/* N vars */]) = 0
                # for strace 2018, format:
                #  012 execve("PATH", ["E", "..."], 0xM /* N vars */) = 0
                # remove the tail of execve()
                line = re.sub(r", \[/\* [^*]+ \*/\]", "", m.group(2))
                line = re.sub(r', 0x[^\)]+', '', line)
                (prog_name, command) = eval(line)
                if ccache_re.match(prog_name) is not None \
                   or compiler_call(prog_name):
                    obj_list.append({
                        'type': OType.EXEC,
                        'pid': pid,
                        'prog_name': prog_name,
                        'command': command
                    })

    return obj_list


def get_parent_pid(itr_pid_obj, pid):
    'get parent PID'
    for itr in itr_pid_obj:
        if itr['type'] == OType.CHILD:
            if itr['cid'] == pid:
                return itr['pid']

    return None


def parse_exec_trace(proc_run, fname, auto_sys_inc=False):
    """Construct the compile tree, and the key is pid, the node contain
proc_run[pid] = {
'cwd':'',   # the last chdir, the child process depend on this value
'child':[], # the child node
'cmds': []  # the commands
}"""
    obj_list = genlineobjs(fname)
    itr = iter(obj_list)
    while True:
        item = None
        try:
            item = next(itr)
        except StopIteration:
            break

        pid = item['pid']
        if pid not in proc_run:
            # first ocurr in the lines, it's new child process, get the dir
            # try to find the child end log to get its parent
            ppid = get_parent_pid(copy.copy(itr), pid)
            cwd = proc_run[ppid]['cwd'] if ppid in proc_run else ""
            proc_run[pid] = {"cwd": cwd, "child": [], "cmds": []}

        if item['type'] == OType.CHDIR:  # chdir, record this
            proc_run[pid]["cwd"] = os.path.join(proc_run[pid]["cwd"],
                                                item['wd'])
            # print(pid + " chdir:" + proc_run[pid]["cwd"])
            continue

        if item['type'] == OType.CHILD:
            # the child process end, move it to it's parent
            pid = item['pid']
            cid = item['cid']
            if cid in proc_run:
                item = proc_run[cid]
                del proc_run[cid]  # remove from 'running' process list

                if pid not in proc_run:
                    # this process end, append it to it's parent
                    proc_run[pid] = {"cwd": "", "child": [], "cmds": []}
                # print(pid + " child_end:" + item["cwd"])
                proc_run[pid]["child"].append({cid: item})
            continue

        if item['type'] == OType.EXEC:  # execve, get the compiler
            pid = item['pid']
            prog_name, command = item['prog_name'], item['command']
            if ccache_re.match(prog_name) is not None:
                # for "ccache", drop first slot (which is "ccache")
                prog_name = command[1]
                del command[0]

            if compiler_call(prog_name):
                if len(command) >= 2 and command[1] == "-cc1":
                    # ignore the "clang -cc1 ..." call
                    continue

                if any([x in ['-M', '-MM'] for x in command]):
                    # ignore the -Mx param, which will fork a child to compile
                    continue

                sys_inc = []
                if auto_sys_inc:
                    sys_inc = get_sys_inc(command[0])

                for f in command:  # make item for each
                    if is_source_file(f):
                        if pid not in proc_run:
                            proc_run[pid] = {
                                "cwd": "",
                                "child": [],
                                "cmds": []
                            }

                        # print pid + " execv:" + proc_run[pid]["cwd"]
                        cmds = join_command(command + sys_inc)
                        jstr = shell_quote(cmds)
                        proc_run[pid]["cmds"].append({
                            "directory":
                            proc_run[pid]["cwd"],
                            "command":
                            jstr,
                            "file":
                            f
                        })


def print_exec_trace(proc_run, ppwd, proc_res):
    """Print the execute trace in compile data json format."""
    for pid in proc_run:
        proc = proc_run[pid]

        for child in proc["child"]:
            print_exec_trace(child, ppwd, proc_res)
        for cmd in proc_run[pid]["cmds"]:
            cmd["directory"] = os.path.join(ppwd, cmd["directory"])
            f = cmd["file"]

            if len(include_file) > 0 \
               and not any((r.search(f) for r in include_file)):
                continue
            if len(exclude_file) > 0 \
               and any((r.search(f) for r in exclude_file)):
                continue
            if len(include_dir) > 0 \
               and not any((r.search(f) for r in include_dir)):
                continue
            if len(exclude_dir) > 0 \
               and any((r.search(f) for r in exclude_dir)):
                continue
            proc_res.append(cmd)


def trace(args):
    """Trace the compile command and get the raw compile log."""
    # request strace-4.8 or higher
    proc = subprocess.Popen(["strace", "-V"], stdout=subprocess.PIPE)
    proc.wait()
    s_ver = proc.stdout.read().decode('utf-8')
    # for Ubuntu 18.04, the ver string is "version UNKNOWN"
    m_ver = re.match(r'strace -- version (\d+)\.(\d+)', s_ver)
    if m_ver:
        major = int(m_ver.group(1))
        if major < 4 or (major == 4 and int(m_ver.group(2)) < 8):
            print("strace version should high than 4.8")
            print("Current:" + s_ver)
            sys.exit(1)

    proc = subprocess.Popen(["getconf", "ARG_MAX"], stdout=subprocess.PIPE)
    proc.wait()
    arg_max = str(int(proc.stdout.readline()))
    command = [
        "strace", "-f", "-s" + arg_max, "-etrace=execve,chdir", "-o",
        args.output
    ]
    command += args.command
    # TBD: the output of stdin/stderr maybe very large, hangup happend when try
    # to grabe them, refer the manual of .wait() for detail.
    proc = subprocess.Popen(command)
    proc.wait()

    return proc.returncode


def parse(args):
    """Parse the output from trace and generate the compile_commands.json."""
    proc_run = {}
    fname = args.raw_database
    cwd = os.path.abspath(args.startup_dir)
    parse_exec_trace(proc_run, fname, args.auto_sys_inc)
    ofs = sys.stdout
    if args.output != "" and args.output != "-":
        ofs = open(args.output, "w")

    for i in args.include:
        include_file.append(re.compile(i))
    for i in args.exclude:
        exclude_file.append(re.compile(i))
    for i in args.include_dir:
        include_dir.append(re.compile(i))
    for i in args.exclude_dir:
        exclude_dir.append(re.compile(i))
    proc_res = []
    print_exec_trace(proc_run, cwd, proc_res)
    json.dump(proc_res, ofs, indent=4)


def run(args):
    """run the build command and generate the compilation database."""
    raw_database = "./compile_commands.raw"
    output = args.output
    args.output = raw_database
    if trace(args) == 0:
        args.output = output    # restore the value
        args.raw_database = raw_database
        parse(args)


def add_common_opts_parse(s):
    """add the opts for subcommand "parse" """
    s.add_argument(
        "--startup-dir", "-s",
        default='.',
        help="the startup directory")
    s.add_argument(
        "--auto-sys-inc", "-a",
        default=True,
        action="store_true",
        help="auto detect the system include path")
    s.add_argument(
        "--include", "-i",
        metavar="REGEX",
        default=[],
        action="append",
        help="include the file parten")
    s.add_argument (
        "--exclude", "-e",
        metavar="REGEX",
        default=[],
        action="append",
        help="exclude the file patten")
    s.add_argument(
        "--include-dir", "-I",
        metavar="REGEX",
        default=[],
        action="append",
        help="include the dir parten")
    s.add_argument(
        "--exclude-dir", "-E",
        metavar="REGEX",
        default=[],
        action="append",
        help="exclude the dir patten")


def add_common_opts_trace(s):
    """add the opts for subcommand "trace" """
    s.add_argument(
        "command",
        metavar="COMMAND",
        nargs=argparse.REMAINDER,
        help="build command line")


def main():
    "The main function"

    parser = argparse.ArgumentParser(
        description="Generate the compile database from build")
    subparsers = parser.add_subparsers(metavar="SUBCOMMAND")

    # run the compile command and generate the JSON compilation database
    s = subparsers.add_parser(
        "run",
        help="(Default) trace build command, and parse result ",
        description="Create a compilation database by tracing build command.")
    add_common_opts_parse(s)
    add_common_opts_trace(s)
    s.add_argument(
        "--output", "-o",
        default="./compile_commands.json",
        help="the strace output file")
    s.set_defaults(sourceType="run")
    s.set_defaults(fun=run)

    # trace
    s = subparsers.add_parser(
        "trace",
        help="trace build command",
        description="Create a compilation database by tracing build command.")
    s.add_argument(
        "--output", "-o",
        default="./compile_commands.raw",
        help="the strace output file")
    add_common_opts_trace(s)
    s.set_defaults(sourceType="trace")
    s.set_defaults(fun=trace)

    # parse
    s = subparsers.add_parser(
        "parse",
        help="parse the strace file",
        description="Create compilation database from the tracking log.")
    add_common_opts_parse(s)
    s.add_argument(
        "raw_database",
        default="./compile_commands.raw",
        nargs='?',
        help="the raw database from strace")
    s.add_argument(
        "output",
        default="./compile_commands.json",
        nargs='?',
        help="the output compilor database")
    s.set_defaults(sourceType="parse")
    s.set_defaults(fun=parse)

    # set default subcommand after all subcommand ready
    parser.set_default_subparser(len(os.sys.argv) <= 1 and "-h" or "run")
    args = parser.parse_args()
    return args.fun(args)

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
    sys.exit(main())
