#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import copy
import json
import os
import re
import subprocess
import sys

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
    _, ext = os.path.splitext(filename)
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
    EXIT = 1
    CHDIR = 2
    EXEC = 3


chdir_re = re.compile(r"^(\d+) +chdir\((.*)(\)\s+= 0|<unfinished \.\.\.>)")
exec_re = re.compile(r"^(\d+) +execve\((.*)(\)\s*= 0|<unfinished \.\.\.>)")
exit_re = re.compile(r"^(\d+) +\+\+\+ (?:exited with|killed by) ")
fork_re = re.compile(r"^(\d+) +v?fork\((?:.+?\) += (\d+)| <unfinished \.\.\.>)$")
fork_resumed_re = re.compile(r"^(\d+) +<\.\.\. v?fork resumed>\) += (\d+)$")
clone_re = re.compile(r"^(\d+) +clone3?\((?:.+?\) = (\d+)| <unfinished \.\.\.>)$")
child_re = re.compile(r"^(\d+).+?, child_tidptr=.*\) += (\d+)$")
ccache_re = re.compile(r'^([^/]*/)*([^-]*-)*ccache(-\d+(\.\d+){0,2})?$')

parent = {}

def genlineobjs(fname):
    """Parse the lines into objects."""
    obj_list = []
    unfinished_fork = False
    with open(fname, 'r') as fd:  # pre process to sensitive objects
        linum = 0                 # most editor line begin with 1
        for line in fd:
            linum += 1
            m = chdir_re.match(line)
            if m:  # chdir, record this
                pid = m.group(1)
                wdir = eval(m.group(2))
                obj_list.append({
                    'line': linum,
                    'type': OType.CHDIR,
                    'pid': pid,
                    'wd': wdir})
                # print (pid + " chdir:" + proc_run[pid]["cwd"])
                continue

            m = fork_re.match(line)
            if m:
                pid, cid = m.group(1, 2)
                if cid is not None:
                    parent[cid] = pid
                else:
                    unfinished_fork = True
                continue

            m = fork_resumed_re.match(line)
            if m:
                assert unfinished_fork
                pid, cid = m.group(1, 2)
                parent[cid] = pid
                unfinished_fork = False
                continue

            m = clone_re.match(line)
            if m:
                pid, cid = m.group(1, 2)
                if cid is not None:
                    parent[cid] = pid
                else:
                    unfinished_fork = True
                continue

            m = child_re.match(line)
            if m:
                if unfinished_fork:
                    unfinished_fork = False
                    pid, cid = m.group(1, 2)
                    parent[cid] = pid
                continue

            m = exit_re.match(line)
            if m:
                pid = m.group(1)
                obj_list.append({
                    'line': linum,
                    'type': OType.EXIT,
                    'pid': pid})
                continue

            m = exec_re.match(line)
            if m:  # execve, get the compiler
                pid = m.group(1)
                # for strace <=4.11, format:
                #  012 execve("PATH", ["E", "..."], [/* N vars */]) = 0
                # for strace 2018, format:
                #  012 execve("PATH", ["E", "..."], 0xM /* N vars */) = 0
                # remove the tail of execve()
                line = re.sub(r", \[/\* [^*]+ \*/\]", "", m.group(2))
                line = re.sub(r', 0x[^\)]+', '', line)
                (pname, command) = eval(line)
                obj_list.append({
                    "line": linum,
                    "type": OType.EXEC,
                    "pid": pid,
                    "pname": pname,
                    "command": command
                })

        assert not unfinished_fork

    return obj_list


def parse_exec_trace(fname, ppwd, proc_run):
    """Construct the compile tree, and the key is pid, the node contain
proc_run[pid] = {
'cwd': '',   # the last chdir, the child process depend on this value
'child': [], # the child node
'pname': ''  # program name
'command': ''  # the commands
}"""
    obj_list = genlineobjs(fname)
    itr = iter(obj_list)
    while True:
        item = None
        try:
            item = next(itr)
        except StopIteration:
            break

        if item['type'] == OType.EXIT:
            # the child process end, move it to it's parent
            cid = item['pid']
            if cid in proc_run:
                child_item = proc_run[cid]
                del proc_run[cid]  # remove from 'running' process list

                pid = parent.get(cid)
                if pid not in proc_run:
                    # this process end, append it to its parent
                    proc_run[pid] = {"cwd": ppwd,
                                     "child": [],
                                     "pname": "",
                                     "command": ""}
                proc_run[pid]["child"].append({cid: child_item})
            continue

        pid = item['pid']
        if pid not in proc_run:
            # first ocurr in the lines, it's new child process, get the dir
            # try to find the child end log to get its parent
            ppid = parent.get(pid)
            assert ppid is not None or not proc_run, f"{ppid} {pid} {proc_run} {parent}"
            cwd = proc_run[ppid]['cwd'] if ppid in proc_run else ppwd
            proc_run[pid] = {"cwd": cwd,
                             "child": [],
                             "pname": "",
                             "command": ""}

        pobj = proc_run[pid]
        if item['type'] == OType.EXEC:
            # execve, add to the running process
            pobj['pname'] = item['pname']
            pobj['command'] = item['command']
            continue

        if item['type'] == OType.CHDIR:  # chdir, record this
            pobj["cwd"] = os.path.join(pobj["cwd"], item['wd'])
            # print(pid + " chdir:" + pobj["cwd"])
            continue


def print_exec_trace(proc_run, proc_res, auto_sys_inc=False):
    """Print the execute trace in compile data json format."""
    for pid, item in proc_run.items():
        # process the child first, get the reverse results
        for child in item["child"]:
            print_exec_trace(child, proc_res, auto_sys_inc)

        pname, command = item['pname'], item['command']
        if ccache_re.match(pname) is not None:
            # for "ccache", drop first slot (which is "ccache")
            pname = command[1]
            del command[0]

        if ccache_re.match(pname) or compiler_call(pname):
            if len(command) >= 2 and command[1] == "-cc1":
                # ignore the "clang -cc1 ..." call
                continue

            if any([x in ['-M', '-MM'] for x in command]):
                # ignore the -Mx param, which will fork a child to compile
                continue

            sys_inc = []
            if auto_sys_inc:
                sys_inc = get_sys_inc(command[0])

            cmd_files = []
            cmd_opts = []
            for opt in command:  # make item for each
                if is_source_file(opt):
                    if ((len(include_file) > 0
                         and not any((r.search(opt) for r in include_file)))
                        or (len(exclude_file) > 0
                            and any((r.search(opt) for r in exclude_file)))
                        or (len(include_dir) > 0
                            and not any((r.search(opt) for r in include_dir)))
                        or (len(exclude_dir) > 0
                            and any((r.search(opt) for r in exclude_dir)))):
                        continue

                    cmd_files.append(opt)
                else:
                    cmd_opts.append(opt)

            for fname in cmd_files:
                cmds = join_command(cmd_opts + [fname] + sys_inc)
                jstr = shell_quote(cmds)
                cmd = {"directory": item["cwd"],
                       "command": jstr,
                       "file": fname}
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
        "strace", "-z", "-f", "-s" + arg_max, "-etrace=%process,chdir", "-o",
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
    parse_exec_trace(fname, cwd, proc_run)
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
    print_exec_trace(proc_run, proc_res, args.auto_sys_inc)
    json.dump(proc_res, ofs, indent=4)


def run(args):
    """run the build command and generate the compilation database."""
    raw_database = "./compile_commands.raw"
    output = args.output
    args.output = raw_database
    if trace(args) == 0:
        args.output = output  # restore the value
        args.raw_database = raw_database
        parse(args)


def add_common_opts_parse(s):
    """add the opts for subcommand "parse" """
    s.add_argument("--startup-dir",
                   "-s",
                   default='.',
                   help="the startup directory")
    s.add_argument("--auto-sys-inc",
                   "-a",
                   default=True,
                   action="store_true",
                   help="auto detect the system include path")
    s.add_argument("--no-auto-sys-inc",
                   "-A",
                   action="store_false",
                   dest="auto_sys_inc",
                   help="don't auto detect the system include path")
    s.add_argument("--include",
                   "-i",
                   metavar="REGEX",
                   default=[],
                   action="append",
                   help="include the file parten")
    s.add_argument("--exclude",
                   "-e",
                   metavar="REGEX",
                   default=[],
                   action="append",
                   help="exclude the file patten")
    s.add_argument("--include-dir",
                   "-I",
                   metavar="REGEX",
                   default=[],
                   action="append",
                   help="include the dir parten")
    s.add_argument("--exclude-dir",
                   "-E",
                   metavar="REGEX",
                   default=[],
                   action="append",
                   help="exclude the dir patten")


def add_common_opts_trace(parser):
    """add the opts for subcommand "trace" """
    parser.add_argument("command",
                        metavar="COMMAND",
                        nargs=argparse.REMAINDER,
                        help="build command line")


def main():
    "The main function"
    parser = argparse.ArgumentParser(
        description="Generate the compile database from build")
    subparsers = parser.add_subparsers(metavar="SUBCOMMAND")

    # run the compile command and generate the JSON compilation database
    parser_run = subparsers.add_parser(
        "run",
        help="(Default) trace build command, and parse result ",
        description="Create a compilation database by tracing build command.")
    add_common_opts_parse(parser_run)
    add_common_opts_trace(parser_run)
    parser_run.add_argument("--output",
                            "-o",
                            default="./compile_commands.json",
                            help="the strace output file")
    parser_run.set_defaults(fun=run)

    # trace
    parser_trace = subparsers.add_parser(
        "trace",
        help="trace build command",
        description="Create a compilation database by tracing build command.")
    parser_trace.add_argument("--output",
                              "-o",
                              default="./compile_commands.raw",
                              help="the strace output file")
    add_common_opts_trace(parser_trace)
    parser_trace.set_defaults(fun=trace)

    # parse
    parser_parse = subparsers.add_parser(
        "parse",
        help="parse the strace file",
        description="Create compilation database from the tracking log.")
    add_common_opts_parse(parser_parse)
    parser_parse.add_argument("raw_database",
                              default="./compile_commands.raw",
                              nargs='?',
                              help="the raw database from strace")
    parser_parse.add_argument("output",
                              default="./compile_commands.json",
                              nargs='?',
                              help="the output compilor database")
    parser_parse.set_defaults(fun=parse)

    # no subcommand in argv, set the 'run' as default
    if len(sys.argv) >= 2:
        if not any(['-h' in sys.argv,
                    '--help' in sys.argv,
                    sys.argv[1] in ['trace', 'parse', 'run']]):
            sys.argv.insert(1, 'run')
    else:                       # len(sys.argv) == 1
        sys.argv.insert(1, "-h")

    args = parser.parse_args()
    return args.fun(args)


if __name__ == "__main__":
    sys.exit(main())
