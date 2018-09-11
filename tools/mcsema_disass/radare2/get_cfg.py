#!/usr/bin/env python
#
# Copyright (c) 2019 Breakpoint GmbH/Fraunhofer AISEC
#
#    Julian Schuette (julian@breakpoint-security.de), Samuel Hopstock (samuel.hopstock@aisec.fraunhofer.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# This script depends more or less on the correct radare2 version:
#
# radare2 3.1.0-git 19773 @ linux-x86-64 git.3.0.1-17-g567cdb1fc
# commit: 567cdb1fcfc4a643fd39fc1237c3a0734b4231fa build: 2018-10-23__07:31:40
#
#
# Call this script as follows:
# python __main__.py --disassembler radare2 --arch aarch64 --os linux --output <cfg file> --binary <binary> --entrypoint main
#
# then lift the created .cfg file using mcsema-lift-4.0:
# mcsema-lift-4.0 --cfg <cfg file> --output <bc file> --os linux --arch aarch64
#
# To see all outputs prepend the following variables to the command:
# GLOG_logtostderr=1 GLOG_v=1 GLOG_minloglevel=0 
#

from __future__ import print_function

import argparse
import binascii
import os
import random
import re
import string
import sys
import threading
import time
from Queue import Queue

import r2pipe
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from tqdm import tqdm

import CFG_pb2  # Note: The bootstrap file will copy CFG_pb2.py into this dir!!

# Global switch for turning debugging on/off
DEBUG = False

# hack for r2pipe to see google protobuf lib
if os.path.isdir('/usr/lib/python2.7/dist-packages'):
    sys.path.append('/usr/lib/python2.7/dist-packages')

if os.path.isdir('/usr/local/lib/python2.7/dist-packages'):
    sys.path.append('/usr/local/lib/python2.7/dist-packages')

tools_disass_ida_dir = os.path.dirname(__file__)
tools_disass_dir = os.path.dirname(tools_disass_ida_dir)

# Cache for variables. A map of EAs to discovered Variable objects
VARS = {}
vars_lock = threading.Lock()

# Cache for Instructions. A map of EAs to "aoj" objects
INSTS = {}
insts_lock = threading.Lock()

# Cache for segments, so that we don't have to use iSj hundreds of times
SEGS = {}

# Cache for imported external functions
EXTERNAL_FUNCS = []

# CLI args
args = None

# r2pipe objects
r2 = []

# Create parallel job pool
cpu_count = open('/proc/cpuinfo').read().count('processor\t:')
print("Using %d CPU cores" % cpu_count)
WORKERS = 5
executor = ThreadPoolExecutor(WORKERS)
main_thread_executor = ThreadPoolExecutor(1)
free_workers = Queue()
for i in range(WORKERS):
    free_workers.put(i)


class use_worker(object):
    """
    Used for managing worker IDs for parallel tasks. Use inside a "with" statement: The first available worker is
    chosen, and after the client function exits, the worker ID is being marked as available again.
    """

    def __init__(self):
        self.worker_id = None

    def __enter__(self):
        if free_workers.qsize() == 0:
            raise RuntimeError("All r2 instances marked as busy but a new job has been started")
        self.worker_id = free_workers.get()
        return self.worker_id

    def __exit__(self, exc_type, exc_val, exc_tb):
        free_workers.put(self.worker_id)


M = CFG_pb2.Module()

# xref comment pattern: instruction ; [address location:size?]=(target address) ; "(string value, optional)",
# everything in parentheses is a capture group
xref_comment_pattern = re.compile(r'; \[0x.*:\d*]=((?:0x)?[0-9a-f]*)(?:.* ; "(.*)"$)?')
# alternative xref comment pattern: instruction ; (target address) ; "(string value)"
xref_comment_pattern_2 = re.compile(r'; ((?:0x)?[0-9a-f]*)(?:.* ; "(.*)"$)')


def split_quote_preserving(s):
    """
    Split a string by spaces, preserving quoted substrings.

    This is "a test"  --> ["This", "is", "\"a test\""]
    """
    return [p.replace("\x00", " ") for p in re.sub('".+?"', lambda m: m.group(0).replace(" ", "\x00"), s).split()]


def is_valid_xref(target_ea):
    """
    Returns true if target_ea is located within a segment.
    """
    return get_segment(target_ea) is not None


def get_segment(ea):
    """
    Returns the Segment object that holds the ea or None, if not existing
    """
    for S in M.segments:
        if S.ea <= ea < S.ea + len(S.data):
            return S
    return None


def is_in_code_segment(ea):
    global SEGS

    for s in SEGS:
        if s["vaddr"] <= ea <= s["vaddr"] + s["size"]:
            if "x" in s["perm"] and s["name"] not in [".plt", ".got"]:
                return True
            else:
                return False
    return False


def fix_segment_boundaries(segments):
    """ If necessary, this is the place to correct segment boundaries from radare2.
        For example, IDA summaries ".init_aray" and ".fini_array" in a single ".init_array"

        Also, some Mach-O files seem to have segments which overlap by one byte. McSema does not like that
        and we might want to fix that here.
    """
    pass


def is_external_func(ea):
    """
    Returns true if given ea is not contained in a .text segment
    """
    global SEGS, EXTERNAL_FUNCS

    if ea in EXTERNAL_FUNCS:
        return True

    for s in SEGS:
        if s['vaddr'] <= ea <= s['vaddr'] + s['size']:
            if s['name'] == '.rodata':
                return False
            if 'x' in s['perm'] and s['name'] not in ['.plt', '.got']:
                # Check only eXecutable segments, no PLT/GOT (dynamically linked external functions)
                return False
            else:
                debug("External function: 0x%02x" % ea)
                return True
    debug("is_external_func: no segment found for 0x%02x" % ea)
    return True


def create_name_for_string_var(ea, s):
    """
    Creates an IDA Pro-like(ish) variable name for a string variable, based on its content.
    This method does not care about uniqueness of variable names.
    Its caller is responsible for further modifying the name to make it unique.
    "This is a test string"  -->  "aThisIsATestStr"
    """
    s = s.title()
    regex = re.compile(r"[^a-zA-Z.]")
    s = regex.sub("", s)
    s = s.replace('"', '')
    s = s.replace('.', '_')
    s = s.replace(' ', '')
    s = s.replace(' ', '')
    s = 'a' + s[:14]

    # Now make it unique
    counter = 0
    while s in VARS.values():
        s = s + '_' + str(counter)
        counter = counter + 1
    VARS[ea] = s

    return s


def must_resolve_xref(aoj_object):
    """
    Returns true if the given JSON result of the "aoj" command indicates a data xref by "imm" or "mem".
    """
    for obj in aoj_object:
        if u'opex' in obj:
            if u'operands' in obj[u'opex']:
                for op in obj[u'opex'][u'operands']:
                    if op[u'type'] == 'imm' or op[u'type'] == 'mem':
                        return True
    return False


def get_xrefs_from_dasm_comment(aoj_obj, comment):
    """
    Generator that parses the comment part of a line of radare2 disassembly
    and returns a (possibly empty) list of CodeReference objects.
    """
    matches = xref_comment_pattern.findall(comment) or xref_comment_pattern_2.findall(comment)
    if matches:
        variable_ea, variable_content = matches[0]
    else:
        # no correct variable usage
        return
    try:
        base = 16 if "0x" in variable_ea else 10
        variable_ea = long(variable_ea, base)
    except ValueError as e:
        debug("Error getting variable ea: %s" % str(e))
        return

    xref_data = {}

    with vars_lock:
        var_name = ''
        if variable_content:
            var_name = create_name_for_string_var(variable_ea, variable_content)

        # If we could not find a name here, look up cache if variable has a known name
        if var_name == '' and variable_ea in VARS:
            var_name = VARS[variable_ea]

        # if variable still does not have a name, just set any random string. Empty names are not allowed by mcsema.
        if var_name == '':
            var_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            VARS[variable_ea] = var_name

    # Add xref to instruction
    xref_data["ea"] = variable_ea
    xref_data["target_type"] = CFG_pb2.CodeReference.DataTarget
    xref_data["operand_type"] = CFG_pb2.CodeReference.ImmediateOperand  # or CFG_pb2.CodeReference.MemoryOperand ?
    xref_data["location"] = CFG_pb2.CodeReference.External if is_external_func(
        xref_data["ea"]) else CFG_pb2.CodeReference.Internal
    xref_data["name"] = var_name

    # Add variable to segment
    data_segment = get_segment(xref_data["ea"])
    if data_segment is not None:
        debug("Adding to data segment")
        existing_var = next(iter([v for v in data_segment.vars if v.ea == xref_data["ea"]]), None)
        if existing_var is not None:  # Merge with existing var
            existing_var = xref_data["name"] if xref_data["name"] != '' else existing_var.name
        else:
            var = data_segment.vars.add()
            var.ea = xref_data["ea"]
            var.name = xref_data["name"]

    if var_name[:4] == 'obj.':
        xref_data["name"] = var_name[4:]
    return xref_data


def run(cmd, workers=None):
    if workers is None:
        workers = range(WORKERS)

    if len(workers) == 1:
        result = r2[workers[0]].cmd(cmd)
    else:
        futures = [executor.submit(r2[i].cmd, cmd) for i in workers]
        result = [f.result() for f in as_completed(futures)][0]
    return result


def runj(cmd, workers=None):
    if workers is None:
        workers = range(WORKERS)

    result = None
    try:
        if len(workers) == 1:
            result = r2[workers[0]].cmdj(cmd)
        else:
            futures = [executor.submit(r2[i].cmdj, cmd) for i in workers]
            result = [f.result() for f in as_completed(futures)][0]
    except IOError as e:
        print("ERROR %s" % e)
    return result


def debug(msg):
    global args

    if args.debug:
        print(msg)


def info(msg):
    print("\x1b[1;32;1m%s\x1b[0m" % msg)


class Debug:
    global args

    def write(self, msg):
        if args.debug:
            print(msg)

    def flush(self):
        pass


def print_asciiart():
    """
    Now this is what happens if you have to spend 2 hrs at the airport for the flight home...
    """
    print("")
    print("\x1b[1;37m           |")
    print("\x1b[1;37m           |")
    print("\x1b[1;37m          / \\")
    print("\x1b[1;37m         /   \\")
    print("\x1b[1;37m        /_____\\")
    print("\x1b[1;37m       |       |")
    print("\x1b[1;37m       |       |")
    print("\x1b[1;37m       |  |r|  |")
    print("\x1b[1;37m       |  |a|  |")
    print("\x1b[1;37m       |  |d|  |")
    print("\x1b[1;37m       |  |a|  |")
    print("\x1b[1;37m       |  |r|  |")
    print("\x1b[1;37m       |  |e|  |")
    print("\x1b[1;37m       |  |2|  |")
    print("\x1b[1;37m       |       |")
    print("\x1b[1;37m       |       |")
    print("\x1b[1;37m      /| ##!## |\\")
    print("\x1b[1;37m     / | ##!## | \\")
    print("\x1b[1;37m    /  | ##!## |  \\")
    print("\x1b[1;37m   |  /  ^ | ^  \\  |")
    print("\x1b[1;37m   | /\x1b[1;33m   ( | )  \x1b[0m \\ |")
    print("\x1b[1;37m   |/\x1b[1;33m    ( | )  \x1b[0m  \\|")
    print("     \x1b[1;33m   ((   ))\x1b[0m")
    print("     \x1b[1;33m  ((  :  ))\x1b[0m")
    print("     \x1b[1;33m  ((  :  ))\x1b[0m")
    print("     \x1b[1;33m   ((   ))\x1b[0m")
    print("     \x1b[1;33m    (( ))\x1b[0m")
    print("     \x1b[1;33m     ( )\x1b[0m")
    print("           .")
    print("           .")


def main(a, command_args):
    """
    This is where the magic begins.
    """
    global r2
    global args
    start = time.time()

    args = a

    if args.debug:
        print("Debug on")

    sys.stderr = Debug()
    os.environ['R_DEBUG'] = "1"
    M.name = args.binary[args.binary.rfind("/") + 1:]

    print()
    print("Lifting %s ... " % args.binary)

    #print_asciiart()

    initial_analysis(args)

    info("Analyzing exported symbols")
    exported = [e["vaddr"] for e in runj("iEj")]

    # Analyze flags (global variables)
    info("Analyzing global variables")
    vars_global = runj("isj")

    analyze_segments(vars_global)
    funcs = analyze_functions()
    code_xrefs = analyze_xrefs()
    analyze_basic_blocks(exported, funcs, code_xrefs)

    for r in r2:
        r.quit()
    info("Saving to: {0}".format(args.output))
    f = open(args.output, "wb")
    f.write(M.SerializeToString())
    f.close()
    end = time.time()
    print("Runtime: %.2f seconds" % (end - start))


def analyze_basic_blocks(exported, funcs, code_xrefs):
    """
    Array of function objects looking like this:
    {u'calltype': u'arm32', u'realsz': 4, u'diff': u'NEW', u'name': u'method.GADRequest.setBirthdayWithMonth:day:year:',
    u'cc': 1, u'indegree': 0, u'maxbound': u'195056', u'minbound': u'195052', u'difftype': u'new', u'edges': 0,
    u'outdegree': 0, u'range': u'4', u'cost': 0, u'nargs': 0, u'nlocals': 0, u'offset': 195052, u'ebbs': 1, u'nbbs': 1,
    u'type': u'fcn', u'size': 4}, {u'calltype': u'arm32', u'realsz': 4, u'diff': u'NEW',
    u'name': u'method.GADRequest.setLocationWithLatitude:longitude:accuracy:', u'cc': 1, u'indegree': 0,
    u'maxbound': u'195060', u'minbound': u'195056', u'difftype': u'new', u'edges': 0, u'outdegree': 0, u'range': u'4',
    u'cost': 0, u'nargs': 0, u'nlocals': 0, u'offset': 195056, u'ebbs': 1, u'nbbs': 1, u'type': u'fcn', u'size': 4}
    """

    info("Analyzing basic blocks, local vars ...")
    print("Getting basic blocks for all functions from r2")
    # After our parallelized jobs have finished, we need to fill the basic block stubs with more info. For this, we
    # need a way of uniquely identifying the basic blocks we have. This is done by a dict: bb_id -> BB
    func_futures = []
    bb_lookup = []
    for func in sorted(funcs, key=lambda func: func[u"offset"]):
        func_futures += [executor.submit(analyze_bbs_for_function, exported, func, code_xrefs)]

    for future in tqdm(iterable=as_completed(func_futures), total=len(func_futures), unit=" func", file=sys.stdout):
        result = future.result()
        if result:
            F, bb_lookup_items = result
            attached_F = M.funcs.add()
            attached_F.CopyFrom(F)
            bb_lookup += [(attached_F, bb_lookup_items)]

    print("Waiting for basic block analysis results")
    if args.debug:
        # collect all bb futures in one list to wait for
        bb_futures = []
        for F, bb_lookup_items in bb_lookup:
            bbs, bb_futures_for_f = zip(*bb_lookup_items)
            bb_futures.extend(bb_futures_for_f)
        wait(bb_futures)
    else:
        bb_futures = []
        for F, bb_lookup_items in bb_lookup:
            bbs, bb_futures_for_f = zip(*bb_lookup_items)
            bb_futures.extend(bb_futures_for_f)
        for _ in tqdm(iterable=as_completed(bb_futures), total=len(bb_futures), unit=" bb", file=sys.stdout):
            pass  # display progress bar while waiting

    for F, bb_lookup_items in bb_lookup:
        # now we have the instructions for the basic blocks (those are still empty at the moment)
        for bb, future in bb_lookup_items:
            bb_instrs = future.result()
            for I in bb_instrs:
                bb.instructions.add().CopyFrom(I)
            # now attach the finished basic block to the function
            F.blocks.add().CopyFrom(bb)


def analyze_bbs_for_function(exported, func, code_xrefs):
    with use_worker() as worker_id:
        F = CFG_pb2.Function()
        F.name = func[u'name'].replace("sym.imp", "").replace("sym.", "")  # Name of function (yes, key is unicode)
        F.ea = func[u'offset']  # ea of function
        F.is_entrypoint = F.ea in exported

        bb_lookup = []

        ################## Basic Blocks per Function ###############################
        debug("Getting basic blocks in function %s at 0x%02x" % (F.name, F.ea))
        bbs = runj("afbj 0x%02x" % F.ea, workers=[worker_id])  # Get basic blocks as JSON
        # make sure it is a list and not the string "[]" representing an empty list
        if bbs is None or len(bbs) == 0:
            debug("radare2 cannot parse basic block at 0x%02x" % F.ea)
            return

        # check if there is a correct entry block (block["addr"] == F.ea)
        if not any(bb["addr"] == F.ea for bb in bbs):
            debug("Function %s at 0x%02x has no basic block at the function offset: skipping" % (F.name, F.ea))
            return

        # radare2 considers BLX and BL instructions not as end of basic block. This is correct,
        # as BLX goes to external symbol objc_msgSend and does not branch the intraprocedural flow.
        for bb in sorted(bbs, key=lambda bb: bb['addr']):
            ''' each BB looks like this:
                {"jump":451312,"fail":451296,"addr":451272,"size":24,"inputs":0,"outputs":2,"ninstr":0,"traced":false},
            '''
            BB = CFG_pb2.Block()  # Create new block in function

            # xrefs = []  # List of CodeReference

            BB.ea = bb['addr']  # Address of basic block
            if u"jump" in bb:
                BB.successor_eas.append(bb[u'jump'])  # Address of successor
                debug("   Successor (jump) from %d to %d" % (BB.ea, bb[u'jump']))
            if u"fail" in bb:
                BB.successor_eas.append(bb[u'fail'])  # Address of successor
                debug("   Successor (fail) %d" % bb[u'fail'])
            # Note: May create exception handlers from eh_frame here.

            instrs = runj("pdbj @0x%02x" % BB.ea, workers=[worker_id])

            if not instrs or len(instrs) == 0:
                return
            # mapping: (basic block, future for this bb's instructions)
            bb_lookup += [(BB, executor.submit(analyze_bb_instructions, F, instrs, code_xrefs))]
        return F, bb_lookup


def analyze_bb_instructions(F, instrs, code_xrefs):
    with use_worker() as worker_id:
        protobuf_instrs = []
        for inst in instrs:
            # print("INST: %s"%inst)
            # Instructions can also be of type "invalid" and have no "bytes" key
            if u"bytes" in inst and inst[u"bytes"] != '':
                I = CFG_pb2.Instruction()
                I.ea = inst[u"offset"]
                bytes_list = binascii.unhexlify(inst[u"bytes"])  # Turns "08208de5" into "\x08 \x8d\xe5"
                I.bytes = bytes_list
                I.local_noreturn = inst[u"opcode"][:2] == "b"

                # Code XRef for branches
                branch_type = None
                if u"jump" in inst:
                    # True branch
                    branch_type = u"jump"
                elif u"fail" in inst:
                    # False branch
                    branch_type = u"fail"
                if branch_type and inst[branch_type] != I.ea + inst[u"size"]:
                    if not get_segment(inst[branch_type]):
                        debug("Branch target not in a segment, skipping: 0x%02x -> 0x%02x" % (I.ea, inst[branch_type]))
                        continue
                    xref_branch = I.xrefs.add()
                    xref_branch.ea = inst[branch_type]
                    xref_branch.target_type = CFG_pb2.CodeReference.CodeTarget if not is_external_func(
                        xref_branch.ea) else CFG_pb2.CodeReference.DataTarget
                    xref_branch.operand_type = CFG_pb2.CodeReference.ControlFlowOperand
                    xref_branch.location = CFG_pb2.CodeReference.External if is_external_func(
                        xref_branch.ea) else CFG_pb2.CodeReference.Internal
                    name_of_jmp_target = runj("fdj %d" % xref_branch.ea, workers=[worker_id]).get(u"name", "") \
                        .replace("sym.", "").replace("imp.", "")
                    xref_branch.name = name_of_jmp_target if name_of_jmp_target != F.name else ""

                if I.ea in code_xrefs:
                    debug("Code xrefs found for instruction 0x%02x" % I.ea)
                    attach_xrefs(I, code_xrefs[I.ea])

                # Additional Code XRef
                # radare2 does not always properly provide xrefs.
                # We must parse them from each statement's JSON.
                with insts_lock:
                    if I.ea not in INSTS:
                        INSTS[I.ea] = runj("aoj @%d" % I.ea, workers=[worker_id])
                    aoj_object = INSTS[I.ea]

                if must_resolve_xref(INSTS[I.ea]):
                    instrs_formatted = runj("pdJ 1 @0x%02x" % I.ea, workers=[worker_id])
                    # can be None in case of invalid instructions
                    if not instrs_formatted:
                        continue
                    commented_assembly = instrs_formatted[0]["text"]

                    xref_from_comment = get_xrefs_from_dasm_comment(aoj_object, commented_assembly)
                    if xref_from_comment and I.ea not in code_xrefs:
                        attach_xrefs(I, [xref_from_comment])
                protobuf_instrs += [I]
        return protobuf_instrs


def analyze_xrefs():
    info("Analyzing xrefs ...")
    print("Getting raw xrefs from r2")
    xrefs_from_r2 = runj("axj")
    word_size = int(run("? $w|grep int32").split()[
                        1])  # trick to find out the word (=pointer) size. 4 for 32 bit apps, 8 for 64 bit apps.
    debug("Word size %d" % word_size)
    code_xrefs, data_xrefs = {}, {}
    unknown_operands = {}

    print("Analyzing raw xrefs")
    futures = [executor.submit(analyze_xref, r, word_size) for r in
               sorted(xrefs_from_r2, key=lambda xref: xref["from"])]

    for future in tqdm(iterable=as_completed(futures), total=len(futures), file=sys.stdout, unit=" xref", disable=args.debug):
        result = future.result()
        if result:
            is_code_xref, caller_ea, xref = result
            dest_dict = code_xrefs if is_code_xref else data_xrefs
            if caller_ea not in dest_dict:
                dest_dict[caller_ea] = []
            dest_dict[caller_ea] += [xref]

    for ea, xrefs in data_xrefs.items():
        segment = get_segment(ea)
        debug("Data xref found for segment %s" % segment.name)
        attach_xrefs(segment, xrefs)

    if unknown_operands:
        print("Unknown operands (with last seen opcode sample): %s" % unknown_operands)
    return code_xrefs


def analyze_xref(r, word_size):
    with use_worker() as worker_id:
        # print("x %s"%xs_result)
        reftype = r["type"]  # possible values: DATA, CODE, CALL, UNKNOWN
        caller_ea = r["from"]

        # radare2 xrefs point at the exact address called.
        # However, in McSema CFG file, xrefs point to the start of the referenced function.
        callee_ea = r["addr"]

        if not get_segment(caller_ea) or not get_segment(callee_ea):
            debug("xref 0x%02x -> 0x%02x not in a segment" % (caller_ea, callee_ea))
            return
        if get_segment(r["from"]).name == "cstring":
            debug("xref 0x%02x -> 0x%02x: caller in cstring, skipping" % (caller_ea, callee_ea))
            return

        # Correct callee_ea by offset
        callee_info = runj("fdj %d" % callee_ea, workers=[worker_id])
        callee_offset = callee_info.get(u"offset", 0)
        callee_name = r["refname"].replace("sym.", "").replace("imp.", "")
        # Note: The above line is not necessarily correct.
        #  if "callee_ea" points to a data segment,
        #  "fdj" will still provide the name of the (last) method from code segment,
        #  although we are clearly not referencing a jump, but data.
        #  Needs to be fixed and currently leads to McSema error "Null basic block in function"

        if is_in_code_segment(caller_ea):
            xref = analyze_code_xref(caller_ea, callee_ea, callee_name, reftype, worker_id)
            if xref:
                return True, caller_ea, xref
            else:
                return
        else:
            xref = {'ea': long(caller_ea),  # address of calling instruction
                    'width': word_size,  # size of the reference (mostly pointer size, thus hardcoded to word_size)
                    'target_ea': callee_ea,  # address of target
                    'target_name': callee_name,  # name of target function (may be None)
                    'target_is_code': is_in_code_segment(callee_ea),
                    'target_fixup_kind': CFG_pb2.DataReference.Absolute
                    }
            return False, caller_ea, xref


def analyze_code_xref(caller_ea, callee_ea, callee_name, reftype, worker_id):
    operand_special_cases = {
        "adrp": CFG_pb2.CodeReference.MemoryOperand,
        "adr": CFG_pb2.CodeReference.MemoryOperand
    }

    # Find out what we are referencing here (data or code)
    if reftype == "DATA":
        target_type = CFG_pb2.CodeReference.DataTarget
    else:
        # Targets to external functions in .got or .plt segments are also data references.
        if is_external_func(callee_ea):
            target_type = CFG_pb2.CodeReference.DataTarget
        else:
            target_type = CFG_pb2.CodeReference.DataTarget if reftype == "UNKNOWN" else CFG_pb2.CodeReference.CodeTarget

    # Find out what type of operand the instruction uses (use INSTS cache, if available)
    if caller_ea not in INSTS:
        INSTS[caller_ea] = runj("aoj @%d" % caller_ea, workers=[worker_id])

    opcode_analysis = INSTS[caller_ea]
    if opcode_analysis is None or len(opcode_analysis) == 0:
        debug("ERROR: Opcode analysis for 0x%02x did not return anything." % caller_ea)
        return
    elif opcode_analysis[0]["opcode"] == "invalid":
        debug("Invalid opcode at 0x%02x" % caller_ea)
        return

    opexes = opcode_analysis[0].get("opex", {u'operands': None}).get(u'operands', None)
    operand = None
    if opexes is not None and opcode_analysis[0][
        "mnemonic"] != "invalid":  # may be None in case of invalid instructions
        types = [opex["type"] for opex in opexes]
        if opcode_analysis[0]["mnemonic"] in operand_special_cases:
            # for some instructions like adrp, r2 reports the operand as an immediate even though this is incorrect
            # See armv8 manual, chapter C3
            operand = operand_special_cases[opcode_analysis[0]["mnemonic"]]
        elif "mem" in types:
            operand = CFG_pb2.CodeReference.MemoryDisplacementOperand
        elif "imm" in types:
            opcode_type = opcode_analysis[0]["type"]
            if opcode_type in ["call", "jmp", "cjmp"]:
                operand = CFG_pb2.CodeReference.ControlFlowOperand
            elif opcode_type in ["lea"]:
                operand = CFG_pb2.CodeReference.MemoryOperand
            else:
                operand = CFG_pb2.CodeReference.ImmediateOperand
        elif len(types) > 0 and all(t == "reg" for t in types):
            # only register operands, r2 probably knows which value a specific register has and thus treats this
            # as a xref. Let's treat this as a memory operand
            operand = CFG_pb2.CodeReference.MemoryOperand
        else:
            commented_asm = [asm["text"] for asm in runj("aav;pdJ 1 @0x%02x" % caller_ea, workers=[worker_id])]
            if any(".dword" in asm for asm in commented_asm):
                debug("Skipping .dword element: 0x%02x: %s" % (caller_ea, commented_asm))
                return
            else:
                debug("Unknown operand, skipping: 0x%02x: %s" % (caller_ea, commented_asm))
            # Note There are more OperandTypes which could be added here. What are the possible types r2 can output??
            return

    else:
        return
    if operand is None:
        debug("No operand type: 0x%02x %s" % (caller_ea, opcode_analysis[0]["opcode"]))
        operand = CFG_pb2.CodeReference.MemoryOperand

    debug("Caller xref %s" % caller_ea)

    if callee_ea in EXTERNAL_FUNCS:
        location = CFG_pb2.CodeReference.External
    else:
        location = CFG_pb2.CodeReference.Internal
    xref = {
        'ea': long(callee_ea),
        'target_type': target_type,
        'operand_type': operand,
        'location': location,
        'name': callee_name
    }
    return xref


def attach_xrefs(target_item, xrefs):
    for xref in xrefs:
        X = target_item.xrefs.add()
        for k, v in xref.items():
            # match protobuf values with the dict entries, e.g. X.ea = xref["ea"]
            setattr(X, k, v)


def analyze_functions():
    info("Analyzing functions ...")
    # run("aas")  # Analyze function boundaries by following symbols
    debug("Getting functions ...")
    funcs = runj("aflj")
    info("Analyzing imports (external functions)...")
    imports = runj("iij")
    global EXTERNAL_FUNCS
    EXTERNAL_FUNCS = []
    for i in imports:
        if i["type"] != "FUNC":
            continue
        E = M.external_funcs.add()
        E.name = i["name"]
        E.ea = i["plt"]
        EXTERNAL_FUNCS += [E.ea]
        # radare gives no further information about external functions and there is no file with function definitions
        # as for Linux/Windows, so we have to guess what would make sense
        E.argument_count = 0
        # ARM uses FastCall as it has enough registers for arguments (x0-x7)
        E.cc = CFG_pb2.ExternalFunction.FastCall
        E.is_weak = False  # strong references are the default
        # We don't have a nice list for iOS/OSX, but it looks like most of the functions have a 'N' in linux.txt
        ret = 'N'
        E.no_return = ret == 'Y'
        E.has_return = ret == 'N'
    return funcs


def analyze_segments(vars_global):
    info("Analyzing sections/segments")
    global SEGS
    SEGS = runj("iSj")
    for seg in SEGS:
        if seg[u"vsize"] == 0:
            continue
        if seg[u"vaddr"] == 0:  # Skip empty segments. They do not contain code but are only loaded by the linker
            continue

        # Skipping a few segments that are irrelevant (and not lifted by IDA as well)
        if any(skip_seg in seg["name"] for skip_seg in [".gnu", ".note", ".rela", ".interp", ".dynsym", ".dynstr",
                                                        ".dynamic"]):
            continue

        S = CFG_pb2.Segment()
        S.ea = seg[u"vaddr"]  # vaddr, not paddr!
        S.read_only = 'w' not in seg["perm"]
        ea_end = seg[u"vaddr"] + seg[u"vsize"] - 1
        name_m = re.search(r'(\d+)\.(\w+)\.(\w+)', seg[u"name"])  # index, category, name
        if name_m is not None and len(name_m.groups()) >= 3:
            S.name = name_m.group(3).replace("__", "")
            S.is_external = u'XTRN' in name_m.group(2)
        else:
            S.name = seg[u"name"]
            # SEG_XTRN is an IDA pseudo-segment for symbols not belonging to any other segment, so possibly no r2
            # equivalent (also see CFG.cpp:273, xrefs targeting unknown segments treated as external segment calls).
            S.is_external = False
        S.is_exported = False # Note: Determine exportedness
        S.is_thread_local = u"__TLS" in seg[u"name"] or u".TLS" in seg[u"name"]
        if seg[u"vsize"] > 0:
            data = runj("pxj %d @0x%02x" % (seg[u"vsize"], S.ea))
            # data may be None if "pxj 71098340 @0xBB10" fails with "Block size too big".
            # Note: Unclear if max blocksize in radare2 can be increased
            if data is not None:
                S.data = ''.join(chr(byt) for byt in data)
            for v in vars_global:
                if S.ea <= v["vaddr"] < S.ea + len(S.data) and v["type"] == "OBJ" and v["type"] != "" \
                        and v["name"][:1] != "_":
                    var = S.vars.add()
                    var.ea = v["vaddr"]
                    var.name = v["name"]

        M.segments.extend([S])
        info("    Segment %s (%s bytes)" % (S.name, len(S.data)))


def initial_analysis(args):
    global r2
    r2_flags = []
    if args.debug:
        r2_flags = ['-0']  # -0 prints backtrace and attempts ptrace attach when radare2 crash
    else:
        r2_flags = ['-2']  # -2 closes stderr of r2 to suppress warnings.
    r2 = [r2pipe.open(args.binary, flags=r2_flags) for _ in range(WORKERS)]
    file_info = runj("ij")
    info("Analyzing ...")
    print("  %s: %s (%s, %s bits %s)" % (
        file_info['core'][u'type'], file_info['bin'][u'bintype'], file_info['bin'][u'arch'], file_info['bin'][u'bits'],
        file_info['bin']['machine']))
    run("e anal.vars=true")  # Enable variable analysis (required later).
    run("e scr.color=0")  # Remove ANSI colors, as they may crash the r2pipe
    run("e anal.a2f=false")
    run("e anal.bb.maxsize=4096")  # increasing max size of basic blocks (required for some apps)
    run("e anal.ptrdepth=3")  # Maximum number of nested pointers to follow in analysis
    run("e anal.esil=false")  # Use the new radare2 ESIL code analysis - does not work yet
    run("e anal.noncode=false")
    run("e anal.vinfun=true")  # Needed in order to correctly identify .dword pointers inside functions (r2 issue 6653)    
    run("aaa")  # # Now run radare2 disassembly + analysis (Auto analysis)

    '''
    Note: The following commands do what "aaa" does, but excluding "afta" (type matching for functions, unneeded and slow)
        run("afna")
        run("aac")
        run("aar")
        run("aan")
        run("aav")
        run("af@@= `iE~[2]`;afva") # Fast and not too bad. Analyzes Functions, starting at all exported symbols (iE)
        run("afr @@= `iE~[2]`;afva")  # Analyzes Functions recursively, starting at all exported symbols (iE)
        run("afr @@= `isq~[0]`")  # Analyzes Functions recursively starting at all (@@) Symbols (isq~[0] means print symbols, first column)
    '''


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    if args.debug:
        print("Debug is on")
        DEBUG = True

    main(args, command_args)
