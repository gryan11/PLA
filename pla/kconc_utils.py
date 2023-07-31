from tqdm import tqdm
from collections import namedtuple, defaultdict
from copy import copy
from functools import reduce
import subprocess as sp
from types import SimpleNamespace
import re, json, os, pickle, random, csv, sys
import lz4.frame
from contextlib import suppress
import hashlib, filelock
from glob import glob
from filelock import UnixFileLock
import psutil, signal
import operator as op
import pandas as pd
import itertools


# TraceRW = namedtuple('TraceRW', ['pid', 'ip', 'addr', 'size', 'rw_type', 'loc'])
# TraceLock = namedtuple('TraceLock', ['pid', 'lock_addr', 'action', 'lock_type', 'meta'])
# TraceSyscall = namedtuple('TraceSyscall', ['pid', 'syscall', 'action', 'NR', 'args', 'ret'])

RaceCheckResult = namedtuple('RaceCheckResult',
        ["wp_input","other_input",
                        "wp_ip", "wp_addr",
                        "barrier0_set", "barrier1_set",
                        "barrier0_passed", "wp_set", "barrier1_passed",
                        "race_found",
                        "race_ips", "err", "msg"])

# MemOp = namedtuple('MemOp', ['idx', 'pid', 'ip', 'addr', 'size', 'rw_type', 'loc', 'lockset', 'label'])

RANDOM = 'random'
GREEDY = 'greedy'
RARE_FIRST = 'rare_first'

GB = 1_000_000_000


RW = 'rw'
LOCK = 'lock'
SYS = 'sys'
DBG = 'dbg'
ATOMIC = 'atomic'

KCSAN_WRITE = (1<<0)
KCSAN_READWRITE = (1<<1)
KCSAN_ATOMIC = (1<<2)
KCSAN_ASSERTION = (1<<3)
KCSAN_SCOPED = (1<<4)
KCSAN_IS_ATOMIC = (1<<5)

IS_FLAT_ATOMIC = (1<<6)
IS_ATOMIC_NEXT = (1<<7)
IS_ATOMIC_NEST = (1<<8)

ATOMIC_NEST_ENTER = (1<<9)
ATOMIC_NEST_EXIT  = (1<<10)
ATOMIC_FLAT_ENTER = (1<<12)
ATOMIC_FLAT_EXIT = (1<<13)
ATOMIC_NEXT_SET = (1<<11)

IS_ATOMIC_META = ATOMIC_NEST_ENTER | ATOMIC_NEST_EXIT  | \
                ATOMIC_FLAT_ENTER | ATOMIC_FLAT_EXIT | \
                ATOMIC_NEXT_SET


LOCK_IGNORE_LIST = ('read rcu_read_lock')


sys_return_re = re.compile(r'sys_(\w+) -> (.*)')
sys_name_re = re.compile(r'sys_(\w+)')
parens_comma_re = re.compile(r'\(|\)|,')


def basename(fpath):
    return fpath.split('/')[-1].split('.')[0]


class SharedCSV():

    def __init__(self, out_f, header):
        self.out_f = out_f
        self.header = header
        self.lock_f = out_f+'.lock'

        with open(out_f, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)

    def writerows(self, rows):
        if not rows:
            return

        if not len(rows[0]) == len(self.header):
            print('ERROR row header mismatch')
            print('header:', self.header)
            print('row:', row)

        lock = UnixFileLock(self.lock_f)

        with lock.acquire():
            with open(self.out_f, 'a') as f:
                writer = csv.writer(f)
                writer.writerows(rows)


class ListMap():

    def __init__(self):
        self.list = []
        self.map = {}

    def add(self, item):
        if item not in self.map:
            item_id = len(self.list)
            self.map[item] = item_id
            self.list += [item]
        else:
            item_id = self.map[item]

        return item_id

    def get(self, item_id):
        return self.list[item_id]


class LocMap():

    def __init__(self, init_file=None):

        self.filemap = ListMap()
        self.funcmap = ListMap()
        self.ip_locs = {}

        if init_file:
            self.load(init_file)

    def add(self, ip, filen, line, func):
        file_id = self.filemap.add(filen)
        func_id = self.funcmap.add(func)

        self.ip_locs[ip] = (file_id, line, func_id)

    def get_loc(self, ip):
        file_id, line, func_id = self.ip_locs[ip]
        filen = self.filemap.get(file_id)
        func = self.funcmap.get(func_id)

        return filen, line, func

    def save(self, json_fn):
        data = {'ip_locs':self.ip_locs,
                'file_list':self.filemap.list,
                'func_list':self.funcmap.list}
        with open(json_fn, 'w') as f:
            json.dump(data, f)

    def load(self, json_fn):
        with open(json_fn, 'r') as f:
            data = json.load(f)

        self.ip_locs = data['ip_locs']
        self.filemap.list = data['file_list']
        self.funcmap.list = data['func_list']

    def __contains__(self, item):
        return item in self.ip_locs

    def __getitem__(self, key):
        return self.get_loc(key)


def db_getall(db, key):
    agg = []
    i = 0
    while f'{key}-{i}' in db:
        agg += [ loads_pz4(db[f'{key}-{i}']) ]
        i += 1

    return agg


def db_addnext(db, key, val):
    i = 0
    while f'{key}-{i}' in db:
        i += 1

    db[f'{key}-{i}'] = dumps_pz4(val)


def tobytes(val):
    if isinstance(val, bytes):
        return val
    elif isinstance(val, str):
        return bytes(val, 'utf8')
    else:
        return pickle.dumps(val)


def md5hex(val):
    return hashlib.md5(hash(val)).hexdigest()


class PklTrieDir():

    def __init__(self, base_d, hash_dirs=True):
    # def __init__(self, base_d):
        self.base_d = base_d
        # self.keystore_f = f'{base_d}/keystore.db'
        # self.keystore_lock = f'{base_d}/keystore.lock'
        self.hash_dirs = hash_dirs

    def tokeydir(self, key):
        dkey = key.split('-')[0]
        if self.hash_dirs:
            dkey = hashlib.md5(dkey.encode('utf8')).hexdigest()[:10]

        dks = [dkey[i:i+2] for i in range(0, len(dkey), 2)]
        keydir = '/'.join([self.base_d] + dks)
        return keydir

    def topath(self, key):
        keydir = self.tokeydir(key)
        return f'{keydir}/{key}.pkl.lz4'

    def __contains__(self, key):
        fpath = self.topath(key)
        return os.path.isfile(fpath)

    def __setitem__(self, key, val):
        keydir = self.tokeydir(key)

        # if not os.path.isdir(keydir):
        with suppress(Exception):
            os.makedirs(keydir)

        dump_pz4(val, f'{keydir}/{key}.pkl.lz4')

    def __getitem__(self, key):
        keydir = self.tokeydir(key)

        return load_pz4(f'{keydir}/{key}.pkl.lz4')


    def getiter(self, keypart, max_mem=None):

        keydir = self.tokeydir(keypart)
        all_fpaths = glob(f'{keydir}/{keypart}*')
        res = []
        for fpath in all_fpaths:
            yield load_pz4(fpath)


    def getall(self, keypart, max_mem=None):

        keydir = self.tokeydir(keypart)
        all_fpaths = glob(f'{keydir}/{keypart}*')
        res = []
        for fpath in all_fpaths:
            res += [load_pz4(fpath)]

            if not max_mem:
                continue

            process = psutil.Process(os.getpid())
            cur_mem = process.memory_info().rss  # in bytes

            if cur_mem > max_mem:
                print('Exceeded max mem', max_mem, 'for', keypart)
                break
        # res = [load_pz4(fpath) for fpath in all_fpaths]

        return res

    def getone(self, keypart, max_mem=None):

        keydir = self.tokeydir(keypart)
        all_fpaths = glob(f'{keydir}/{keypart}*')
        fpath = all_fpaths[0]
        return load_pz4(fpath)

    def addraw(self, key, val):
        keydir = self.tokeydir(key)

        if not os.path.isdir(keydir):
            os.makedirs(keydir)

        fpath = self.topath(key)
        with open(fpath, 'wb') as f:
            f.write(val)


class Printable():
    def __repr__(self):
        return self.__str__()

    def __str__(self):
        ret = self.__class__.__name__ + '('
        for k, v in self.__dict__.items():
            ret += k + '=' + str(v) + ','
        ret += ')'

        return ret

    def list(self):
        vals = []
        for k in sorted(self.__dict__):
            vals += [self.__dict__[k]]

        return vals


class TraceRW(Printable):

    def __init__(self, pid, action, ip, addr, size, val, loc, func, flags, cpu):
        self.type = RW
        self.pid = pid
        self.action = action
        self.ip = ip
        self.addr = addr
        self.size = size
        self.val = val
        self.loc = loc
        self.func = func
        self.flags = flags
        self.cpu = cpu

        self.is_read, self.is_write, self.is_atomic, self.is_scoped =\
                    kcsan_access_type(action)

        # added flag to track the kcsan is_atomic() check
        self.kcsan_is_atomic = bool(int(action) & (1<<5))

        # atomic type
        self.atomic_type = ''
        if (int(action) & IS_FLAT_ATOMIC):
            self.atomic_type = 'flat_atomic'
        if (int(action) & IS_ATOMIC_NEXT):
            self.atomic_type += 'atomic_next'
        if (int(action) & IS_ATOMIC_NEST):
            self.atomic_type += 'atomic_nest'

    def rw_lbl(self):
        lbl = ''
        lbl += 'R' if self.is_read else ''
        lbl += 'W' if self.is_write else ''
        return lbl


class TraceLock(Printable):

    def __init__(self, pid, action, lock_addr, lock_type, meta, flags, cpu):
        self.type = LOCK
        self.pid = pid
        self.action = action
        self.lock_addr = lock_addr
        self.lock_type = lock_type
        self.meta = meta
        self.flags = flags
        self.cpu = cpu

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        ret = self.__class__.__name__ + '('
        for k, v in self.__dict__.items():
            ret += k + '=' + str(v) + ','
        ret += ')'

        return ret


class TraceDebug(Printable):

    def __init__(self, pid, msg, flags):
        self.type = DBG
        self.pid = pid
        self.msg = msg
        self.flags = flags


class TraceSyscall(Printable):

    def __init__(self, pid, action, syscall, args, ret, cpu):
        self.type = SYS
        self.pid = pid
        self.action = action
        self.syscall = syscall
        self.args = args
        self.ret = ret
        self.cpu = cpu


class TraceAtomic(Printable):

    def __init__(self, pid, action, ip, size, loc, func, cpu):
        self.type = ATOMIC
        self.pid = pid
        self.action = action
        self.ip = ip
        self.size = size
        self.loc = loc
        self.func = func
        self.cpu = cpu

        self.atomic_event = ''
        if (int(action) & ATOMIC_NEST_ENTER):
            self.atomic_event = 'nest_enter'
        elif (int(action) & ATOMIC_NEST_EXIT):
            self.atomic_event = 'nest_exit'
        elif (int(action) & ATOMIC_NEXT_SET):
            self.atomic_event = 'next_set'
        elif (int(action) & ATOMIC_FLAT_ENTER):
            self.atomic_event = 'flat_enter'
        elif (int(action) & ATOMIC_FLAT_EXIT):
            self.atomic_event = 'flat_exit'


class LocksetMemOp(TraceRW):

    def __init__(self, tr_idx, t, lockset, label):
        val = 0
        try:
            val = t.val
        except:
            pass
        super().__init__(t.pid, t.action, t.ip, t.addr, t.size, val, t.loc, t.func)
        self.tr_idx = tr_idx
        self.lockset = lockset
        self.label = label


class RaceCheckInput(Printable):

    def __init__(self, watchpoint_input, other_input, watchpoint_ip, watchpoint_mem_addr, pred_race_ips, race_prob=0.0):
        self.wp_input = watchpoint_input
        self.other_input = other_input
        self.wp_ip = watchpoint_ip
        self.wp_addr = watchpoint_mem_addr
        self.pred_race_ips = pred_race_ips
        self.race_prob = race_prob


def dump_pz4(data, outfile):
    with lz4.frame.open(outfile, mode='wb') as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)


def load_pz4(infile):
    with lz4.frame.open(infile, 'r') as f:
        data = pickle.load(f)

    return data


def topz4(val):
    return lz4.frame.compress(pickle.dumps(val))

def frompz4(cval):
    return pickle.loads(lz4.frame.decompress(cval))


def readlist(jlist):
    return json.loads(jlist.replace("'", "\""))


def readset(jset):
    return json.loads('['+jset.replace("'", "\"")[1:-1]+']')



def kcsan_access_type(action):
    action = int(action)
    is_write = bool((action & KCSAN_WRITE) or (action & KCSAN_READWRITE))
    is_read = bool((action & KCSAN_READWRITE) or (not is_write))
    is_atomic = bool(action & KCSAN_ATOMIC)
    is_scoped = bool(action & KCSAN_SCOPED)
    return is_read, is_write, is_atomic, is_scoped


def parse_trace(trace_f, loc_map=None, unlabeled_map=None, lz4_input=False):
    trace = []
    with open(trace_f) as f, lz4.frame.open(trace_f) as f_lz4:
        if lz4_input:
            f = f_lz4
        cur_syscall = ''
#         unlabeled_map = defaultdict(int)
        for i, line in enumerate(f):
            if lz4_input:
                line = line.decode('utf8')
        # for i, line in tqdm(enumerate(f)):
            if line[0] == '#': continue
            line = line.strip()

            if not line: continue
#             if not line.startswith('syz-executor'): continue

            try:

                ll = line.split(':')

                tr_info = ll[0].split()
                pid = tr_info[0].split('-')[-1]
                trace_type = ll[1].strip()

                lls = line.split()
                flags = lls[2]
                cpu = lls[1][-2]

                if trace_type == 'mem_read_write':

                    trace_vals = tuple(map(lambda x:x.split('=')[-1], ll[2].split(',')))
    #                 print(trace_vals)
                    ip, addr, size, access_type, val = trace_vals
                    access_type = int(access_type)

                    loc = ('', '', '')
                    if loc_map and ip in loc_map.ip_locs:
                        loc = loc_map.get_loc(ip)
                    elif unlabeled_map:
                        unlabeled_map[cur_syscall] += 1

                    if access_type & IS_ATOMIC_META:
                        trace += [TraceAtomic(pid, access_type, ip, size, loc[0]+':'+loc[1], loc[2], cpu)]

                    else:
                        trace += [TraceRW(pid, access_type, ip, addr, size, val, loc[0]+':'+loc[1], loc[2], flags, cpu)]

                elif trace_type.startswith('lock_'):
                    trace_vals = ll[2].strip().split()

                    lock_addr = trace_vals[0]
                    action = trace_type
                    lock_type = ' '.join(trace_vals[1:])
                    meta = ''

                    trace += [TraceLock(pid, action, lock_addr, lock_type, meta, flags, cpu)]

                elif trace_type.startswith('sys_'):

#                     print(line)
#                     print(ll)

                    args = ''
                    ret = ''
                    NR = ''

                    if m := sys_return_re.match(trace_type):
                        action = 'sys_exit'
                        syscall = m[1]
                        ret = m[2]
                    else:
                        action = 'sys_enter'
                        syscall = sys_name_re.match(trace_type)[1]
                        args = parens_comma_re.split(':'.join(ll[2:]))

                    cur_syscall = syscall+'-'+action

                    trace += [TraceSyscall(pid, action, syscall, args, ret, cpu)]
#                     print(trace[-1])
                elif trace_type == 'debug_msg':
                    msg = ':'.join(ll[2:])
                    trace += [TraceDebug(pid, msg, flags, cpu)]
                else:
                    pass
#                     print('UNEXPECTED FORMAT:', line)
#                     break

            except Exception as e:
                print('ERROR', i, str(e), line)
                # raise e
                pass

    return trace


def ips2locs(ips, kernel_path=None):
    if not kernel_path:
        kernel_path = os.environ['KERNEL']

    uniq_ips = list(sorted(set(ips)))

    IP_ARGS = 5000
    uniq_locs = []
    for i in range(0, len(uniq_ips), IP_ARGS):

        uniq_locs.extend(sp.run(f'llvm-addr2line -e {kernel_path}/vmlinux '+' '.join(uniq_ips[i:i+IP_ARGS]), shell=True,\
                     capture_output=True).stdout.decode().split())
    ip2loc = {ip:loc for ip, loc in zip(uniq_ips, uniq_locs)}
    locs = [ip2loc[ip] for ip in ips]

    return locs, ip2loc


def check_race_preds(input_dir, vm_log_f, race_inputs,
        monitor='/tmp/qemu_sock', port=10021):
    race_re = re.compile(r'PID2 RACE AT ([a-fA-F0-9]+)')

    if not input_dir.endswith('/'):
        input_dir += '/'

#     input_dir = '../data/inputs/corpus10_pocs/'
#     vm_log_f = '../vm.log'
    scripts_dir = os.environ['SCRIPTS']


    if not scripts_dir:
        print('need to set SCRIPTS env var!')
        sys.exit(1)

    env = os.environ.copy()
    env['MONITOR'] = monitor
    env['PORT'] = str(port)


    with open(vm_log_f) as log_f:

        results = []
        logs = []
        reports = []

        for i, race_input in enumerate(race_inputs):
    #     for i, race_input in enumerate([poc15_input, poc15_input, poc15_input]):

#             print(race_input)
            # update log_f position

            log_f.seek(0, 2)

            # run race check
            cmd = [f'{scripts_dir}/run_watchpoint_locked.sh']
            cmd += [input_dir+race_input.wp_input+'.data']
            cmd += [input_dir+race_input.other_input+'.data']
            cmd += [race_input.wp_ip]
            cmd += [race_input.wp_addr]
            # cmd += [vm_log_f]
            # cmd += [str(log_f.tell())]

            # print(' '.join(cmd))

            try:
                # sp.run(cmd, timeout=5, capture_output=True, env=env)
                # sp.run(cmd, timeout=5)
                p = sp.Popen(cmd, start_new_session=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL, env=env) # capture output, env?
                p.wait(timeout=5)
            except sp.TimeoutExpired:
                pass

            os.killpg(os.getpgid(p.pid), signal.SIGTERM)

            #

            # check vm log for races
            result_log = log_f.read()

            race_ips = set()
            watchpoint_set = False
            barrier0_passed = False
            barrier1_passed = False
            barrier0_set = False
            barrier1_set = False

            in_race_report = False

            cur_report = []
            race_reports = {}

            new_race_ip = False


            for line in result_log.split('\n'):
                # print(line)
                if "PID1 SET WATCHPOINT" in line:
                    watchpoint_set = True
                elif "barrier0 set:" in line:
                    barrier0_set = True
                elif "barrier1 set:" in line:
                    barrier1_set = True
                elif "barrier0 continuing" in line:
                    barrier0_passed = True
                elif "barrier1 continuing" in line:
                    barrier1_passed = True

                elif m := race_re.search(line):
                    race_ip = m[1]

                    new_race_ip = race_ip not in race_ips

                    if new_race_ip:
                        race_ips.add(race_ip)

                elif "="*20 in line:
                    in_race_report = not in_race_report

                    # if we just finished report, record and reset
                    if not in_race_report:
                        if new_race_ip:
                            race_reports[race_ip] = "\n".join(cur_report)

                        cur_report = []

                elif in_race_report:
                    cur_report += [line.strip()]


                    # print('found race', race_ip)

            results += [RaceCheckResult(race_input.wp_input, race_input.other_input,
                        race_input.wp_ip, race_input.wp_addr,
                        barrier0_set, barrier1_set,
                        barrier0_passed, watchpoint_set, barrier1_passed,
                        len(race_ips) > 0,
                        list(race_ips), False, "")]

            logs += [result_log]
            reports += [race_reports]

            # if len(results) > 1:
                # break

        return results, logs, reports, cmd


# shell util
def sh(cmd):
    return sp.run(cmd, shell=True)

# --------------------------------------------------------------------------
# race result analysis here
# --------------------------------------------------------------------------

def get_race_tuples(rdf, include_inputs=True):
    race_tuples = set()
    for row in rdf.itertuples():
        if not row.race_found:
            continue

        for rip in readset(row.race_ips):
            if include_inputs:
                race_tuples.add((row.wp_input, row.other_input, row.wp_ip, rip))
            else:
                race_tuples.add((row.wp_ip, rip))


    return race_tuples


def align_trace_results(pdf, rdf=pd.DataFrame(), compare_inputs=True):
    race_tuples = get_race_tuples(rdf, include_inputs=compare_inputs)

    race_pairs = set()
    tps, fps = 0,0
    pdf_results = []
    for row in pdf.itertuples():

        pred_ips = readset(row.pred_race_ips)
        for pred_ip in pred_ips:

            if compare_inputs:
                pred_tuple = (row.wp_input, row.other_input, row.wp_ip, pred_ip)
            else:
                pred_tuple = (row.wp_ip, pred_ip)

            race = pred_tuple in race_tuples
            if race:
                race_pairs.add(tuple(sorted([row.wp_ip, pred_ip])))
                tps += 1
            else:
                fps += 1

            aligned_result = (row.wp_input, row.other_input, row.wp_ip, row.wp_addr, pred_ip, race)
            pdf_results += [aligned_result]


    pdf_results = pd.DataFrame(pdf_results, columns='wp_input other_input wp_ip wp_addr pred_ip race'.split())
    return pdf_results


