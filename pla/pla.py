import pandas as pd
import json, os
from glob import glob
import pla.kconc_utils as kc
from importlib import reload
from tqdm import tqdm
from collections import defaultdict, Counter
from sortedcontainers import SortedSet
from functools import reduce
import numpy as np

MAX_LOCKSETS = 1000

EPS = 0.001

INPT = 0
IP = 1
MEM = 2
IS_WRITE = 3


def get_access_locksets(trace, cpus, access_locksets=defaultdict(set), inpt=''):
    accesses = defaultdict(set)
    cur_lockset = defaultdict(lambda:SortedSet())  #set()

    for i, t in enumerate(trace):

        if t.type not in (kc.RW, kc.LOCK) or t.cpu not in cpus:
            continue

        if t.type == kc.LOCK:

            if t.action == 'lock_acquire' or t.action == 'lock_acquired':

                if t.lock_type in kc.LOCK_IGNORE_LIST:
                    continue

                # TODO lock special case handling, rcu etc.
                cur_lockset[t.cpu].add(t.lock_addr)

            elif t.action == 'lock_release':
                if t.lock_addr in cur_lockset[t.cpu]:
                    cur_lockset[t.cpu].remove(t.lock_addr)

        if t.type == kc.RW:
            access = (inpt, t.ip, t.addr, t.is_write)
            accesses[t.cpu].add(access)
            # TODO would lockset2access mapping be more efficient?
            access_locksets[access].add(tuple(cur_lockset[t.cpu]))

        if t.type == kc.SYS:
            print(i, t.cpu, t.syscall, t.action)

    return accesses, access_locksets



def load_trace_accesses(trace_fs, progbar=False):
    access_cnts = defaultdict(int)
    access_locksets = defaultdict(set)

    nsamples = defaultdict(int)

    if progbar:
        trace_fs = tqdm(trace_fs)

    for trace_f in trace_fs:
        cpus = []
        t_inpt, o_inpt = tuple(kc.basename(trace_f).split('_'))
        # assert(t_inpt == inpt)
        # if f'{inpt}_{inpt}' == kc.basename(trace_f):
        if t_inpt == o_inpt:
            cpus = ['0', '1']
        elif trace_f.endswith('t0.lz4'):
            cpus = ['0']
        elif trace_f.endswith('t1.lz4'):
            cpus = ['1']
        else:
            print('bad tracefile name?', trace_f)
            continue

        nsamples[t_inpt] += len(cpus)

        # print(trace_f, cpus)

        trace = kc.parse_trace(trace_f, lz4_input=True)

        accesses, access_locksets = get_access_locksets(trace, cpus,
            access_locksets=access_locksets, inpt=t_inpt)

        for cpu_accesses in accesses.values():
            for cpu_acc in cpu_accesses:
                access_cnts[cpu_acc] += 1

    for acc, cnt in access_cnts.items():
        access_cnts[acc] = cnt/nsamples[acc[INPT]]

    return access_cnts, access_locksets


def deflist_dict():
    return defaultdict(list)

def defset_dict():
    return defaultdict(set)

def defdeflist_dict():
    return defaultdict(deflist_dict)

def build_accesslocksets(access_probs, access_locksets, beta_thresh=0.4,
        early_thresholding=True):

    mems2accs = defaultdict(list)
    mems2acc_cnts = Counter()

    mems2locksets2probs2accs = \
        defaultdict(defdeflist_dict)

    mems2locksets2ipcovers = \
        defaultdict(defset_dict)

    for acc, prob in access_probs.items():
        if early_thresholding and prob < beta_thresh - EPS:
            continue

        inpt, ip, mem, is_write = acc

        mems2acc_cnts[mem] += 1

        mems2accs[mem] += [acc]
        for lockset in access_locksets[acc]:

            # accs should be unique here, no need for set
            mems2locksets2probs2accs[mem][lockset][prob] += [acc]

            mems2locksets2ipcovers[mem][lockset].add(ip)

    return mems2locksets2probs2accs, mems2locksets2ipcovers, mems2accs, mems2acc_cnts


def bucketsort(items, key=lambda x:x, reverse=False, min_key=0.0):
    d = defaultdict(list)
    for x in items:
        if key(x) >= min_key:
            d[key(x)] += [x]

    for k in sorted(d.keys(), reverse=reverse):
        for x in d[k]:
            yield x


def pair_predict(lockset_insns1, lockset_insns2, ip_cover, use_ip_coverage=True,
        beta=0.4):

    pair_pred_races = []

    # ASSUME on single mem address

    # order by probs
    lockset_insns1 = [(prob, acc) for prob in sorted(lockset_insns1.keys(), reverse=True) for acc in lockset_insns1[prob]]
    lockset_insns2 = [(prob, acc) for prob in sorted(lockset_insns2.keys(), reverse=True) for acc in lockset_insns2[prob]]

    stores = [(p, acc, lockset_insns2) for p, acc in filter(lambda acc: acc[1][IS_WRITE], lockset_insns1)]
    stores += [(p, acc, lockset_insns1) for p, acc in filter(lambda acc: acc[1][IS_WRITE], lockset_insns2)]

    # note shouldn't hit this b/c we check before calling
    if not stores:
        return pair_pred_races, ip_cover

    inputs2locs = defaultdict(set)
    total_locs = set()
    for p, insn in lockset_insns1 + lockset_insns2:
        inputs2locs[(insn[INPT])].add(insn[IP])
        total_locs.add(insn[IP])

    if use_ip_coverage and total_locs.issubset(ip_cover):
        return pair_pred_races, ip_cover

    for s_p, store_op, other_lockset_insns in bucketsort(stores, key=lambda x: x[0], reverse=True):
        # pick input from insn from other lockset that has different loc
        for o_p, other_acc in other_lockset_insns:
            pred_race_ips = inputs2locs[other_acc[INPT]]
            if use_ip_coverage and (store_op[IP] in ip_cover\
                    and set(pred_race_ips).issubset(ip_cover)):
            # if use_ip_coverage and (store_op[IP] in ip_cover\
                    # and other_acc[IP] in ip_cover):
                continue

            race_prob = s_p * o_p

            if not use_ip_coverage:
                race_cov_id = (store_op[INPT], other_acc[INPT], store_op[IP],
                                            store_op[MEM])
                if race_cov_id in ip_cover:
                    continue

                ip_cover.add(race_cov_id)

            pred_race = kc.RaceCheckInput(store_op[INPT], other_acc[INPT], store_op[IP],
                                            store_op[MEM], pred_race_ips, race_prob)

            pair_pred_races += [ pred_race ]


            if use_ip_coverage:
                ip_cover |= set([store_op[IP]])| pred_race_ips

                if total_locs.issubset(ip_cover):
                    return pair_pred_races, ip_cover

    return pair_pred_races, ip_cover


def log_sort(mem2cnts):
    sorted_mems = [[] for _ in range(100)]

    for mem, cnt in mem2cnts.items():
        sorted_mems[int(np.log2(cnt))] += [mem]

    for bucket in sorted_mems:
        for mem in bucket:
            yield mem


class MultiListDict():

    def __init__(self, dicts):
        self.dicts = dicts

    def __getitem__(self, keys):
        results = []
        for d in self.dicts:
            contains = True
            for k in keys:
                if k not in d:
                    contains = False
                    break
                d = d[k]
            if contains:
                results += [d]

        if isinstance(results[0], list):
            results = itertools.chain(results)
        if isinstance(results[0], set):
            results = set.union(*results)
        if isinstance(results[0], dict):
            results = MultiListDict(results)
        return results

    def keys(self):
        allkeys = set(self.dicts[0].keys())
        for d in self.dicts[1:]:
            allkeys |= d.keys()
        return allkeys


def predict_races(mems2locksets2probs2accs, mems2locksets2ipcovers,
                    mems2accs, mems2acc_cnts, progbar=False,
                    use_linear_lockset=True,
                    use_ip_coverage=True, beta=0.4):

    race_inpts, ip_cover = [], set()

    sorted_mems = log_sort(mems2acc_cnts)
    if progbar:
        sorted_mems = tqdm(sorted_mems)

    for mem in sorted_mems:
        locksets2probs2accs = mems2locksets2probs2accs[mem]
        lockset_keys = list(locksets2probs2accs.keys())[:MAX_LOCKSETS]
        locksets = tuple(map(set, lockset_keys)) # tuples to sets

        common_lockset = reduce(lambda x,y: x&y, locksets)

        if use_linear_lockset and common_lockset: # common lock, continue
            continue

        # check stores
        if not any((acc[IS_WRITE] for acc in mems2accs[mem])):
            continue


        if () in locksets2probs2accs:
            ips1 = mems2locksets2ipcovers[mem][()]
            if (use_ip_coverage and not ips1.issubset(ip_cover)) or not use_ip_coverage:
                accs1 = locksets2probs2accs[()]
                new_race_inpts, ip_cover = pair_predict(accs1, accs1, ip_cover,
                        use_ip_coverage=use_ip_coverage, beta=beta)
                race_inpts +=  new_race_inpts

        # pairwise:
        for i in range(len(locksets)):
            for j in range(i+1, len(locksets)):
                l1, l2 = locksets[i], locksets[j]
                if l1 & l2: # no race
                    continue

                l1_key, l2_key = lockset_keys[i], lockset_keys[j]

                # can we get additional coverage?
                ips1 = mems2locksets2ipcovers[mem][l1_key]
                ips2 = mems2locksets2ipcovers[mem][l2_key]
                if use_ip_coverage and (ips1 | ips2).issubset(ip_cover):
                    continue

                # pair predict
                accs1 = locksets2probs2accs[l1_key]
                accs2 = locksets2probs2accs[l2_key]

                new_race_inpts, ip_cover = pair_predict(accs1, accs2, ip_cover,
                        use_ip_coverage=use_ip_coverage, beta=beta)
                race_inpts += new_race_inpts

    race_inpts = list(bucketsort(race_inpts, key=lambda x:x.race_prob, reverse=True, min_key=0.4))

    return race_inpts


