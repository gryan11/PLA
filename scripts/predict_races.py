import os, sys, random, csv, argparse, time
from glob import glob
from importlib import reload
from tqdm import tqdm
from collections import defaultdict
import subprocess as sp

import pandas as pd
import json, os
from glob import glob
from importlib import reload
from tqdm import tqdm
from collections import defaultdict, Counter
from sortedcontainers import SortedSet
from functools import reduce
from itertools import chain

from joblib import Parallel, delayed


INPT = 0
IP = 1
MEM = 2
IS_WRITE = 3


import pla.kconc_utils as kc
import pla


def traces2memlocksets(wid, trace_fs, opts):
    # we should get all the traces for each input together
    # when this is called

    if isinstance(trace_fs[0], list):
        trace_fs = chain.from_iterable(trace_fs)

    access_probs, access_locksets = pla.load_trace_accesses(trace_fs)

    all_ips = set()

    for acc in access_probs.keys():
        all_ips.add(acc[IP])

    mems2locksets2probs2accs, mems2locksets2ipcovers, mems2accs, mems2acc_cnts = \
        pla.build_accesslocksets(access_probs, access_locksets, beta_thresh=opts.beta)

    # store into dbs by here
    db = kc.PklTrieDir(f'{opts.corpus}/{opts.db_f}')

    for addr in mems2accs:
        db[f'{addr}-locksets2probs2accs-{wid}'] = mems2locksets2probs2accs[addr]
        db[f'{addr}-locksets2ipcovers-{wid}'] = mems2locksets2ipcovers[addr]
        db[f'{addr}-accs-{wid}'] = mems2accs[addr]
        db[f'{addr}-acc_cnts-{wid}'] = mems2acc_cnts[addr]

    db[f'all_ips-{wid}'] = all_ips
    db[f'all_addrs-{wid}'] = set(mems2accs.keys())

    return sum(mems2acc_cnts.values())


def get_merged_memlocksets(trace_fs, opts):
    # chunk by inputs
    trace_fs_inpts = defaultdict(list)
    for tf in trace_fs:
        # trace fs are formatted: 100319_100319.1.t0.lz4
        base_tf = os.path.basename(tf)

        inpt = base_tf.split('_')[0]
        trace_fs_inpts[kc.basename(tf).split('_')[0]] += [tf]

    trace_fs_inpts = list(trace_fs_inpts.values())
    trcf_bs = (trace_fs_inpts[i:i+opts.batch] for i in range(0, len(trace_fs_inpts), opts.batch))

    tasks = [delayed(traces2memlocksets)(wid, trace_fs, opts) for (wid, trace_fs) in enumerate(trcf_bs)]

    print('probability estimation')
    processed_acc_cnts = Parallel(n_jobs=args.j)(tqdm(tasks))
    total_uniq_accs = sum(processed_acc_cnts)

    return total_uniq_accs



def linear_cluster_check(addr, args):

    db_f = args.corpus + '/' + args.db_f
    db = kc.PklTrieDir(db_f)

    # linear check, skip if locked
    locksets2ipcovers = db.getall(addr+'-locksets2ipcovers')
    locksets = chain.from_iterable((l2i.keys() for l2i in locksets2ipcovers))
    lockset_intersection = reduce(lambda x,y:x&y, map(set, locksets))

    # myaddr = 'ffff88800c2f8140'
    # if myaddr == addr:
        # print('lockset:', lockset_intersection)

    if lockset_intersection:
        return None # None indicates no possible races

    # common_ipcover = reduce(lambda x,y:x&y, map(set, locksets2ipcovers.values()))
    ipcovers = chain.from_iterable((l2i.values() for l2i in locksets2ipcovers))
    common_ipcover = reduce(lambda x,y:x&y, ipcovers)

    # if myaddr == addr:
        # print('ipcover:', common_ipcover)


    # return ipcover for address clustering
    return addr, tuple(sorted(common_ipcover))


def predict_races(addrs, args):

    db_f = args.corpus + '/' + args.db_f
    db = kc.PklTrieDir(db_f)

    mems2accs = defaultdict(list)
    mems2acc_cnts = Counter()
    mems2locksets2probs2accs = \
        defaultdict(pla.defdeflist_dict)
    mems2locksets2ipcovers = \
        defaultdict(pla.defset_dict)

    for addr in addrs:
        # get and merge access locksets
        for locksets2probs2accs in db.getiter(f'{addr}-locksets2probs2accs'):
            for lockset, probs2accs in locksets2probs2accs.items():
                for prob, accs in probs2accs.items():
                    mems2locksets2probs2accs[addr][lockset][prob] += accs

        for locksets2ipcovers in db.getiter(f'{addr}-locksets2ipcovers'):
            for lockset, ipcover in locksets2ipcovers.items():
                mems2locksets2ipcovers[addr][lockset] |= ipcover

        for accs in db.getiter(f'{addr}-accs'):
            mems2accs[addr] += accs

        mems2acc_cnts[addr] = sum(db.getiter(f'{addr}-acc_cnts'))

    # myaddr = 'ffff88800c2f8140'
    # if myaddr in addrs:
        # print('calling predict')
        # print(mems2locksets2ipcovers[myaddr])
        # print(mems2locksets2probs2accs[myaddr])
        # print(mems2accs[myaddr])


    race_preds = pla.predict_races(mems2locksets2probs2accs, mems2locksets2ipcovers,
                               mems2accs, mems2acc_cnts, progbar=False,
                               beta=args.beta)

    return race_preds




if __name__=='__main__':

    random.seed(0)

    parser = argparse.ArgumentParser()
    parser.add_argument('corpus')
    parser.add_argument('-o', '--outfile', default='pred_races.csv')
    parser.add_argument('--beta', type=float, default=0.5)
    parser.add_argument('--label', default='')
    parser.add_argument('--cache', action='store_true')
    parser.add_argument('-b', '--batch', type=int, default=1)
    parser.add_argument('--db_f', default='access_locksets.db')
    parser.add_argument('-j', type=int, default=1)
    args = parser.parse_args()

    trace_dir = args.corpus + '/raw_traces'
    out_d = args.corpus
    out_f = args.corpus + '/' + args.outfile
    if args.label:
        out_f = args.corpus + '/' + args.outfile.split('.')[0]+f'_{args.label}.csv'

    sp.run(f'mkdir -p `dirname {out_f}`', shell=True)

    trace_fs = sorted(glob(trace_dir + '/*'))

    start_t = time.time()

    db_f = args.corpus + '/' + args.db_f

    total_uniq_accs = 0
    if args.cache and not os.path.isdir(db_f) or not args.cache:
        total_uniq_accs = get_merged_memlocksets(trace_fs, args)

    start_pred_t = time.time()

    print('linear lockset check')

    db = kc.PklTrieDir(db_f)

    all_addrs = list(reduce(lambda x,y:x|y, db.getiter('all_addrs')))

    # linear check, get ips for each racing addr
    tasks = [delayed(linear_cluster_check)(addr, args) for addr in all_addrs]
    racing_addr_ipcovers = Parallel(n_jobs=args.j)(tqdm(tasks))

    # cluster by ip sets:
    ipclusters2addrs = defaultdict(list)
    for addr, ipcover in zip(all_addrs, racing_addr_ipcovers):

        if not ipcover:
            continue

        ipclusters2addrs[ipcover] += [addr]

    # run parallel predict on clusters
    race_pred_tasks = []
    for ipcluster in sorted(ipclusters2addrs.keys(), key=len):
        addrs = ipclusters2addrs[ipcluster]

        race_pred_tasks += [ delayed(predict_races)(addrs, args) ]

    print('pairwise race prediction')

    pred_races = Parallel(n_jobs=args.j)(tqdm(race_pred_tasks))

    pred_races = chain.from_iterable(pred_races)
    pred_races = pla.bucketsort(pred_races, key=lambda x:x.race_prob, reverse=True, min_key=args.beta - pla.EPS)

    pred_ip_cover = set()
    mincover_pred_races = []
    for pred_race in pred_races:
        if (pred_race.wp_ip in pred_ip_cover and\
            pred_race.pred_race_ips.issubset(pred_ip_cover)):
            continue

        mincover_pred_races += [pred_race]

        pred_ip_cover.add(pred_race.wp_ip)
        pred_ip_cover |= pred_race.pred_race_ips



    with open(out_f, 'w') as f:
        writer = csv.writer(f)

        writer.writerow('idx,wp_input,other_input,wp_ip,wp_addr,pred_race_ips,race_prob'.split(','))

        for i, ri in enumerate(mincover_pred_races):
            writer.writerow([i,ri.wp_input,ri.other_input,ri.wp_ip,ri.wp_addr,ri.pred_race_ips,ri.race_prob])


    end_pred_t = time.time()

    total_runtime = end_pred_t - start_t
    pred_runtime = end_pred_t - start_pred_t

    print(f'wrote race preds to {out_f}')

    print(f'total runtime: {total_runtime}, analysis runtime: {pred_runtime}')
