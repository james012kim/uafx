#!/usr/bin/python

#Extract and process the warnings in the log output.

import sys,os
import datetime
import json
from unittest import skip
import traceback
import xml.etree.ElementTree as ET

warns = []
jwarns = {}
jcbs = []
time_stats = []
mem_stats = []

#Get a tuple rep for the InstLoc json object.
def get_loc_tuple(j):
    if (not j) or len(j) == 0:
        return None
    locs = tuple([(loc.get('at_file','unk_file'),loc.get('at_line',0)) for loc in j.get('loc',[])])
    return (locs, j.get('at_func','unk_func'), get_top_entry(j.get('ctx',[])))

def ext_warns(log, *tys):
    global warns, jwarns, time_stats, mem_stats
    is_warn = False
    is_callback_info = False
    mem_ln = 0
    cnt = 0
    cnt_total = 0
    with open(log,'r') as f:
        ln = 0
        for l in f:
            ln += 1
            if l.startswith('@@@@@@'):
                is_warn = (not is_warn)
            elif l.startswith('CCCCCCC'):
                is_callback_info = (not is_callback_info)
            elif is_warn:
                cnt_total += 1
                if tys and all([l.find(ty) < 0 for ty in tys]):
                    continue
                #One line per warning.
                l = l.strip()
                if l.startswith('\"warn_data\":'):
                    #warns.append(l)
                    try:
                        j = json.loads(l[12:])
                    except:
                        traceback.print_exc(None,sys.stderr)
                        sys.stderr.write('Error parsing json line ' + str(ln) + '\n')
                        exit(1)
                    #We group the warnings by the two-layer key: loc0 (e.g., free) and loc1 (e.g., use).
                    i0 = get_loc_tuple(j.get('loc0',{}))
                    i1 = get_loc_tuple(j.get('loc1',{}))
                    if i0 and i1:
                        jwarns.setdefault(i0,{}).setdefault(i1,[]).append(j)
                        cnt += 1
                        if cnt % 10 == 0:
                            sys.stderr.write(str(cnt) + '/' + str(cnt_total) + '\n')
                    else:
                        sys.stderr.write('Unrecognized warning: line ' + str(ln) + '\n')
            elif is_callback_info:
                if l.startswith('{\"funcs'):
                    try:
                        j = json.loads(l)
                    except:
                        traceback.print_exc(None,sys.stderr)
                        sys.stderr.write('Error parsing json line ' + str(ln) + '\n')
                        exit(1)
                    jcbs.append(j)
            elif l.startswith('[TIMING]') and l.find('finished in') > 0:
                #Record timing information
                time_stats.append(l.strip())
            elif l.startswith('[MEM]') and l.find('Statistics') > 0:
                mem_stats.append(l.strip())
                mem_ln = 7
            elif mem_ln > 0:
                mem_stats.append(l.strip())
                mem_ln -= 1

def cnt_uf_fired(log):
    uses = set()
    frees = set()
    is_warn = False
    cnt = 0
    cnt_total = 0
    with open(log,'r') as f:
        ln = 0
        for l in f:
            ln += 1
            if l.startswith('@@@@@@'):
                is_warn = (not is_warn)
            elif is_warn:
                cnt_total += 1
                #One line per warning.
                l = l.strip()
                if l.startswith('\"warn_data\":'):
                    #warns.append(l)
                    try:
                        j = json.loads(l[12:])
                    except:
                        traceback.print_exc(None,sys.stderr)
                        sys.stderr.write('Error parsing json line ' + str(ln) + '\n')
                        exit(1)
                    #loc0 (e.g., free) and loc1 (e.g., use).
                    i0 = get_loc_tuple(j.get('loc0',{}))
                    i1 = get_loc_tuple(j.get('loc1',{}))
                    if i0 and i1:
                        frees.add(i0)
                        uses.add(i1)
                        cnt += 1
                        if cnt % 10 == 0:
                            sys.stderr.write(str(cnt) + '/' + str(cnt_total) + '\n')
                    else:
                        sys.stderr.write('Unrecognized warning: line ' + str(ln) + '\n')
    print('Frees: %d' % (len(frees)))
    print('Uses: %d' % (len(uses)))

def cnt_uf_raw(log):
    uses = set()
    frees = set()
    is_warn = False
    cnt = 0
    cnt_total = 0
    with open(log,'r') as f:
        for l in f:
            if l.startswith('validateUAF(): about to validate the UAF'):
                cnt_total += 1
                i0 = l.find('loc0:')
                i1 = l.find('loc1:')
                i2 = l.find('fobj:')
                if i0 < 0 or i1 < 0 or i2 < 0:
                    sys.stderr.write('Unrecognized warning: line ' + str(l) + '\n')
                else:
                    frees.add(l[i0+5:i1-2])
                    uses.add(l[i1+5:i2-2])
                    cnt += 1
                    if cnt % 10 == 0:
                        sys.stderr.write(str(cnt) + '/' + str(cnt_total) + '\n')
    print('Frees: %d' % (len(frees)))
    print('Uses: %d' % (len(uses)))

#Extract the raw warnings lines from the log file (in case the log is very large).
def ext_warns_raw(log):
    global warns
    is_warn = False
    with open(log,'r') as f:
        for l in f:
            if l.startswith('@@@@@@'):
                is_warn = (not is_warn)
                print(l.strip())
            elif is_warn:
                #One line per warning.
                print(l.strip())

def dump_warns_raw():
    global warns
    #Dump the warning
    for l in warns:
        print(l)

URL_PREFIX_LINUX = "https://elixir.bootlin.com/linux/v5.17.11/source/"

def mkurl_linux(fp, ln):
    fp = fp.replace('\\','')
    return URL_PREFIX_LINUX + fp + '#L' + str(ln)

def mkurl_default(fp, ln):
    return fp + '@' + str(ln)

def mkurl(j, inline_unroll = False):
    loc = j.get('loc',[])
    if (not loc) or len(loc) == 0:
        return ['']
    if (len(loc) == 1) or (not inline_unroll):
        #Only return the actual inst loc
        fp = loc[0].get('at_file','unk_file')
        ln = loc[0].get('at_line',0)
        return [mkurl_default(fp, ln)]
    #Reaching here means that the inst is in an inlined
    #function, and we need to detail the inline sites.
    buf = []
    for i in range(len(loc)):
        s = ('(inline) ' if i > 0 else '(actual) ')
        fp = loc[i].get('at_file','unk_file')
        ln = loc[i].get('at_line',0)
        s += mkurl_default(fp, ln)
        buf.append(s)
    return buf

def get_ctx_strs(ctx, inline_unroll = False):
    if (not ctx) or len(ctx) == 0:
        return []
    chain = []
    chain_comp = []
    is_entry = True
    for inst in ctx:
        func = inst.get('at_func','UNK_FUNC')
        furl = mkurl(inst, inline_unroll)
        if is_entry:
            chain.append(func)
            s = func + ' (' + furl[0] + ')'
            chain_comp.append(s)
        else:
            #Record the callsite info.
            ins = inst.get('instr','UNK_INST')
            furl[0] += (' : ' + ins)
            for f in furl[::-1]:
                s = '----> (' + f + ')'
                chain_comp.append(s)
        is_entry = (not is_entry)
    chain_comp.append(' -> '.join(chain))
    return chain_comp

#Get the upmost caller (in function name str) of this calling context.
def get_top_entry(ctx):
    if (not ctx) or len(ctx) == 0:
        return ''
    return ctx[0].get('at_func','UNK_FUNC')

def get_inst_url(j):
    func = j.get('at_func','UNK_FUNC')
    furl = mkurl(j, True)
    inst = j.get('instr','UNK_INST')
    #"func" and "inst" are for the actual location, not inline sites.
    furl[0] += (' (' + func + ' : ' + inst + ')')
    furl.reverse()
    return '\n'.join(furl)

def pprint_loc_url(j):
    #First print the ctx.
    ctx = get_ctx_strs(j.get('ctx',[]), True)
    if ctx:
        print('#####CTX##### ' + ctx[-1])
        for i in range(len(ctx)-1):
            print(ctx[i])
    #Now print the inst.
    print('#####INST#####')
    print(get_inst_url(j))

def pprint_ep(p):
    cur_ctx = None
    for n in p.get('path',[]):
        #Print the context of this inst loc- if we haven't done so already.
        ctx = get_ctx_strs(n.get('ctx',[]), True)
        if (not cur_ctx) or cur_ctx != ctx:
            print('#####CTX##### ' + ctx[-1])
            for i in range(len(ctx)-1):
                print(ctx[i])
            print('#####INSTS#####')
            cur_ctx = ctx
        #Now print current inst and the related object escape/fetch info.
        lbl = n.get('label',-1) #0: escape, 1: fetch
        lbl_str = ' <- ' if lbl == 0 else ' -> ' if lbl == 1 else ' -- '
        src = n.get('so','UNK_OBJ') + '|' + str(n.get('sf',-1))
        dst = n.get('do','UNK_OBJ') + '|' + str(n.get('df',-1)) 
        print(src + lbl_str + dst + ' : ' + get_inst_url(n))

def pprint_eps(j):
    #Src and dst objects
    so = j.get('so','UNK_OBJ')
    do = j.get('do','UNK_OBJ')
    print(so + ' -> ' + do + (' (Identical objects)' if so == do else ''))
    #Detailed escape/fetch paths, note that there can be multiple paths between a same
    #object pair, for now we print them all.
    if so != do:
        ep_cnt = 0
        for p in j.get('paths',[]):
            print ('@@Path ' + str(ep_cnt) + '@@')
            ep_cnt += 1
            pprint_ep(p)

#Print out the json bug report in a concise and easily readable way.
def pprint(j):
    ty = j.get('by','UNK')
    hint = j.get('hint','No hints')
    jloc0 = j.get('loc0',{})
    jloc1 = j.get('loc1',{})
    #Print heading part: the warning type and the key locations.
    print(ty)
    print(hint)
    print('****LOC 0****')
    pprint_loc_url(jloc0)
    print('****LOC 1****')
    pprint_loc_url(jloc1)
    #Print the object escape/fetch paths (e.g., ep0 and ep1).
    jep0 = j.get('ep0',{})
    if jep0:
        print('****EP 0****')
        pprint_eps(jep0)
    print('****EP 1****')
    pprint_eps(j.get('ep1',{}))

#Group and sort the related warnings.
#Grouping policy:
#(1) same loc0 (e.g., free site) and same calling context of it.
#(2) same flow type ('con' or 'seq')
#(3) compatiable calling contexts of loc1 (e.g., use site), e.g.,
#loc1 ctx of one warning should be a prefix or the same as another
#one in the same group.
def group_warns():
    global jwarns
    res = []
    for fi in jwarns:
        #warnings in jwarns[fi] share the same free inst and top-entry of
        #the free site.
        #Now we scan all these warnings to further classify them according
        #to the aforementioned principles.
        #fmap: calling ctx of F -> flow type -> warning jsons
        fmap = {}
        for wi in jwarns[fi]:
            for warn in jwarns[fi][wi]:
                f_ctx = get_ctx_strs(warn.get('loc0',{}).get('ctx',[]))[-1]
                ty = warn.get('hint','def')
                fmap.setdefault(f_ctx,{}).setdefault(ty,[]).append((warn,wi))
        #Further divide each bin in fmap according to principle (3).
        for fctx in fmap:
            for ty in fmap[fctx]:
                wlist = []
                for w in fmap[fctx][ty]:
                    u_ctx = get_ctx_strs(w[0].get('loc1',{}).get('ctx',[]))[-1]
                    placed = False
                    for e in wlist:
                        if u_ctx.startswith(e[0]):
                            e[1].append(w)
                            placed = True
                            break
                        if e[0].startswith(u_ctx):
                            e[0] = u_ctx
                            e[1].append(w)
                            placed = True
                            break
                    if not placed:
                        wlist.append([u_ctx,[w]])
                #Sort the final groups and put them into the result.
                for e in wlist:
                    e[1].sort(key = lambda x : (x[1][0][0][0], x[1][0][0][1]))
                    res.append({'warns' : e[1], 'loc0' : fi})
    #Sort the grps according to loc0.
    res.sort(key = lambda x : (x.get('loc0')[0][0][0], x.get('loc0')[0][0][1]))
    return res

def dump_warns_pretty():
    global time_stats, mem_stats
    warn_grps = group_warns()
    gcnt = 0
    for grp in warn_grps:
        print('=========================GROUP %d=========================' % (gcnt))
        print('#########Summary#########')
        #Summarize the loc0 (e.g., free site) and loc1 (use site) in the group.
        print('LOC 0:')
        fi = grp['loc0']
        print((fi[0][0][0], fi[0][0][1], fi[1]))
        print('LOC 1:')
        prev_loc_tuple = None
        for wa in grp.get('warns',[]):
            loc_tuple = wa[1]
            if (not prev_loc_tuple) or prev_loc_tuple != loc_tuple:
                print((loc_tuple[0][0][0], loc_tuple[0][0][1], loc_tuple[1]))
                #print(loc_tuple)
                prev_loc_tuple = loc_tuple
        print('#########################')
        print('')
        wcnt = 0
        for j in grp.get('warns',[]):
            print('++++++++++++++++WARN %d++++++++++++++++' % (wcnt))
            pprint(j[0])
            print('')
            wcnt += 1
        gcnt += 1
    #Output some quick statistics
    sys.stderr.write('#group: %d\n' % (gcnt))
    sys.stderr.write('=====Time Statistics=====\n')
    sys.stderr.write('\n'.join(time_stats) + '\n')
    sys.stderr.write('=====Mem Statistics=====\n')
    sys.stderr.write('\n'.join(mem_stats) + '\n')

def print_callback_info():
    global jcbs
    if jcbs:
        print('===============CALLBACKS===============')
        for j in jcbs:
            print('@@@ Callback Funcs: ' + j.get('funcs',''))
            print('Ref Loc:')
            pprint_loc_url(j.get('ref',{}))
            print('')

if __name__ == '__main__':
    if len(sys.argv) < 3:
        #print('Usage: ./ext_warns.py log warn_type_0 warn_type_1 ...')
        cnt_uf_raw(sys.argv[1])
    else:
        ext_warns(sys.argv[1],*sys.argv[2:])
        print_callback_info()
        dump_warns_pretty()