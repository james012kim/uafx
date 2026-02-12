import sys, os

def _process_entry_out(output_file, target_bc_file, analysis_funcs):
    out_cache = []
    out_cache_cand = {}
    fp = open(output_file, 'r')
    all_lines = fp.readlines()
    for curr_li in all_lines:
        curr_li = curr_li.strip()
        if curr_li:
            tks = curr_li.split(':')
            if tks[0].endswith('_CAND'):
                if not tks[1] in out_cache_cand:
                    out_cache_cand[tks[1]] = (tks[0], tks[2])
            elif not tks[1] in out_cache:
                out_cache.append(tks[1])
                if tks[0].startswith('INT_HANDLER'):
                    analysis_funcs.append('#' + tks[2] + '\n#' + tks[1] + ' ' + tks[0])
                else:
                    analysis_funcs.append('#' + tks[2] + '\n' + tks[1] + ' ' + tks[0])
    for k in out_cache_cand:
        if not k in out_cache:
            #By default comment out the cand ioctl().
            analysis_funcs.append('#' + out_cache_cand[k][1] + '\n#' + k + ' ' + out_cache_cand[k][0])
    fp.close()

entry_point_bin = './entry_point_handler'
entry_point_bin_v2 = './entry_point_handler_v2'
entry_point_bin_v3 = './entry_point_handler_v3'

def generate_entry_points(bc, entry_point_file=None, version=1):
    out_analysis_funcs = []
    if not os.path.exists(bc):
        print('The specified bc file does not exist.')
        return False
    bc_dir = os.path.dirname(bc)
    bc_name = os.path.basename(bc).split('.')[0]
    # Use version-specific suffix for v2/v3 output files to avoid overwriting
    if version == 2:
        entry_point_out = bc_dir + '/' + bc_name + '_v2.conf'
        selected_bin = entry_point_bin_v2
    elif version == 3:
        entry_point_out = bc_dir + '/' + bc_name + '_v3.conf'
        selected_bin = entry_point_bin_v3
    else:
        entry_point_out = bc_dir + '/' + bc_name + '.conf'
        selected_bin = entry_point_bin
    if entry_point_file and os.path.exists(entry_point_file) and version == 1:
        os.system(selected_bin + ' ' + bc + ' ' + entry_point_out + ' ' + entry_point_file)
    else:
        os.system(selected_bin + ' ' + bc + ' ' + entry_point_out)
    assert(os.path.exists(entry_point_out))
    _process_entry_out(entry_point_out, bc, out_analysis_funcs)
    fp = open(entry_point_out, "w")
    for curr_en in sorted(out_analysis_funcs):
        fp.write(curr_en + "\n")
    fp.close()
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: entry_point_identifier.py [--version N] path/to/bitcode [entry_point_file]')
        print('  --version N : 1 (default, struct-based), 2 (call graph), 3 (call graph + MLTA)')
    else:
        version = 1
        args = sys.argv[1:]
        if '--version' in args:
            idx = args.index('--version')
            version = int(args[idx + 1])
            args = args[:idx] + args[idx + 2:]
        bc = args[0]
        ep_file = args[1] if len(args) > 1 else None
        generate_entry_points(bc, entry_point_file=ep_file, version=version)
