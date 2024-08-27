import sys
import re
import subprocess
from trie import Trie

def multireplace(string, replacements, ignore_case=False):
    """
    Given a string and a replacement map, it returns the replaced string.

    :param str string: string to execute replacements on
    :param dict replacements: replacement dictionary {value to find: value to replace}
    :param bool ignore_case: whether the match should be case insensitive
    :rtype: str

    """
    if not replacements:
        # Edge case that'd produce a funny regex and cause a KeyError
        return string

    # If case insensitive, we need to normalize the old string so that later a replacement
    # can be found. For instance with {"HEY": "lol"} we should match and find a replacement for "hey",
    # "HEY", "hEy", etc.
    if ignore_case:
        def normalize_old(s):
            return s.lower()

        re_mode = re.IGNORECASE

    else:
        def normalize_old(s):
            return s

        re_mode = 0

    trie = Trie()
    for r in replacements:
        trie.add(r)
    pattern = re.compile(r"0?x?0*" + trie.pattern() + r"", re.IGNORECASE)


    #replacements = {normalize_old(key): val for key, val in replacements.items()}

    # Place longer ones first to keep shorter substrings from matching where the longer ones should take place
    # For instance given the replacements {'ab': 'AB', 'abc': 'ABC'} against the string 'hey abc', it should produce
    # 'hey ABC' and not 'hey ABc'
    #rep_sorted = sorted(replacements, key=len, reverse=True)
    #rep_escaped = map(re.escape, rep_sorted)


    # Create a big OR regex that matches any of the substrings to replace
    #pattern = re.compile("|".join(rep_escaped), re_mode)
    #pattern = re.compile("|".join(["0?x?(" + a + ")" for a in rep_escaped]), re_mode)
    #print(pattern)

    # For each match, look up the new string in the replacements, being the key the normalized old string
    return pattern.sub(lambda match: replacements[normalize_old("{:x}".format(int(match.group(0),16)))], string)

layout = sys.argv[1]
symbol_base = sys.argv[2]

with open(layout, 'r') as f:
    lines = f.readlines()

sym_to_fullpath = dict()

bases = dict()


bases_to_names = dict()

loaded = set()

mod2pdb = {}
ranges = {}
for l in lines:
    if ".pdb" in l:
        module_name = ".".join(l.split()[-1].split("\\")[-1].split(".")[:-1]).lower()
        pdbpath = symbol_base + "/" + "/".join(l.split()[-1].split("\\")[-3:])
        mod2pdb[module_name] = pdbpath
    elif ".exe" in l or ".dll" in l and "`" not in l:
        name = ".".join(l.split()[4].split(".")[:-1]).lower()
        start = int(l.split()[2], 16)
        end = start + int(l.split()[3], 16)
        if name in mod2pdb:
            ranges[(start, end)] = [name, mod2pdb[name], []]


syms = dict()
sorted_bases = sorted(bases_to_names.keys())[::-1]
# for a in sorted_bases:
#     print(hex(a))

def loadsyms(r):
    # print("loading {}".format(s))
    subprocess.run(['ls', '-l'], stdout=subprocess.PIPE)
    result = subprocess.run(['llvm-pdbutil', 'dump', '-all', ranges[r][1]], check=False, stdout=subprocess.PIPE)
    name = None
    newsyms=[]
    for l in result.stdout.decode('utf-8').splitlines():
        if "S_LPROC32" in l or "S_PUB32" in l:
            name = "".join(l.split("`")[1:-1])
        else:
            if "addr = " in l and name != None:
                m = re.match(".*addr = ([0-9:]+).*", l)
                offset = int(m.group(1).split(":")[1])
                mult = int(m.group(1).split(":")[0])
                if mult == 1:
                    offset += mult*0x1000
                    addr = offset
                
                    newsyms.append((addr, name))
                name = None
    stinput = ""
    for sym in newsyms:
        stinput += sym[1] + "\n"
    p = subprocess.Popen(['demumble'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_data = p.communicate(input=stinput.encode())[0]
    i = 0
    for line in stdout_data.splitlines():
        ranges[r][2].append((newsyms[i][0], line.decode("utf-8")))
        i+=1
    ranges[r][2].sort(key=lambda x: x[0])
    ranges[r][2].reverse()

    # for v in ranges[r][2]:
    #     print(hex(v[0]), v[1])

reps = {}
with open(sys.argv[3],'r') as file:
    contents = file.read()
    nums = set(re.findall(r'0x[0-9A-Fa-f]+', contents, re.I))
    nums = re.findall(r'[0-9A-Fa-f]+', contents, re.I)
    for n in set(nums):
        n = int(n, 16)
        #print(hex(n))
        for r in ranges:
            if not (n >= r[0] and n < r[1]):
                continue
            if ranges[r][0] not in loaded:
                loadsyms(r)
                loaded.add(ranges[r][0])
            for s in ranges[r][2]:
                if n-r[0] >= s[0]:
                    # print(hex(n), hex(n-r[0]) , hex(s[0]), s[1])
                    rep = "({:x})<{}>{} +{}".format(n, ranges[r][0], s[1], hex(n-r[0]-s[0]))
                    reps["{:x}".format(n)] = rep
                    break
contents = multireplace(contents, reps, True)
print(contents)
