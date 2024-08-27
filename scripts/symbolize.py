import sys
import re
import subprocess
import tempfile
import collections
from trie import Trie

mapping = sys.argv[1]
base=sys.argv[2]
inp=sys.argv[3]


conv = dict()
ranges = dict()

pathrange=collections.defaultdict(list)



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
    pattern = re.compile(r"(0x)?0*" + trie.pattern() + r"", re.IGNORECASE)


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


with open(mapping, 'r') as f:
    lines = f.readlines()
    for l in lines:
        start = int(l.split()[2], 16)
        end = int(l.split()[4], 16)
        file = l.split()[8]
        section_name = l.split()[10]
        ranges[(start, end)] = (file, section_name)

# opening the text file
with open(inp,'r') as file:
    contents = file.read()
    nums = set(re.findall(r'0x[0-9A-Fa-f]+', contents, re.I))
    nums.update(set(re.findall(r'[0-9A-Fa-f]+', contents, re.I)))
    # print(set(nums))
    for n in set(nums):
        n = int(n, 16)
        for r in ranges:
            if(n >= r[0] and n <= r[1]):
                path = base+"/"+ranges[r][0].split("/")[-1]
                pathrange[(path,ranges[r][1], r[0])].append(n)
reps={}
for r in pathrange:
    intemp = tempfile.TemporaryFile()
    outtemp = tempfile.TemporaryFile()
    for addr in pathrange[r]:
        intemp.write("0x{:x}\n".format(addr-r[2]).encode("utf-8"))
    intemp.seek(0)
    #print(intemp.read().decode("utf-8"))
    # print(r)
    if ".ko" in r[0]:
        # print('eu-addr2line --demangle -af -e {} --section={} '.format(r[0],r[1]))
        p = subprocess.Popen('eu-addr2line --demangle -af -e {} --section={} '.format(r[0],r[1]), shell=True, stdin=intemp, stdout=outtemp)
    else :
        elfpath="/home/bkov/Downloads/elfutils/"
        a2lpath=elfpath+"./src/addr2line"
        a2lpath="/home/linuxbrew/.linuxbrew/Cellar/binutils/2.42/bin/addr2line"
        binpath="debuginfod-find"
        #binpath=elfpath+"./debuginfod/debuginfod-find"
        # sopath = ":".join([elfpath+i for i in ["debuginfod/libdebuginfod.so.1", "/libdw/libdw.so.1"]])
        # print('{} --demangle -a -f -e $({} debuginfo {} || echo {}) --section={}'.format(a2lpath, binpath, r[0], r[0], r[1]))
        p = subprocess.Popen('{} --demangle -a -f -e $({} debuginfo {} || echo {}) --section={}'.format(a2lpath, binpath, r[0], r[0], r[1]), shell=True, stdin=intemp, stdout=outtemp)
    ret_code = p.wait()
    outtemp.flush()
    outtemp.seek(0)
    lines = [line.rstrip().decode("utf-8") for line in outtemp]
    outtemp.seek(0)
    i = 0
    while i < len(lines):
        addr = pathrange[r][int(i/3)]
        func = lines[i+1]
        file = lines[i+2]
        i+=3
        if file.startswith("/local"):
            file = file[6:]
        rep = "{}[{}](0x{:x})".format(func,file, addr)
        # print("{:x} -> {}".format(addr, rep))
        reps["{:x}".format(addr)] = rep
        #reps["0x{:x}".format(addr)] = rep
        #reg = re.compile(r'0?x?0*({:x}|{:X})'.format(addr, addr))
        #contents = re.sub(reg, rep, contents)
        #contents= contents.replace("0x{:x}".format(addr), rep)
        #contents= contents.replace("0x{:X}".format(addr), rep)
        #contents= contents.replace("{:x}".format(addr), rep)
        #contents= contents.replace("{:X}".format(addr), rep)
contents = multireplace(contents, reps, True)
#print(reps)
print(contents)
