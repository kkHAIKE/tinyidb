import re
import sys
from collections import OrderedDict

class DummyParser(object):
    def parse(self, line):
        pass

class ApplyStrucTInfosParser(object):
    def __init__(self, cont):
        if "structType" not in cont:
            cont["structType"] = OrderedDict()
        self.cont = cont["structType"]

        self.re_name = re.compile(r'^id = get_struc_id\("([^"]+)"\);$')
        self.re_type = re.compile(r'^SetType\(get_member_id\(id, [^\)]+\), "[^"]+"\);$')
        self.last = None

    def parse(self, line):
        if line == "auto id;" or line == "return id;":
            return

        ret = self.re_name.match(line)
        if ret:
            st = [line]
            self.cont[ret.group(1)] = st
            self.last = st
            return

        ret = self.re_type.match(line)
        if ret:
            self.last.append(line)
            return

        raise BaseException("ApplyStrucTInfosParser get unparse line: " + line)

class IDC_Struct(object):
    def __init__(self, name, new):
        self.name = name
        self.new = new
        self.member = []
        self.clean = []
        self.attrs = []
        # self.cmt = None
        # self.cmt_rpt = None
        # self.member_cmt = {}

    def __eq__(self, obj):
        return self.name == obj.name and self.member == obj.member and self.attrs == obj.attrs

    def __ne__(self, obj):
        return not self == obj

    def mem_change(self, obj):
        return self.member != obj.member

    def attr_change(self, obj):
        return self.attrs != obj.attrs

class StructuresParser(object):
    def __init__(self, cont):
        if "struct" not in cont:
            cont["struct"] = OrderedDict()
        self.cont = cont["struct"]

        if "lastStruct" not in cont:
            cont["lastStruct"] = [None]
        self.last = cont["lastStruct"]

        self.re_new = re.compile(r'^id = add_struc\(-1,"([^"]+)",\d\);$')
        self.re_name = re.compile(r'^id = get_struc_id\("([^"]+)"\);$')
        self.re_member = re.compile(r'^mid = add_struc_member\(id,"[^"]+",\s*([^,]+)(,\s*[^,]+){3,6}\);$')
        self.re_attr = re.compile(r'^set_struc_align\(id,([^\)]+)\);$')
        # self.re_cmt = re.compile(r'^set_struc_cmt\(id,"(.+)",(\d)\);$')
        # self.re_member_cmt = re.compile(r'^set_member_cmt(id,\s*0,	"fuckme",	0);

    def parse(self, line):
        if line == "auto mid;" or line == "return id;":
            return

        ret = self.re_new.match(line)
        if ret:
            s = IDC_Struct(ret.group(1), line)
            self.cont[s.name] = s
            self.last[0] = s
            return

        ret = self.re_name.match(line)
        if ret:
            self.last[0] = self.cont[ret.group(1)]
            return

        ret = self.re_member.match(line)
        if ret:
            self.last[0].member.append(line)
            self.last[0].clean.insert(0, "del_struc_member(id,{0});".format(ret.group(1)))
            return

        ret = self.re_attr.match(line)
        if ret:
            self.last[0].attrs.append(line)
            return

        # ret = self.re_cmt.match(line)
        # if ret:
        #     if

        raise BaseException("StructuresParser get unparse line: " + line)

class PatchesParser(object):
    def __init__(self, cont):
        if "patch" not in cont:
            cont["patch"] = []
        self.cont = cont["patch"]
        self.re_patch = re.compile(r'^patch_byte\s*\([^,]+,\s*[^\)]+\);$')

    def parse(self, line):
        ret = self.re_patch.match(line)
        if ret:
            self.cont.append(line)

class BytesParser(object):
    def __init__(self, cont):
        if "bytes" not in cont:
            cont["bytes"] = OrderedDict()
        self.cont = cont["bytes"]

        if "lastBytes" not in cont:
            cont["lastBytes"] = [None]
        self.last = cont["lastBytes"]

        self.re_attr = re.compile(r'^(?:set_name|set_cmt|update_extra_cmt|create_byte|create_word|create_dword|create_qword|create_oword|create_float|create_insn|create_strlit|MakeStruct|make_array)\s*\((?:x=)?([^,\)]+).+$')
        # self.re_cmt = re.compile(r'^set_cmt\s*\(([^,]+),\s*"[^"]*",\s*[^\)]+\);$')
        # self.re_cmt2 = re.compile(r'^update_extra_cmt\s*\(([^,]+),\s*[^,]+,\s*"[^"]*"\);$')
        # self.re_create = re.compile(r'^create_(?:dword|insn)\s*\((?:x=)?([^\)]+)\);$')
        self.re_op = re.compile(r'^op_(?:hex|stkvar|plain_offset|dec|seg)\s*\(x(,\s*[^\)]+)+\);$')
        self.re_tog = re.compile(r'^toggle_sign\s*\(x,\s*[^\)]+\);$')
        # self.re_name = re.compile(r'^set_name\s*\(([^,]+),\s*"[^"]*"\);$')
        # self.re_mkst = re.compile(r'^MakeStruct\s*\(([^,]+),\s*"[^"]*"\);$')
        # self.re_create_str = re.compile(r'^create_strlit\s*\(([^\,]+)\,\s*[^\)]+\);$')
        # self.re_mkarr = re.compile(r'^make_array\s*\(([^,]+),\s*[^\)]*\);$')

    def parse(self, line):
        if line == "auto x;":
            return

        ret = self.re_attr.match(line)
        if ret:
            addr = ret.group(1)
            if addr not in self.cont:
                self.cont[addr] = []
            self.cont[addr].append(line)
            self.last[0] = self.cont[addr]
            return

        ret = self.re_op.match(line) or self.re_tog.match(line)
        if ret:
            self.last[0].append(line)
            return

        raise BaseException("BytesParser get unparse line: " + line)

class IDC_Func(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.attrs = []

    def __eq__(self, obj):
        return self.start == obj.start and self.end == obj.end and self.attrs == obj.attrs

    def __ne__(self, obj):
        return not self == obj

    def end_change(self, obj):
        return self.end != obj.end

    def attr_change(self, obj):
        return self.attrs != obj.attrs

    def attr_sub(self, obj):
        s = set(obj.attrs)
        return [x for x in self.attrs if x not in s]

class FunctionsParser(object):
    def __init__(self, cont):
        if "funcs" not in cont:
            cont["funcs"] = OrderedDict()
        self.cont = cont["funcs"]

        self.re_new = re.compile(r'^add_func\s*\(([^,]+),([^\)]+)\);$')
        self.re_attr = re.compile(r'^(?:set_func_flags|SetType|set_frame_size|define_local_var)\s*\(([^,\)]+).+$')
        # del_func set_func_end

    def parse(self, line):
        ret = self.re_new.match(line)
        if ret:
            f = IDC_Func(ret.group(1), ret.group(2))
            self.cont[f.start] = f
            return

        ret = self.re_attr.match(line)
        if ret:
            self.cont[ret.group(1)].attrs.append(line)
            return

        raise BaseException("FunctionsParser get unparse line: " + line)

def get_parser(line, cont):
    idx = line.index("(")
    name = line[7: idx]
    if name in {"main", "GenInfo", "Segments", "Enums", "ApplyStrucTInfos", "Functions", "SegRegs", "Patches", "Bytes"}:
        return DummyParser()

    if name.startswith("ApplyStrucTInfos_"):
        return ApplyStrucTInfosParser(cont)

    if name.startswith("Structures_"):
        return StructuresParser(cont)

    if name == "Structures":
        # that is a 7.0 bug, "patch_byte" in "Structures" function
        return PatchesParser(cont)

    if name.startswith("Bytes_"):
        return BytesParser(cont)

    if name.startswith("Functions_"):
        return FunctionsParser(cont)

    raise BaseException("get_parser get unsupport function name: " + name)

def read_dc(fpath):
    parser = None
    cont = {}
    with open(fpath, "rt") as f:
        f.readline() # skip first line
        while True:
            line = f.readline()
            if not line:
                break
            line = line.rstrip("\r\n")

            # skip define
            if line.startswith("#"):
                continue
            # skip main
            if line == "{":
                continue

            # skip comment
            idx = line.find("//")
            if idx != -1:
                line = line[:idx]
            line = line.strip()

            if not line:
                continue

            if line.startswith("static "):
                parser = get_parser(line, cont)
                continue

            if line == "}":
                parser = None
                continue

            parser.parse(line)
    return cont

###############################################

def gen_struct(cont1, cont2):
    adds = []
    changes = []

    for k, v2 in cont2.iteritems():
        if k in cont1:
            v1 = cont1[k]
            if v2 != v1:
                changes.append("")
                changes.append("  id = get_struc_id(\"{0}\");".format(v2.name))
                if v2.mem_change(v1):
                    changes.extend(v1.clean)
                    changes.extend(v2.member)
                if v2.attr_change(v1):
                    changes.extend(v2.attrs)
        else:
            adds.append(" " + v2.new)
            changes.append("")
            changes.append("  id = get_struc_id(\"{0}\");".format(v2.name))
            changes.extend(v2.member)
            changes.extend(v2.attrs)

    return "\n".join(adds) + "\n" + "\n".join(changes) + "\n"

def gen_struct_type_bytes(cont1, cont2):
    ret = []
    for k, v2 in cont2.iteritems():
        flag = False
        if k in cont1:
            if v2 != cont1[k]:
                flag = True
        else:
            flag = True

        if flag and not (len(v2) == 1 and v2[0].startswith("set_cmt") and '"__int64",' in v2[0]): # skip one line autogen set_cmt(__int64)
            ret.append("")
            ret.extend(v2)

    return "\n".join(ret) + "\n"

def gen_patchs(cont1, cont2):
    return "\n".join(cont2) + "\n"

def gen_function(cont1, cont2):
    ret = []
    for k, v2 in cont2.iteritems():
        if k in cont1:
            v1 = cont1[k]
            if v2 != v1:
                if v2.end_change(v1):
                    ret.append("  set_func_end({0},{1})".format(v2.start, v2.end))
                if v2.attr_change(v1):
                    ret.extend(v2.attr_sub(v1))
        else:
            ret.append("  add_func({0},{1})".format(v2.start, v2.end))
            ret.extend(v2.attrs)

    return "\n".join(ret) + "\n"

def gen_file(cont1, cont2):

    print """#define UNLOADED_FILE   1
#include <idc.idc>

static main(void) {
set_inf_attr(INF_GENFLAGS, INFFL_LOADIDC|get_inf_attr(INF_GENFLAGS));
  Structures();         // structure types
  ApplyStrucTInfos();   // structure type infos
  Patches();            // manual patches
  Bytes();              // individual bytes (code,data)
  Functions();          // function definitions
  set_inf_attr(INF_GENFLAGS, ~INFFL_LOADIDC&get_inf_attr(INF_GENFLAGS));
}

static Structures(void) {
  auto id;
  auto mid;
  begin_type_updating(UTP_STRUCT);
"""

    print gen_struct(cont1["struct"], cont2["struct"])

    print """
  end_type_updating(UTP_STRUCT);
}

static ApplyStrucTInfos() {
  auto id;
"""

    print gen_struct_type_bytes(cont1["structType"], cont2["structType"])

    print """
}

static Patches(void) {
"""

    print gen_patchs(cont1["patch"], cont2["patch"])

    print """
}

static Bytes(void) {
        auto x;
#define id x
"""

    print gen_struct_type_bytes(cont1["bytes"], cont2["bytes"])

    print """
}

static Functions(void) {
"""

    print gen_function(cont1["funcs"], cont2["funcs"])

    print """
}

"""

if __name__ == "__main__":
    gen_file(read_dc(sys.argv[1]), read_dc(sys.argv[2]))
