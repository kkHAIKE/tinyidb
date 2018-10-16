import idautils
import ida_hexrays
import ida_loader
import pickle
import os

# edited from https://github.com/IDArlingTeam/IDArling

def _get_vdloc(location):
    return {
        "atype": location.atype(),
        "reg1": location.reg1(),
        "reg2": location.reg2(),
        "stkoff": location.stkoff(),
        "ea": location.get_ea(),
    }

def _get_lvar_locator(ll):
    return {
        "location": _get_vdloc(ll.location),
        "defea": ll.defea,
    }

def _get_tinfo(type):
    if type.empty():
        return None

    return str(type)

def _get_lvar_saved_info(lv):
    return {
        "ll": _get_lvar_locator(lv.ll),
        "name": lv.name, #.encode("hex"),
        "type": _get_tinfo(lv.type),
        "cmt": lv.cmt.encode("hex"),
        "flags": lv.flags,
    }

def _get_user_lvar_settings(ea):
    dct = {}
    lvinf = ida_hexrays.lvar_uservec_t()
    if ida_hexrays.restore_user_lvar_settings(lvinf, ea):
        dct["lvvec"] = []
        for lv in lvinf.lvvec:
            dct["lvvec"].append(_get_lvar_saved_info(lv))
        if hasattr(lvinf, "sizes"):
            dct["sizes"] = list(lvinf.sizes)
        dct["lmaps"] = []
        it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
        while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
            key = ida_hexrays.lvar_mapping_first(it)
            key = _get_lvar_locator(key)
            val = ida_hexrays.lvar_mapping_second(it)
            val = _get_lvar_locator(val)
            dct["lmaps"].append((key, val))
            it = ida_hexrays.lvar_mapping_next(it)
        dct["stkoff_delta"] = lvinf.stkoff_delta
        dct["ulv_flags"] = lvinf.ulv_flags
    return dct

########################################

def get_user_define(ea):
    ret = {}
    labels = ida_hexrays.restore_user_labels(ea)
    if labels is not None:
        arr = []
        it = ida_hexrays.user_labels_begin(labels)
        while it != ida_hexrays.user_labels_end(labels):
            org_label = ida_hexrays.user_labels_first(it)
            name = ida_hexrays.user_labels_second(it)
            arr.append((org_label, name.encode("hex")))
            it = ida_hexrays.user_labels_next(it)
        ret["labels"] = arr
        ida_hexrays.user_labels_free(labels)

    cmts = ida_hexrays.restore_user_cmts(ea);
    if cmts is not None:
        arr = []
        for tl, cmt in cmts.iteritems():
            arr.append((tl.ea, tl.itp, str(cmt).encode("hex")))
        ret["cmts"] = arr
        ida_hexrays.user_cmts_free(cmts)

    iflags = ida_hexrays.restore_user_iflags(ea)
    if iflags is not None:
        arr = []
        for cl, f in iflags.iteritems():
            arr.append((cl.ea, cl.op, f))
        ret["iflags"] = arr
        ida_hexrays.user_iflags_free(iflags)

    numforms = ida_hexrays.restore_user_numforms(ea)
    if numforms is not None:
        arr = []
        for ol, nf in numforms.iteritems():
            arr.append((ol.ea, ol.opnum, nf.flags, nf.opnum, nf.props, nf.serial, nf.org_nbytes, nf.type_name))
        ret["numforms"] = arr
        ida_hexrays.user_numforms_free(numforms)

    lvars = _get_user_lvar_settings(ea)
    if lvars:
        ret["lvars"] = lvars

    return ret

def main():
    # ida_hexrays.init_hexrays_plugin()
    ret = []
    for func in idautils.Functions():
        usr = get_user_define(func)
        if usr:
            ret.append((func, usr))
    with open(os.path.splitext(ida_loader.get_path(ida_loader.PATH_TYPE_ID0))[0].decode("utf-8") + "_.dmp", "wb") as f:
        pickle.dump(ret, f, pickle.HIGHEST_PROTOCOL)

main()
