import idautils
import ida_hexrays
import ida_loader
import pickle
import os
import ida_pro
import ida_typeinf

# edited from https://github.com/IDArlingTeam/IDArling

def _get_vdloc(dct):
   location = ida_hexrays.vdloc_t()
   if dct["atype"] == ida_typeinf.ALOC_NONE:
       pass
   elif dct["atype"] == ida_typeinf.ALOC_STACK:
       location.set_stkoff(dct["stkoff"])
   elif dct["atype"] == ida_typeinf.ALOC_DIST:
       pass  # FIXME: Not supported
   elif dct["atype"] == ida_typeinf.ALOC_REG1:
       location.set_reg1(dct["reg1"])
   elif dct["atype"] == ida_typeinf.ALOC_REG2:
       location.set_reg2(dct["reg1"], dct["reg2"])
   elif dct["atype"] == ida_typeinf.ALOC_RREL:
       pass  # FIXME: Not supported
   elif dct["atype"] == ida_typeinf.ALOC_STATIC:
       location.set_ea(dct["ea"])
   elif dct["atype"] == ida_typeinf.ALOC_CUSTOM:
       pass  # FIXME: Not supported
   return location

def _get_lvar_locator(dct):
    ll = ida_hexrays.lvar_locator_t()
    ll.location = _get_vdloc(dct["location"])
    ll.defea = dct["defea"]
    return ll

def _get_tinfo(type):
    type_ = ida_typeinf.tinfo_t()
    if type is not None:
        ida_typeinf.parse_decl(type_, ida_typeinf.cvar.idati, type + ";", ida_typeinf.PT_TYP)
    return type_

def _get_lvar_saved_info(dct):
    lv = ida_hexrays.lvar_saved_info_t()
    lv.ll = _get_lvar_locator(dct["ll"])
    lv.name = dct["name"]
    lv.type = _get_tinfo(dct["type"])
    lv.cmt = dct["cmt"].decode("hex")
    lv.flags = dct["flags"]
    return lv

def _set_user_lvar_settings(ea, lvars):
    lvinf = ida_hexrays.lvar_uservec_t()
    lvinf.lvvec = ida_hexrays.lvar_saved_infos_t()
    for lv in lvars["lvvec"]:
        lvinf.lvvec.push_back(
            _get_lvar_saved_info(lv)
        )
    lvinf.sizes = ida_pro.intvec_t()
    if "sizes" in lvars:
        for i in lvars["sizes"]:
            lvinf.sizes.push_back(i)
    lvinf.lmaps = ida_hexrays.lvar_mapping_t()
    for key, val in lvars["lmaps"]:
        key = _get_lvar_locator(key)
        val = _get_lvar_locator(val)
        ida_hexrays.lvar_mapping_insert(lvinf.lmaps, key, val)
    lvinf.stkoff_delta = lvars["stkoff_delta"]
    lvinf.ulv_flags = lvars["ulv_flags"]
    ida_hexrays.save_user_lvar_settings(ea, lvinf)

################################

def set_user_define(ea, usr):
    if "labels" in usr:
        labels = ida_hexrays.user_labels_new()
        for org_label, name in usr["labels"]:
            ida_hexrays.user_labels_insert(labels, org_label, name.decode("hex"))
        ida_hexrays.save_user_labels(ea, labels)

    if "cmts" in usr:
        cmts = ida_hexrays.user_cmts_new()
        for tl_ea, tl_itp, cmt in usr["cmts"]:
            tl = ida_hexrays.treeloc_t()
            tl.ea = tl_ea
            tl.itp = tl_itp
            cmts.insert(tl, ida_hexrays.citem_cmt_t(cmt.decode("hex")))
        ida_hexrays.save_user_cmts(ea, cmts)

    if "iflags" in usr:
        iflags = ida_hexrays.user_iflags_new()
        for cl_ea, cl_op, f in usr["iflags"]:
            cl = ida_hexrays.citem_locator_t(cl_ea, cl_op)
            iflags.insert(cl, f)
        ida_hexrays.save_user_iflags(ea, iflags)

        # cfunc = ida_hexrays.decompile(self.ea)
        # for (cl_ea, cl_op), f in self.iflags:
        #     cl = ida_hexrays.citem_locator_t(cl_ea, cl_op)
        #     cfunc.set_user_iflags(cl, f)
        # cfunc.save_user_iflags()

    if "numforms" in usr:
        numforms = ida_hexrays.user_numforms_new()
        for row in usr["numforms"]:
            ol = ida_hexrays.operand_locator_t(row[0], row[1])
            nf = ida_hexrays.number_format_t()
            nf.flags = row[2]
            nf.opnum = row[3]
            nf.props = row[4]
            nf.serial = row[5]
            nf.org_nbytes = row[6]
            nf.type_name = row[7]
            ida_hexrays.user_numforms_insert(numforms, ol, nf)
        ida_hexrays.save_user_numforms(ea, numforms)

    if "lvars" in usr:
        _set_user_lvar_settings(ea, usr["lvars"])

def main():
    with open(os.path.splitext(ida_loader.get_path(ida_loader.PATH_TYPE_ID0))[0].decode("utf-8") + "_.dmp", "rb") as f:
        ret = pickle.load(f)

    for func, usr in ret:
        set_user_define(func, usr)

main()
