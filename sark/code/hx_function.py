import ida_hexrays

import ida_typeinf
import idc


class HX_Function():
    """Wrapper around all the API functionality of hexrays for a specific function"""


    def __init__(self, ea):
        self._cfunc = ida_hexrays.decompile(ea)
        self._ea = ea





    @property
    def type(self):

        assert ida_typeinf.idc_get_type(self._ea) == str(self._cfunc.type)
        # ida_typeinf.idc_get_type(self._ea)
        return str(self._cfunc.type)


    @type.setter
    def type(self, new_type):
        """ Baseo on idc.SetType but with proper exceptions"""
        pt = idc.parse_decl()


        ida_typeinf.apply_type(
            None,
            new_type,
            None,
            self.ea,
            ida_typeinf.TINFO_DEFINITE
        )


    def recompile(self):
        self._cfunc = ida_hexrays.decompile(self._ea)
