#!/usr/bin/python2
# Note: The bootstrap file will copy CFG_pb2.py into this dir!!
import CFG_pb2
import sys
import binascii

def main(argv):
    
    with open(argv[1], 'rb') as f:
        M = CFG_pb2.Module()
        M.ParseFromString(f.read())
        print("name: %s"%M.name)
        segs = sorted(M.segments, key=lambda k: k.ea, reverse=False)
        for seg in segs:
            print("Segment starts ---------")
            print("  segea: 0x%02X"%seg.ea)
            print("  segname: %s"%seg.name)
            print("  segsize: %s"%len(seg.data))
            print("  segdata: [omitted]")
            for var in sorted(seg.vars, key=lambda v: v.ea):
                print("   var { ea: 0x%02X \n                 name: %s }"%(var.ea, var.name))
            for xref in sorted(seg.xrefs, key=lambda v: v.ea):
                print("   xref { from: 0x%02X)"%xref.ea)
                print("          target_ea: 0x%02X"%xref.target_ea)
                print("          target_is_code: %s"%xref.target_is_code)
                print("          width: %s"%xref.width)
                print("          target_fixup_kind: %s"%xref.target_fixup_kind)
                print("          name: %s }"%xref.target_name)
        for func in sorted(M.funcs, key=lambda f: f.ea):
            print(func.name)
            print("  Stack vars {")
            for stack_var in func.stack_vars:
                print("     name: %s" % stack_var.name)
                print("     size: %s" % stack_var.size)
                print("     sp_offset: %02X" % stack_var.sp_offset)
                print("     has_frame: %s" % stack_var.has_frame)
                print("     reg_name: %s" % stack_var.reg_name)
                print("     reg_eas: %s" % stack_var.reg_eas)
            print("             }")
            for bb in sorted(func.blocks, key=lambda block: block.ea):
                print("    Basic Block  0x%02X successors: %s"%(bb.ea, [("0x%02X"%sea) for sea in sorted(bb.successor_eas)]))
                for ins in bb.instructions:
                    print("      ins(ea, local_noret, bytes)    0x%02X %s %s"%(ins.ea, ins.local_noreturn, binascii.hexlify(ins.bytes)))
                    for ref in ins.xrefs:
                        print("         xref ea: 0x%02X"%ref.ea)
                        print("              name: %s"%ref.name)
                        print("              target_type: %s"%ref.target_type)
                        print("              operand: %s"%ref.operand_type)
                        print("              location: %s"%ref.location)

if __name__ == '__main__':
    main(sys.argv)