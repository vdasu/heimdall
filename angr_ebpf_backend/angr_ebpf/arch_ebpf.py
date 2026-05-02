from archinfo import Arch, Register, RegisterOffset, register_arch

class ArchExtendedBPF(Arch):

    name = "eBPF"
    bits = 64

    vex_arch = None
    qemu_name = "eBPF"
    ida_processor = "eBPF"

    max_inst_bytes = 8
    instruction_alignment = 1

    register_list = [

        Register(name="R0", vex_offset=0, size=8),

        Register(name="R1", vex_offset=8, size=8),
        Register(name="R2", vex_offset=16, size=8),
        Register(name="R3", vex_offset=24, size=8),
        Register(name="R4", vex_offset=32, size=8),
        Register(name="R5", vex_offset=40, size=8),

        Register(name="R6", vex_offset=48, size=8),
        Register(name="R7", vex_offset=56, size=8),
        Register(name="R8", vex_offset=64, size=8),
        Register(name="R9", vex_offset=72, size=8),

        Register(
            name="R10",
            vex_offset=80,
            size=8,
            default_value=(Arch.initial_sp, True, (Arch.initial_sp, "stack")),
        ),

        Register(name="syscall", vex_offset=88, size=8),
        Register(name="ip", vex_offset=96, size=8),
        Register(name="ip_at_syscall", vex_offset=104, size=8),

        Register(name="call_depth", vex_offset=112, size=8, default_value=(1, False, None)),
    ]
    bp_offset = RegisterOffset(80)

register_arch(["eBPF", "em_bpf"], 64, "any", ArchExtendedBPF)
