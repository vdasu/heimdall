from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter

from .instrs_ebpf import ALU, Jump, LoadStore

class LifterEbpf(GymratLifter):

    instrs = list(ALU | Jump | LoadStore)

register(LifterEbpf, "eBPF")
