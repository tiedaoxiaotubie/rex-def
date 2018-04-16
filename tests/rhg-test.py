import rex
import angr
import simuvex
from angr import sim_options as so
import nose
import struct
from tracer import getlibcfunctionaddr
import colorguard
from rex.vulnerability import Vulnerability
from angr.state_plugins.trace_additions import FormatInfoIntToStr, FormatInfoStrToInt, FormatInfoDontConstrain
from angr.analyses.disassembly import Hook
import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
tests_dir = str(os.path.dirname(os.path.realpath(__file__)))
from angr.procedures.definitions.glibc import libc


def rhg_prepre_paths():
    exclude_sim_procedures_list = ["free", "calloc", "realloc"]
    #crash_path = '/home/vagrant/angrsource/angr-dev/binaries/tests/CRASH/90_pwn10/11/id_000081_fuzzer-2_90_pwn10'
    crash_path = '/home/crossfire/defcon-china/angr-dev/binaries/tests/CRASH/id_000000_fuzzer-1_88_pwn08'
    f = open(crash_path,'rb')
    data = f.read()
    #crash = rex.Crash(os.path.join(bin_location, "tests/work/bin"), data)
    crash = rex.Crash(os.path.join(bin_location, "tests/work/pwn08"),data)
    exploit = crash.exploit()
    if not crash.explorable():
        print 'ready to exploit'
        OWEIP = "0x41414141"
        ReadAddress = '0x080D8C44'
        WriteAddress = '0x080D8C44'
        WriteValue = '0x61616161'
        pov_dir = '/angrsource/angr-dev/binaries/tests/CRASH/88_pwn08/' #hijack=OWEIP, read_addr=ReadAddress, write_addr=WriteAddress, write_value=WriteValue,pov_dir=pov_dir
        arsenal = crash.exploit()


    p = angr.Project(os.path.join(bin_location, "tests/work/88"),exclude_sim_procedures_list=exclude_sim_procedures_list)
    libc_funcs = getlibcfunctionaddr.get_known_libc_functionaddr(os.path.join(bin_location, "tests/work/88"))

    for addr,name in libc_funcs.items():
        if name in set(libc.procedures):
            p.hook(int(addr,16),libc.procedures[name])


    a = 1




if __name__ == '__main__':
    rhg_prepre_paths()