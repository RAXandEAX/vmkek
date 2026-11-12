#!/usr/bin/env python3
"""Run the generated R06 QF_BV obligations using the installed Z3 library."""

import ctypes
import ctypes.util
import signal
import sys


def main():
    signal.alarm(15)
    name = ctypes.util.find_library("z3")
    if name is None:
        raise RuntimeError("libz3 unavailable")
    z3 = ctypes.CDLL(name)
    z3.Z3_get_full_version.restype = ctypes.c_char_p
    z3.Z3_mk_config.restype = ctypes.c_void_p
    z3.Z3_mk_context.argtypes = [ctypes.c_void_p]
    z3.Z3_mk_context.restype = ctypes.c_void_p
    z3.Z3_del_config.argtypes = [ctypes.c_void_p]
    z3.Z3_del_context.argtypes = [ctypes.c_void_p]
    z3.Z3_eval_smtlib2_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    z3.Z3_eval_smtlib2_string.restype = ctypes.c_char_p
    config = z3.Z3_mk_config()
    context = z3.Z3_mk_context(config)
    z3.Z3_del_config(config)
    try:
        version = z3.Z3_get_full_version().decode("ascii")
        answers = z3.Z3_eval_smtlib2_string(context, sys.stdin.buffer.read()).decode("ascii").split()
    finally:
        z3.Z3_del_context(context)
    if answers != ["unsat", "unsat", "sat"]:
        raise RuntimeError(f"Z3 {version} rejected R06 obligations: {answers}")
    print(f"Z3 {version}: add-pair UNSAT, subtract-negated-pair UNSAT, negative control SAT")


if __name__ == "__main__":
    main()
