"""Small PE fixtures with no SDK dependency. RVAs intentionally differ from offsets."""
import argparse
from pathlib import Path
import struct


def put(buf, offset, fmt, *values):
    struct.pack_into("<" + fmt, buf, offset, *values)


def image(machine=0xaa64, code=(0x52800500, 0x11000800, 0xd65f03c0)):
    wide = machine != 0x14c
    opt_size = 240 if wide else 224
    buf = bytearray(0x800)
    buf[:2] = b"MZ"
    put(buf, 60, "I", 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    put(buf, 0x84, "HHIIIHH", machine, 2, 0, 0, 0, opt_size, 0x22)
    op = 0x98
    put(buf, op, "H", 0x20b if wide else 0x10b)
    put(buf, op+16, "II", 0x1000, 0x1000)
    if wide:
        put(buf, op+24, "Q", 0x140000000)
    else:
        put(buf, op+24, "II", 0x2000, 0x400000)
    put(buf, op+32, "II", 4096, 512)
    put(buf, op+40, "HH", 6, 0)
    put(buf, op+48, "HH", 6, 0)
    put(buf, op+56, "II", 0x3000, 0x200)
    put(buf, op+68, "H", 3)
    if wide:
        put(buf, op+72, "QQQQ", 1 << 20, 4096, 1 << 20, 4096)
    else:
        put(buf, op+72, "IIII", 1 << 20, 4096, 1 << 20, 4096)
    put(buf, op+(108 if wide else 92), "I", 16)
    table = op+opt_size
    put(buf, table, "8sIIIIIIHHI", b".text", 512, 4096, 512, 512, 0, 0, 0, 0, 0x60000020)
    put(buf, table+40, "8sIIIIIIHHI", b".data", 1024, 8192, 1024, 1024, 0, 0, 0, 0, 0xc0000040)
    put(buf, 512, "I"*len(code), *code)
    return buf


def directory(buf, index, rva, size):
    put(buf, 0x98+112+8*index, "II", rva, size)


def imported(symbol=b"GetCurrentProcessId"):
    # ADRP x16,+1 page; LDR x16,[x16,#128]; BR x16
    buf = image(code=(0xb0000010, 0xf9404210, 0xd61f0200))
    directory(buf, 1, 0x2000, 40)
    directory(buf, 12, 0x2080, 16)
    put(buf, 0x400, "IIIII", 0x2040, 0, 0, 0x2060, 0x2080)
    put(buf, 0x440, "Q", 0x20a0)
    put(buf, 0x480, "Q", 0x20a0)
    buf[0x460:0x46d] = b"KERNEL32.dll\0"
    buf[0x4a2:0x4a2+len(symbol)] = symbol
    return buf


def tls_image():
    buf = imported(b"GetLastError")
    put(buf, 0x448, "Q", 0x20c0)
    put(buf, 0x488, "Q", 0x20c0)
    buf[0x4c2:0x4cf] = b"SetLastError\0"
    directory(buf, 12, 0x2080, 24)
    directory(buf, 9, 0x2100, 40)
    put(buf, 0x500, "QQQQII", 0, 0, 0, 0x140002140, 0, 0)
    put(buf, 0x540, "QQ", 0x140001040, 0)
    # TLS process attach: SetLastError(42). The entry thunk returns GetLastError().
    put(buf, 0x240, "IIII", 0x52800540, 0xb0000010, 0xf9404610, 0xd61f0200)
    return buf


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description="Write an ARM64 PE that returns 42")
    cli.add_argument("output", type=Path)
    cli.add_argument("--tls", action="store_true")
    args = cli.parse_args()
    args.output.write_bytes(tls_image() if args.tls else image())
