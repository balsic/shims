import ctypes as c
import importlib.util
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

from fixtures import directory, image, imported, put, tls_image

ROOT = Path(__file__).resolve().parents[1]
STEAM = ROOT / "Resources/steam/proton_entry.py"
spec = importlib.util.spec_from_file_location("steam_entry", STEAM)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Loader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        out = Path(cls.tmp.name) / "loader.so"
        src = ROOT / "Sources/MetalBridgeLoader"
        shims = ROOT / "Sources/NativeShims"
        subprocess.run([os.getenv("CXX", "c++"), "-std=c++20", "-Wall", "-Wextra", "-Werror",
                        "-fPIC", "-shared", "-pthread", "-I" + str(src / "include"),
                        "-I" + str(shims / "include"), *sorted(src.glob("*.cpp")),
                        shims / "ntdll_xnu.cpp", "-o", out], check=True)
        cls.lib = c.CDLL(str(out))
        for name in ("mb_inspect", "mb_directories"):
            f = getattr(cls.lib, name)
            f.argtypes = [c.c_char_p, c.c_size_t, c.c_void_p]
            f.restype = c.c_char_p
        cls.lib.mb_native_probe.argtypes = [c.c_char_p, c.c_size_t]
        cls.lib.mb_native_probe.restype = c.c_char_p
        cls.lib.mb_copy_icon.argtypes = [c.c_char_p, c.c_size_t, c.POINTER(c.c_size_t)]
        cls.lib.mb_copy_icon.restype = c.c_void_p
        cls.lib.mb_free.argtypes = [c.c_void_p]
        cls.lib.mb_event_create.argtypes = [c.c_bool, c.c_bool]
        cls.lib.mb_event_create.restype = c.c_uint64
        for name in ("mb_event_set", "mb_event_reset", "mb_event_close"):
            getattr(cls.lib, name).argtypes = [c.c_uint64]
            getattr(cls.lib, name).restype = c.c_bool
        cls.lib.mb_event_wait.argtypes = [c.c_uint64, c.c_int64]

    def inspect(self, buf):
        return self.lib.mb_inspect(bytes(buf), len(buf), c.create_string_buffer(128))

    def probe(self, buf):
        return self.lib.mb_native_probe(bytes(buf), len(buf))

    def test_coff_formats(self):
        for machine in (0xaa64, 0x8664, 0x14c):
            with self.subTest(machine=machine):
                self.assertIsNone(self.inspect(image(machine)))
                self.assertEqual(self.probe(image(machine)) is None, machine == 0xaa64)

    @unittest.skipUnless(shutil.which("clang") and shutil.which("lld-link"), "requires LLVM's Windows linker")
    def test_compiler_produced_arm64_executable(self):
        folder = Path(self.tmp.name)
        source, obj, exe = (folder / ("leaf." + ext) for ext in ("c", "obj", "exe"))
        source.write_text("unsigned entry(void) { return 42; }\n")
        subprocess.run(["clang", "--target=aarch64-pc-windows-msvc", "-O2", "-c", source, "-o", obj], check=True)
        subprocess.run(["lld-link", "/entry:entry", "/machine:arm64", "/subsystem:console",
                        "/nodefaultlib", "/out:" + str(exe), obj], check=True)
        self.assertIsNone(self.probe(exe.read_bytes()))

    def test_truncation_at_every_byte(self):
        buf = image()
        for size in range(len(buf)):
            self.assertIsNotNone(self.inspect(buf[:size]), size)

    def test_no_overlap(self):
        buf = image()
        put(buf, 0x98+240+40+12, "I", 0x1000)
        self.assertIsNotNone(self.inspect(buf))

    def test_native_registers_and_control_flow(self):
        for op in (0xd61f0000, 0xd4000001, 0x52800512, 0x11000620, 0xf9400240, 0xd65f03c0):
            self.assertIsNotNone(self.probe(image(code=(op, 0xd65f03c0))))
        self.assertIsNone(self.probe(image(code=(0xf9402240, 0xd65f03c0))))
        self.assertIsNone(self.probe(image(code=(0xf9402640, 0xd65f03c0))))

    def test_bindings(self):
        self.assertIsNone(self.probe(imported()))
        self.assertIn(b"fallback", self.probe(imported(b"Unknown")))
        buf = imported()
        put(buf, 0x440, "Q", (1 << 63) + 2)
        self.assertIn(b"ordinal", self.probe(buf))

    def test_import_reloc_export_inspection(self):
        buf = imported()
        directory(buf, 5, 0x2100, 12)
        put(buf, 0x500, "IIHH", 0x2000, 12, 0xa180, 0)
        directory(buf, 0, 0x2200, 64)
        put(buf, 0x600+20, "IIIII", 1, 1, 0x2230, 0x2234, 0x2238)
        put(buf, 0x630, "IIH", 0x1000, 0x2060, 0)
        info = (c.c_uint32 * 5)()
        self.assertIsNone(self.lib.mb_directories(bytes(buf), len(buf), info))
        self.assertEqual(list(info), [1, 1, 0, 1, 1])
        put(buf, 0x638, "H", 1)
        self.assertIsNotNone(self.lib.mb_directories(bytes(buf), len(buf), info))

    def test_tls_and_entry_relocations_require_fallback(self):
        buf = image()
        directory(buf, 9, 0x2000, 40)
        self.assertIsNotNone(self.probe(buf))
        buf = image()
        directory(buf, 5, 0x2000, 12)
        put(buf, 0x400, "IIHH", 0x1000, 12, 0xa000, 0)
        self.assertIsNotNone(self.probe(buf))

    def test_callback_only_tls(self):
        buf = tls_image()
        self.assertIsNone(self.probe(buf))
        put(buf, 0x540, "Q", 0x140004000)
        self.assertIsNotNone(self.probe(buf))
        buf = tls_image()
        put(buf, 0x520, "I", 4)
        self.assertIsNotNone(self.probe(buf))

    def test_icon_resource(self):
        buf = image()
        directory(buf, 2, 0x2000, 0xa0)
        for offset, ident, child in [(0, 3, 0x80000020), (32, 7, 0x80000040), (64, 1033, 96)]:
            put(buf, 0x400+offset+14, "HII", 1, ident, child)
        put(buf, 0x460, "II", 0x2100, 64)
        put(buf, 0x500, "IIIHH", 40, 2, 4, 1, 32)
        size = c.c_size_t()
        ptr = self.lib.mb_copy_icon(bytes(buf), len(buf), c.byref(size))
        self.assertTrue(ptr)
        try:
            ico = c.string_at(ptr, size.value)
            self.assertEqual(ico[:8], bytes((0, 0, 1, 0, 1, 0, 2, 2)))
            self.assertEqual(ico[22:], buf[0x500:0x540])
        finally:
            self.lib.mb_free(ptr)

    def test_event_semantics(self):
        for manual in (True, False):
            handle = self.lib.mb_event_create(manual, False)
            self.assertTrue(handle)
            self.assertEqual(self.lib.mb_event_wait(handle, 0), 1)
            self.assertTrue(self.lib.mb_event_set(handle))
            self.assertEqual(self.lib.mb_event_wait(handle, 0), 0)
            self.assertEqual(self.lib.mb_event_wait(handle, 0), 0 if manual else 1)
            self.assertTrue(self.lib.mb_event_reset(handle))
            self.assertEqual(self.lib.mb_event_wait(handle, 0), 1)
            self.assertTrue(self.lib.mb_event_close(handle))
            self.assertEqual(self.lib.mb_event_wait(handle, 0), -1)


class Integration(unittest.TestCase):
    def test_steam_arguments(self):
        args = ["/my game/example.exe", "-option", "a b", ""]
        result = runner.command(["waitforexitandrun", *args], {"SteamAppId": "271590"}, "/app/host")
        self.assertEqual(result, ["/app/host", "run", "--backend", "auto", "--app-id", "271590",
                                  "--wait", "--", *args])
        with self.assertRaises(ValueError):
            runner.command(["run", "g.exe"], {"SteamAppId": "../x"}, "/host")
        with self.assertRaises(ValueError):
            runner.command(["unknown", "g.exe"], {"SteamAppId": "2"}, "/host")

    def test_finder_types(self):
        with (ROOT / "Resources/Info.plist").open("rb") as f:
            info = plistlib.load(f)
        declared = {t["UTTypeIdentifier"] for t in info["UTImportedTypeDeclarations"]}
        self.assertEqual(declared, set(info["CFBundleDocumentTypes"][0]["LSItemContentTypes"]))
