#!/usr/bin/env python3
"""
InterXDB_FFServer v1.0
======================
Anviz VF30PRO / V300 Fingerprint Reader Management System

Features:
  - Real-time punch capture  → CSV log + SQLite database
  - Duplicate punch filtering (configurable window)
  - Network device scan (UDP broadcast)
  - View / edit device network configuration
  - List and delete enrolled users
  - Download / upload fingerprint templates
  - Transfer users between multiple devices
  - Server Mode or Client Mode connection support

Requirements: 64-bit Python 3.8+, PyQt6
Run: python interxdb.py
"""

import ctypes
import json
import os
import struct
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QListWidget, QListWidgetItem, QStackedWidget, QGroupBox, QFormLayout,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QHeaderView,
    QSpinBox, QDateEdit, QDialog, QDialogButtonBox, QTabWidget, QCheckBox,
    QTextEdit, QSplitter, QFrame,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QDate
from PyQt6.QtGui import QPixmap, QIcon, QColor, QFont

import sqlite3

# ─────────────────────────────────────────────────────────────────────────────
# App constants
# ─────────────────────────────────────────────────────────────────────────────
APP_NAME    = "InterXDB_FFServer"
APP_VERSION = "1.0"

# When frozen by PyInstaller the EXE may be in Program Files (read-only).
# Writable files (DB, config, logs) go to %APPDATA%\InterXDB_FFServer\.
# Read-only assets (DLL, images) come from _BUNDLE_DIR (_internal folder).
if getattr(sys, "frozen", False):
    _BUNDLE_DIR = sys._MEIPASS                              # _internal\ (read-only assets)
else:
    _BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))

# User-writable data directory — works for both dev and installed EXE
_APPDATA    = os.environ.get("APPDATA", os.path.expanduser("~"))
APP_DIR     = os.path.join(_APPDATA, "InterXDB_FFServer")
os.makedirs(APP_DIR, exist_ok=True)                         # create on first run

LOGO_PATH   = os.path.join(_BUNDLE_DIR, "InterXDB LOGO.jpg")  # GUI sidebar logo
ICON_PATH   = os.path.join(_BUNDLE_DIR, "InterXICO.ico")      # window/taskbar icon
CONFIG_PATH = os.path.join(APP_DIR, "interxdb_config.json")
DB_PATH     = os.path.join(APP_DIR, "interxdb.db")

# DLL is bundled into _BUNDLE_DIR root (datas dest='.') when frozen,
# otherwise look in the original SDK subfolder.
DLL_NAME    = "tc-b_new_sdk.dll"
DLL_PATH    = os.path.join(_BUNDLE_DIR, DLL_NAME)
BUFF_SIZE   = 32000
FP_MAX_LEN  = 15360

DEFAULT_CONFIG = {
    "conn_mode":     "client",
    "device_ip":     "192.168.1.218",
    "device_port":   5010,
    "server_port":   5010,
    "log_dir":       APP_DIR,
    "dedup_seconds": 60,
}

# ─────────────────────────────────────────────────────────────────────────────
# Attendance / verify lookup tables
# ─────────────────────────────────────────────────────────────────────────────
ATTEND_STATUS = {
    0: ("I",  "Check-In"),
    1: ("O",  "Check-Out"),
    2: ("BO", "Break-Out"),
    3: ("BI", "Break-In"),
    4: ("LO", "OT-In"),
    5: ("LI", "OT-Out"),
}
VERIFY_METHOD = {
    0: "FP", 1: "Card", 2: "PIN", 3: "FP+Card",
    4: "FP+PIN", 5: "Card+PIN", 6: "FP+Card+PIN",
    8: "FP", 15: "Auto",
}

def punch_short(rec_type):
    """Return (short_code, long_name) from a RecordType byte."""
    return ATTEND_STATUS.get(rec_type & 0x0F, ("?", f"Type-{rec_type & 0x0F}"))

def verify_str(rec_type):
    return VERIFY_METHOD.get((rec_type >> 4) & 0x0F, f"Verify-{(rec_type>>4)&0x0F}")

# ─────────────────────────────────────────────────────────────────────────────
# ctypes Structures  (_pack_=1 — no padding, matches SDK exactly)
# ─────────────────────────────────────────────────────────────────────────────

class DevLoginInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("DevIdx",      ctypes.c_int),
        ("MachineId",   ctypes.c_uint),
        ("Addr",        ctypes.c_char * 24),
        ("Version",     ctypes.c_char * 8),
        ("DevType",     ctypes.c_char * 8),
        ("DevTypeFlag", ctypes.c_uint),
    ]

class RecordInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("MachineId",     ctypes.c_uint),
        ("NewRecordFlag", ctypes.c_ubyte),
        ("EmployeeId",    ctypes.c_ubyte * 5),
        ("Date",          ctypes.c_ubyte * 4),
        ("BackId",        ctypes.c_ubyte),
        ("RecordType",    ctypes.c_ubyte),
        ("WorkType",      ctypes.c_ubyte * 3),
        ("Rsv",           ctypes.c_ubyte),
        ("CurIdx",        ctypes.c_uint),
        ("TotalCnt",      ctypes.c_uint),
    ]

class LiveAttendanceInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("MachineId",  ctypes.c_uint),
        ("Result",     ctypes.c_int),
        ("EmployeeId", ctypes.c_ubyte * 5),
        ("Date",       ctypes.c_ubyte * 4),
        ("BackId",     ctypes.c_ubyte),
        ("RecordType", ctypes.c_ubyte),
        ("WorkType",   ctypes.c_ubyte * 3),
    ]

class PersonInfo(ctypes.Structure):
    """CCHEX_RET_PERSON_INFO_STRU — natural C alignment (no _pack_=1).
    Confirmed offsets from raw device dump:
      password        @ 20  (1-byte pad after max_password for int alignment)
      card_id         @ 28  (3-byte pad after max_card_id for uint alignment)
      max_EmployeeName@ 32, EmployeeName[64] @ 33
      Fp_Status       @ 100 (100 is 4-byte aligned, no extra pad needed)
    """
    _fields_ = [
        ("MachineId",        ctypes.c_uint),          # offset 0
        ("CurIdx",           ctypes.c_int),            # offset 4
        ("TotalCnt",         ctypes.c_int),            # offset 8
        ("EmployeeId",       ctypes.c_ubyte * 5),      # offset 12
        ("password_len",     ctypes.c_ubyte),           # offset 17
        ("max_password",     ctypes.c_ubyte),           # offset 18
        # C compiler inserts 1-byte pad here → int aligns to offset 20
        ("password",         ctypes.c_int),             # offset 20
        ("max_card_id",      ctypes.c_ubyte),           # offset 24
        # C compiler inserts 3-byte pad here → uint aligns to offset 28
        ("card_id",          ctypes.c_uint),            # offset 28
        ("max_EmployeeName", ctypes.c_ubyte),           # offset 32
        ("EmployeeName",     ctypes.c_char * 64),       # offset 33
        ("DepartmentId",     ctypes.c_ubyte),           # offset 97
        ("GroupId",          ctypes.c_ubyte),           # offset 98
        ("Mode",             ctypes.c_ubyte),            # offset 99
        ("Fp_Status",        ctypes.c_uint),             # offset 100
        ("Rserved1",         ctypes.c_ubyte),            # offset 104
        ("Rserved2",         ctypes.c_ubyte),            # offset 105
        ("Special",          ctypes.c_ubyte),            # offset 106
        ("EmployeeName2",    ctypes.c_char * 160),       # offset 107
        ("RFC",              ctypes.c_char * 13),        # offset 267
        ("CURP",             ctypes.c_char * 18),        # offset 280
    ]

class DelPersonInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("EmployeeId", ctypes.c_ubyte * 5),
        ("operation",  ctypes.c_ubyte),   # 0xFF = delete everything
    ]

class FpDownloadResult(ctypes.Structure):
    """CCHEX_RET_DLFINGERPRT_STRU — FP_LEN + 18 bytes"""
    _pack_ = 1
    _fields_ = [
        ("MachineId",  ctypes.c_uint),
        ("Result",     ctypes.c_int),
        ("EmployeeId", ctypes.c_ubyte * 5),
        ("FpIdx",      ctypes.c_ubyte),
        ("fp_len",     ctypes.c_uint),
        ("Data",       ctypes.c_ubyte * FP_MAX_LEN),
    ]

class NetCfgInfo(ctypes.Structure):
    """CCHEX_NETCFG_INFO_STRU — 27 bytes"""
    _pack_ = 1
    _fields_ = [
        ("IpAddr",       ctypes.c_ubyte * 4),
        ("IpMask",       ctypes.c_ubyte * 4),
        ("MacAddr",      ctypes.c_ubyte * 6),
        ("GwAddr",       ctypes.c_ubyte * 4),
        ("ServAddr",     ctypes.c_ubyte * 4),
        ("RemoteEnable", ctypes.c_ubyte),
        ("Port",         ctypes.c_ubyte * 2),
        ("Mode",         ctypes.c_ubyte),
        ("DhcpEnable",   ctypes.c_ubyte),
    ]

class GetNetCfgResult(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("MachineId", ctypes.c_uint),
        ("Result",    ctypes.c_int),
        ("Cfg",       NetCfgInfo),
    ]

class DevNetInfo(ctypes.Structure):
    """25-byte net info inside UDP search result"""
    _pack_ = 1
    _fields_ = [
        ("IpAddr",   ctypes.c_ubyte * 4),
        ("IpMask",   ctypes.c_ubyte * 4),
        ("GwAddr",   ctypes.c_ubyte * 4),
        ("MacAddr",  ctypes.c_ubyte * 6),
        ("ServAddr", ctypes.c_ubyte * 4),
        ("Port",     ctypes.c_ubyte * 2),
        ("NetMode",  ctypes.c_ubyte),
    ]

class UdpSearchBasic(ctypes.Structure):
    """CCHEX_UDP_SEARCH_STRU — 63 bytes"""
    _pack_ = 1
    _fields_ = [
        ("DevType",      ctypes.c_char * 10),
        ("DevSerialNum", ctypes.c_char * 16),
        ("DevNetInfo",   DevNetInfo),
        ("Version",      ctypes.c_char * 8),
        ("Reserved",     ctypes.c_ubyte * 4),
    ]

class UdpSearchExtInf(ctypes.Structure):
    """CCHEX_UDP_SEARCH_STRU_EXT_INF — 180 bytes"""
    _pack_ = 1
    _fields_ = [
        ("Data",            ctypes.c_ubyte * 167),
        ("Padding",         ctypes.c_ubyte),
        ("Result",          ctypes.c_int),
        ("MachineId",       ctypes.c_uint),
        ("DevHardwareType", ctypes.c_int),
    ]

class UdpSearchAll(ctypes.Structure):
    """CCHEX_UDP_SEARCH_ALL_STRU_EXT_INF — 9004 bytes"""
    _pack_ = 1
    _fields_ = [
        ("DevNum",       ctypes.c_int),
        ("dev_net_info", UdpSearchExtInf * 50),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def emp_to_int(b) -> int:
    """5-byte big-endian employee ID → integer."""
    r = 0
    for x in b:
        r = (r << 8) | int(x)
    return r

def int_to_emp(uid: int) -> bytes:
    """Integer → 5-byte big-endian employee ID."""
    out = []
    for _ in range(5):
        out.append(uid & 0xFF)
        uid >>= 8
    return bytes(reversed(out))

def decode_ts(date_bytes) -> datetime:
    """Decode 4-byte SDK timestamp → datetime."""
    val = struct.unpack('<I', bytes(date_bytes))[0]
    sw  = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | \
          ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24)
    return datetime(2000, 1, 2) + timedelta(seconds=sw)

def ip_str(b) -> str:
    return ".".join(str(x) for x in b[:4])

def ip_bytes(s: str):
    return [int(x) for x in s.split(".")]

def port_int(b) -> int:
    return (b[0] << 8) | b[1]

def port_bytes(p: int):
    return [(p >> 8) & 0xFF, p & 0xFF]

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                c = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                c.setdefault(k, v)
            return c
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_cfg(c: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(c, f, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────

class Database:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._setup()

    def _setup(self):
        with sqlite3.connect(self.path) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS punches (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER,
                    punch_code  TEXT,
                    punch_label TEXT,
                    verify      TEXT,
                    timestamp   TEXT,
                    device_id   INTEGER,
                    source      TEXT
                )""")
            c.execute("CREATE INDEX IF NOT EXISTS ix_ts  ON punches(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_uid ON punches(user_id)")

            # ac_users — person directory owned by InterXDB_FFServer.
            # SmartBuild reads this table in read-only mode for Access Control.
            c.execute("""
                CREATE TABLE IF NOT EXISTS ac_users (
                    user_id    INTEGER PRIMARY KEY,
                    first_name TEXT    NOT NULL DEFAULT '',
                    last_name  TEXT    NOT NULL DEFAULT '',
                    org_name   TEXT    NOT NULL DEFAULT '',
                    department TEXT    NOT NULL DEFAULT '',
                    photo_path TEXT    NOT NULL DEFAULT ''
                )""")
            # Migration: add photo_path to existing DBs that predate this column
            try:
                c.execute(
                    "ALTER TABLE ac_users ADD COLUMN photo_path TEXT NOT NULL DEFAULT ''"
                )
            except Exception:
                pass  # Column already exists — safe to ignore

    def insert(self, uid, code, label, verify, ts: datetime, dev_id, src):
        with sqlite3.connect(self.path) as c:
            c.execute(
                "INSERT INTO punches (user_id,punch_code,punch_label,verify,timestamp,device_id,source)"
                " VALUES (?,?,?,?,?,?,?)",
                (uid, code, label, verify, ts.strftime("%Y-%m-%d %H:%M:%S"), dev_id, src)
            )

    def query(self, uid=None, df=None, dt=None, code=None, limit=1000):
        sql = "SELECT user_id,punch_code,punch_label,verify,timestamp,device_id,source FROM punches WHERE 1=1"
        p = []
        if uid:   sql += " AND user_id=?";        p.append(uid)
        if df:    sql += " AND timestamp>=?";     p.append(df)
        if dt:    sql += " AND timestamp<=?";     p.append(dt)
        if code:  sql += " AND punch_code=?";     p.append(code)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        p.append(limit)
        with sqlite3.connect(self.path) as c:
            return c.execute(sql, p).fetchall()

    def today_count(self):
        d = datetime.now().strftime("%Y-%m-%d")
        with sqlite3.connect(self.path) as c:
            r = c.execute("SELECT COUNT(*) FROM punches WHERE timestamp LIKE ?", (d+"%",)).fetchone()
            return r[0] if r else 0

    def total_count(self):
        with sqlite3.connect(self.path) as c:
            r = c.execute("SELECT COUNT(*) FROM punches").fetchone()
            return r[0] if r else 0

    # ── ac_users CRUD ─────────────────────────────────────────────────────────

    def ac_get_all(self):
        """Return all rows from ac_users ordered by user_id."""
        with sqlite3.connect(self.path) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(
                "SELECT * FROM ac_users ORDER BY user_id"
            ).fetchall()]

    def ac_upsert(self, user_id: int, first_name: str, last_name: str,
                  org_name: str, department: str, photo_path: str = ""):
        """Insert or replace a person record in ac_users."""
        with sqlite3.connect(self.path) as c:
            c.execute(
                "INSERT OR REPLACE INTO ac_users "
                "(user_id, first_name, last_name, org_name, department, photo_path) "
                "VALUES (?,?,?,?,?,?)",
                (user_id, first_name.strip(), last_name.strip(),
                 org_name.strip(), department.strip(), photo_path.strip())
            )

    def ac_delete(self, user_id: int):
        """Remove a person record from ac_users."""
        with sqlite3.connect(self.path) as c:
            c.execute("DELETE FROM ac_users WHERE user_id=?", (user_id,))

# ─────────────────────────────────────────────────────────────────────────────
# AnvizSDK wrapper
# ─────────────────────────────────────────────────────────────────────────────

class AnvizSDK:
    def __init__(self):
        self.lib    = None
        self.handle = None

    def load(self):
        # Add the directory that contains the DLL so its dependencies resolve
        dll_dir = os.path.dirname(DLL_PATH)
        if not os.path.isdir(dll_dir):
            raise FileNotFoundError(f"DLL directory not found:\n{dll_dir}")
        os.add_dll_directory(dll_dir)
        if not os.path.isfile(DLL_PATH):
            raise FileNotFoundError(f"DLL not found:\n{DLL_PATH}")
        self.lib = ctypes.CDLL(DLL_PATH)
        self._decl()

    def _decl(self):
        L  = self.lib
        vp = ctypes.c_void_p
        ci = ctypes.c_int
        cu = ctypes.c_uint
        cb = ctypes.c_ubyte
        cs = ctypes.c_char_p

        L.CChex_Version.restype  = cu;  L.CChex_Version.argtypes  = []
        L.CChex_Init.restype     = None; L.CChex_Init.argtypes     = []
        # CChex_Start_With_Param replaces the deprecated CChex_Set_Service_Port + CChex_Start
        L.CChex_Start_With_Param.restype  = vp
        L.CChex_Start_With_Param.argtypes = [ctypes.c_uint, ctypes.c_uint]
        L.CChex_Start.restype    = vp;  L.CChex_Start.argtypes    = []
        L.CChex_Stop.restype     = None; L.CChex_Stop.argtypes     = [vp]
        L.CChex_Get_Service_Port.restype  = ci
        L.CChex_Get_Service_Port.argtypes = [vp]
        L.CChex_SetSdkConfig.restype  = None
        L.CChex_SetSdkConfig.argtypes = [vp, ci, ci, ci]
        L.CCHex_ClientConnect.restype    = ci
        L.CCHex_ClientConnect.argtypes   = [vp, cs, ci]
        L.CCHex_ClientDisconnect.restype  = ci
        L.CCHex_ClientDisconnect.argtypes = [vp, ci]
        L.CChex_Update.restype    = ci
        L.CChex_Update.argtypes   = [vp, ctypes.POINTER(ci), ctypes.POINTER(ci), vp, ci]
        L.CChex_DownloadAllRecords.restype    = ci
        L.CChex_DownloadAllRecords.argtypes   = [vp, ci]
        L.CChex_DownloadAllNewRecords.restype  = ci
        L.CChex_DownloadAllNewRecords.argtypes = [vp, ci]
        L.CChex_GetNetConfig.restype   = ci
        L.CChex_GetNetConfig.argtypes  = [vp, ci]
        L.CChex_SetNetConfig.restype   = ci
        L.CChex_SetNetConfig.argtypes  = [vp, ci, ctypes.POINTER(NetCfgInfo)]
        L.CChex_ListPersonInfo.restype  = ci
        L.CChex_ListPersonInfo.argtypes = [vp, ci]
        L.CChex_DeletePersonInfo.restype  = ci
        L.CChex_DeletePersonInfo.argtypes = [vp, ci, ctypes.POINTER(DelPersonInfo)]
        L.CChex_DownloadFingerPrint.restype  = ci
        L.CChex_DownloadFingerPrint.argtypes = [vp, ci, cs, cb]
        L.CChex_UploadFingerPrint.restype  = ci
        L.CChex_UploadFingerPrint.argtypes = [vp, ci, cs, cb, cs, ci]
        L.CCHex_Udp_Search_Dev.restype  = ci
        L.CCHex_Udp_Search_Dev.argtypes = [vp]
        L.CChex_ModifyPersonInfo.restype  = ci
        L.CChex_ModifyPersonInfo.argtypes = [vp, ci, ctypes.POINTER(PersonInfo), cb]

    def start(self, server_port=None):
        self.lib.CChex_Init()
        if server_port:
            # IsCloseServer=0 (keep server open), ServerPort=requested port
            self.handle = self.lib.CChex_Start_With_Param(0, int(server_port))
        else:
            self.handle = self.lib.CChex_Start()
        if not self.handle:
            raise RuntimeError("CChex_Start returned NULL")
        self.lib.CChex_SetSdkConfig(self.handle, 1, 1, 1)
        return self.lib.CChex_Get_Service_Port(self.handle)

    def stop(self):
        if self.handle:
            self.lib.CChex_Stop(self.handle)
            self.handle = None

    def connect(self, ip: str, port: int):
        return self.lib.CCHex_ClientConnect(self.handle, ip.encode("ascii"), port)

    def disconnect(self, dev_idx: int):
        return self.lib.CCHex_ClientDisconnect(self.handle, dev_idx)

    def poll(self, buf, di, ti):
        return self.lib.CChex_Update(
            self.handle, di, ti, ctypes.cast(buf, ctypes.c_void_p), BUFF_SIZE)

    def dl_new(self, di):  return self.lib.CChex_DownloadAllNewRecords(self.handle, di)
    def dl_all(self, di):  return self.lib.CChex_DownloadAllRecords(self.handle, di)
    def get_net(self, di): return self.lib.CChex_GetNetConfig(self.handle, di)

    def set_net(self, di, cfg: NetCfgInfo):
        return self.lib.CChex_SetNetConfig(self.handle, di, ctypes.byref(cfg))

    def list_persons(self, di):
        return self.lib.CChex_ListPersonInfo(self.handle, di)

    def delete_person(self, di, uid_bytes: bytes):
        d = DelPersonInfo()
        for i, b in enumerate(uid_bytes[:5]):
            d.EmployeeId[i] = b
        d.operation = 0xFF
        return self.lib.CChex_DeletePersonInfo(self.handle, di, ctypes.byref(d))

    def dl_fp(self, di, uid_bytes: bytes, fi: int):
        return self.lib.CChex_DownloadFingerPrint(self.handle, di, uid_bytes, fi)

    def ul_fp(self, di, uid_bytes: bytes, fi: int, data: bytes, length: int):
        return self.lib.CChex_UploadFingerPrint(self.handle, di, uid_bytes, fi, data, length)

    def udp_scan(self):
        return self.lib.CCHex_Udp_Search_Dev(self.handle)

    def modify_person(self, di, p: PersonInfo):
        return self.lib.CChex_ModifyPersonInfo(self.handle, di, ctypes.byref(p), 1)

    def version(self):
        return self.lib.CChex_Version()

# ─────────────────────────────────────────────────────────────────────────────
# SDK Poller Thread
# ─────────────────────────────────────────────────────────────────────────────

class Poller(QThread):
    # Signals emitted to the main thread
    dev_login    = pyqtSignal(int, str, int)        # dev_idx, info, type_flag
    dev_logout   = pyqtSignal(int)
    punch        = pyqtSignal(int, object, int, bool)  # uid, datetime, rec_type, is_live
    person       = pyqtSignal(dict)
    fp_dl        = pyqtSignal(int, int, bytes, int)    # uid, fi, data, fp_len
    fp_ul        = pyqtSignal(int, int, bool)           # uid, fi, ok
    net_cfg      = pyqtSignal(int, object)              # dev_idx, NetCfgInfo
    udp_devs     = pyqtSignal(list)
    del_ok       = pyqtSignal(int, bool)                # uid, ok
    log_msg      = pyqtSignal(str)
    connected    = pyqtSignal(bool)

    MSG_RECORD   = 1;  MSG_LOGIN   = 2;  MSG_LOGOUT  = 3
    MSG_DL_FP    = 4;  MSG_UL_FP   = 5;  MSG_PERSON  = 9
    MSG_NEW_REC  = 71; MSG_LIVE    = 54; MSG_GETNET  = 23
    MSG_SETNET   = 24; MSG_DELPRS  = 31; MSG_UDP     = 48
    MSG_RELOGIN  = 201

    def __init__(self, sdk: AnvizSDK):
        super().__init__()
        self.sdk     = sdk
        self.running = False
        self.devices = {}   # dev_idx -> dict

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        buf  = ctypes.create_string_buffer(BUFF_SIZE)
        di   = (ctypes.c_int * 1)(0)
        ti   = (ctypes.c_int * 1)(0)

        while self.running:
            try:
                ret = self.sdk.poll(buf, di, ti)
                if ret <= 0:
                    self.msleep(10)
                    continue

                mt = ti[0]; dx = di[0]

                if mt in (self.MSG_LOGIN, self.MSG_RELOGIN):
                    s = DevLoginInfo.from_buffer_copy(buf.raw)
                    addr  = s.Addr.decode("ascii",  errors="ignore").rstrip("\x00")
                    model = s.DevType.decode("ascii",  errors="ignore").rstrip("\x00")
                    ver   = s.Version.decode("ascii", errors="ignore").rstrip("\x00")
                    self.devices[s.DevIdx] = {
                        "machine_id": s.MachineId, "type_flag": s.DevTypeFlag,
                        "model": model, "addr": addr, "version": ver,
                    }
                    info = f"Model={model}  FW={ver}  MachineId={s.MachineId}  Addr={addr}  Flag=0x{s.DevTypeFlag:08X}"
                    self.dev_login.emit(s.DevIdx, info, int(s.DevTypeFlag))
                    self.connected.emit(True)

                elif mt == self.MSG_LOGOUT:
                    self.devices.pop(dx, None)
                    self.dev_logout.emit(dx)
                    if not self.devices:
                        self.connected.emit(False)

                elif mt in (self.MSG_RECORD, self.MSG_NEW_REC):
                    r = RecordInfo.from_buffer_copy(buf.raw)
                    self.punch.emit(emp_to_int(r.EmployeeId), decode_ts(r.Date), r.RecordType, False)

                elif mt == self.MSG_LIVE:
                    r = LiveAttendanceInfo.from_buffer_copy(buf.raw)
                    self.punch.emit(emp_to_int(r.EmployeeId), decode_ts(r.Date), r.RecordType, True)

                elif mt == self.MSG_PERSON:
                    p  = PersonInfo.from_buffer_copy(buf.raw)
                    uid = emp_to_int(p.EmployeeId)
                    self.person.emit({
                        "uid": uid,
                        "name": p.EmployeeName.decode("ascii", errors="ignore").rstrip("\x00"),
                        "card_id": p.card_id,
                        "fp_status": p.Fp_Status,
                        "fp_count": bin(p.Fp_Status & 0x3FF).count("1"),
                        "dept": p.DepartmentId,
                        "cur": p.CurIdx, "total": p.TotalCnt,
                        "_raw": p,
                    })

                elif mt == self.MSG_DL_FP:
                    fp = FpDownloadResult.from_buffer_copy(buf.raw[:ctypes.sizeof(FpDownloadResult)])
                    uid  = emp_to_int(fp.EmployeeId)
                    data = bytes(fp.Data[:fp.fp_len]) if fp.Result == 0 and fp.fp_len else b""
                    self.fp_dl.emit(uid, fp.FpIdx, data, fp.fp_len)

                elif mt == self.MSG_UL_FP:
                    fp = FpDownloadResult.from_buffer_copy(buf.raw[:ctypes.sizeof(FpDownloadResult)])
                    self.fp_ul.emit(emp_to_int(fp.EmployeeId), fp.FpIdx, fp.Result == 0)

                elif mt == self.MSG_GETNET:
                    r = GetNetCfgResult.from_buffer_copy(buf.raw[:ctypes.sizeof(GetNetCfgResult)])
                    if r.Result == 0:
                        self.net_cfg.emit(dx, r.Cfg)

                elif mt == self.MSG_DELPRS:
                    res = struct.unpack_from('<i', buf.raw, 4)[0]
                    uid = emp_to_int(buf.raw[8:13])
                    self.del_ok.emit(uid, res == 0)

                elif mt == self.MSG_UDP:
                    all_dev = UdpSearchAll.from_buffer_copy(buf.raw[:ctypes.sizeof(UdpSearchAll)])
                    devs = []
                    for i in range(min(all_dev.DevNum, 50)):
                        ext = all_dev.dev_net_info[i]
                        if ext.Result != 0:
                            continue
                        try:
                            b   = UdpSearchBasic.from_buffer_copy(bytes(ext.Data[:ctypes.sizeof(UdpSearchBasic)]))
                            ni  = b.DevNetInfo
                            devs.append({
                                "machine_id": ext.MachineId,
                                "model":   b.DevType.decode("ascii", errors="ignore").rstrip("\x00"),
                                "serial":  b.DevSerialNum.decode("ascii", errors="ignore").rstrip("\x00"),
                                "version": b.Version.decode("ascii", errors="ignore").rstrip("\x00"),
                                "ip":      ip_str(ni.IpAddr), "mask": ip_str(ni.IpMask),
                                "gateway": ip_str(ni.GwAddr),  "serv": ip_str(ni.ServAddr),
                                "port":    port_int(ni.Port),
                                "mode":    "Server" if ni.NetMode == 1 else "Client",
                            })
                        except Exception:
                            pass
                    self.udp_devs.emit(devs)

            except Exception as e:
                self.log_msg.emit(f"[POLL ERROR] {e}")
                self.msleep(100)

# ─────────────────────────────────────────────────────────────────────────────
# Dark theme stylesheet
# ─────────────────────────────────────────────────────────────────────────────
STYLE = """
QMainWindow,QWidget { background:#1a1a2e; color:#e0e0e0; font-family:'Segoe UI'; font-size:13px; }
QWidget#sidebar    { background:#0f0f1a; }
QPushButton        { background:#2a2a4a; color:#e0e0e0; border:1px solid #3a3a5a; border-radius:5px; padding:6px 14px; }
QPushButton:hover  { background:#3a3a6a; }
QPushButton:pressed{ background:#1a1a3a; }
QPushButton#accent { background:#1565c0; color:#fff; border:none; font-weight:bold; }
QPushButton#accent:hover { background:#1976d2; }
QPushButton#danger { background:#b71c1c; color:#fff; border:none; }
QPushButton#danger:hover { background:#c62828; }
QPushButton#nav    { background:transparent; color:#8090b0; border:none; border-radius:0;
                     padding:13px 20px; text-align:left; font-size:13px; }
QPushButton#nav:hover        { background:#1e1e3a; color:#fff; }
QPushButton#nav[active=true] { background:#1e1e4a; color:#4a9eff; border-left:3px solid #4a9eff; }
QLineEdit,QSpinBox,QComboBox { background:#2a2a4a; color:#e0e0e0; border:1px solid #3a3a5a; border-radius:4px; padding:5px 8px; }
QLineEdit:focus,QSpinBox:focus,QComboBox:focus { border:1px solid #4a9eff; }
QTableWidget       { background:#1e1e38; color:#e0e0e0; gridline-color:#2a2a4a; border:1px solid #2a2a4a; selection-background-color:#2a4a7a; }
QTableWidget::item { padding:4px; }
QHeaderView::section { background:#2a2a4a; color:#9090c0; border:1px solid #3a3a5a; padding:5px; font-weight:bold; }
QLabel#title    { font-size:20px; font-weight:bold; color:#fff; }
QLabel#subtitle { font-size:11px; color:#708090; }
QLabel#statval  { font-size:26px; font-weight:bold; color:#4a9eff; }
QLabel#statlbl  { font-size:11px; color:#9090b0; }
QWidget#card    { background:#1e1e38; border:1px solid #2a2a4a; border-radius:8px; }
QListWidget     { background:#1a1a2e; color:#c0c0d0; border:1px solid #2a2a4a; }
QListWidget::item { padding:3px 6px; }
QListWidget::item:selected { background:#2a4a7a; }
QScrollBar:vertical { background:#1a1a2e; width:8px; border-radius:4px; }
QScrollBar::handle:vertical { background:#3a3a5a; border-radius:4px; min-height:20px; }
QGroupBox { color:#9090b0; border:1px solid #2a2a4a; border-radius:6px; margin-top:10px; padding-top:8px; font-weight:bold; }
QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 5px; }
QProgressBar { background:#2a2a4a; border:1px solid #3a3a5a; border-radius:4px; text-align:center; height:16px; }
QProgressBar::chunk { background:#1565c0; border-radius:3px; }
QDateEdit { background:#2a2a4a; color:#e0e0e0; border:1px solid #3a3a5a; border-radius:4px; padding:5px; }
QTabWidget::pane  { border:1px solid #2a2a4a; }
QTabBar::tab      { background:#1a1a2e; color:#9090b0; padding:8px 16px; border:1px solid #2a2a4a; border-bottom:none; }
QTabBar::tab:selected { background:#1e1e38; color:#e0e0e0; }
QTextEdit { background:#1e1e38; color:#c0d0c0; border:1px solid #2a2a4a; font-family:Consolas; font-size:12px; }
QSplitter::handle { background:#2a2a4a; }
"""

# ─────────────────────────────────────────────────────────────────────────────
# Reusable stat card widget
# ─────────────────────────────────────────────────────────────────────────────
class StatCard(QWidget):
    def __init__(self, label, value="0", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setMinimumHeight(90)
        vl = QVBoxLayout(self)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._val = QLabel(value)
        self._val.setObjectName("statval")
        self._val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel(label)
        lbl.setObjectName("statlbl")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(self._val)
        vl.addWidget(lbl)

    def set_value(self, v):
        self._val.setText(str(v))

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Panel
# ─────────────────────────────────────────────────────────────────────────────
class DashboardPanel(QWidget):
    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self._build()
        t = QTimer(self); t.timeout.connect(self._refresh); t.start(5000)

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)

        hdr = QLabel("Dashboard")
        hdr.setObjectName("title")
        root.addWidget(hdr)

        # Stat cards
        cr = QHBoxLayout()
        self._c_devs  = StatCard("Connected Devices", "0")
        self._c_today = StatCard("Today's Punches",   "0")
        self._c_total = StatCard("Total Records",      "0")
        for c in (self._c_devs, self._c_today, self._c_total):
            cr.addWidget(c)
        root.addLayout(cr)

        # Splitter: live feed | devices table
        spl = QSplitter(Qt.Orientation.Horizontal)

        # Live feed
        feed_w = QWidget()
        fl = QVBoxLayout(feed_w)
        fl.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel("Live Punch Feed")
        lbl.setStyleSheet("font-weight:bold; color:#9090b0;")
        fl.addWidget(lbl)
        self._feed = QListWidget()
        fl.addWidget(self._feed)
        clr = QPushButton("Clear"); clr.setMaximumWidth(80)
        clr.clicked.connect(self._feed.clear)
        fl.addWidget(clr)
        spl.addWidget(feed_w)

        # Devices table
        dev_w = QWidget()
        dl = QVBoxLayout(dev_w)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addWidget(QLabel("Connected Devices"))
        self._dev_tbl = QTableWidget(0, 4)
        self._dev_tbl.setHorizontalHeaderLabels(["Idx", "MachineId", "Model", "Address"])
        self._dev_tbl.horizontalHeader().setStretchLastSection(True)
        self._dev_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        dl.addWidget(self._dev_tbl)
        spl.addWidget(dev_w)
        spl.setSizes([600, 350])
        root.addWidget(spl)

        # Log panel
        log_lbl = QLabel("SDK Log")
        log_lbl.setStyleSheet("font-weight:bold; color:#9090b0;")
        root.addWidget(log_lbl)
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(120)
        root.addWidget(self._log)

    def _refresh(self):
        self._c_today.set_value(self.db.today_count())
        self._c_total.set_value(self.db.total_count())

    def add_punch(self, uid, ts: datetime, rec_type, is_live):
        short, long_name = punch_short(rec_type)
        method = verify_str(rec_type)
        kind   = "LIVE " if is_live else "STORE"
        text   = f"[{kind}]  User {uid:>6}  {ts.strftime('%Y-%m-%d %H:%M:%S')}  {short} ({long_name}) [{method}]"
        item   = QListWidgetItem(text)
        item.setForeground(QColor("#4ae04a") if is_live else QColor("#a0c0e0"))
        self._feed.insertItem(0, item)
        if self._feed.count() > 300:
            self._feed.takeItem(self._feed.count() - 1)
        self._refresh()

    def add_log(self, msg: str):
        self._log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def update_device(self, dev_idx, machine_id, model, addr, online: bool):
        for row in range(self._dev_tbl.rowCount()):
            if self._dev_tbl.item(row, 0) and self._dev_tbl.item(row, 0).text() == str(dev_idx):
                if not online:
                    self._dev_tbl.removeRow(row)
                self._c_devs.set_value(self._dev_tbl.rowCount())
                return
        if online:
            r = self._dev_tbl.rowCount()
            self._dev_tbl.insertRow(r)
            self._dev_tbl.setItem(r, 0, QTableWidgetItem(str(dev_idx)))
            self._dev_tbl.setItem(r, 1, QTableWidgetItem(str(machine_id)))
            self._dev_tbl.setItem(r, 2, QTableWidgetItem(model))
            self._dev_tbl.setItem(r, 3, QTableWidgetItem(addr))
        self._c_devs.set_value(self._dev_tbl.rowCount())

# ─────────────────────────────────────────────────────────────────────────────
# Punch Log Panel
# ─────────────────────────────────────────────────────────────────────────────
class PunchLogPanel(QWidget):
    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(10)
        hdr = QLabel("Punch Log"); hdr.setObjectName("title")
        root.addWidget(hdr)

        # Filter bar
        fb = QHBoxLayout()
        fb.addWidget(QLabel("From:"))
        self._df = QDateEdit(QDate.currentDate().addDays(-7))
        self._df.setCalendarPopup(True); fb.addWidget(self._df)
        fb.addWidget(QLabel("To:"))
        self._dt = QDateEdit(QDate.currentDate())
        self._dt.setCalendarPopup(True); fb.addWidget(self._dt)
        fb.addWidget(QLabel("User ID:"))
        self._uid = QLineEdit(); self._uid.setPlaceholderText("All"); self._uid.setMaximumWidth(70)
        fb.addWidget(self._uid)
        fb.addWidget(QLabel("Type:"))
        self._tc = QComboBox()
        self._tc.addItems(["All","I","O","BO","BI","LO","LI"])
        fb.addWidget(self._tc)
        sb = QPushButton("Search"); sb.setObjectName("accent"); sb.clicked.connect(self._search)
        fb.addWidget(sb)
        eb = QPushButton("Export CSV"); eb.clicked.connect(self._export)
        fb.addWidget(eb)
        rb = QPushButton("Refresh"); rb.clicked.connect(self._search)
        fb.addWidget(rb)
        fb.addStretch()
        root.addLayout(fb)

        self._tbl = QTableWidget(0, 7)
        self._tbl.setHorizontalHeaderLabels(["User ID","Code","Description","Verify","Timestamp","Device","Source"])
        self._tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        root.addWidget(self._tbl)

        self._cnt = QLabel("0 records"); self._cnt.setObjectName("subtitle")
        root.addWidget(self._cnt)
        self._search()

    def _search(self):
        uid  = int(self._uid.text()) if self._uid.text().strip().isdigit() else None
        df   = self._df.date().toString("yyyy-MM-dd") + " 00:00:00"
        dt   = self._dt.date().toString("yyyy-MM-dd") + " 23:59:59"
        code = None if self._tc.currentText() == "All" else self._tc.currentText()
        rows = self.db.query(uid=uid, df=df, dt=dt, code=code)
        self._tbl.setRowCount(0)
        for r in rows:
            row = self._tbl.rowCount(); self._tbl.insertRow(row)
            for col, v in enumerate(r):
                self._tbl.setItem(row, col, QTableWidgetItem(str(v) if v is not None else ""))
        self._cnt.setText(f"{len(rows)} records")

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["UserID","Code","Description","Verify","Timestamp","Device","Source"])
            for row in range(self._tbl.rowCount()):
                w.writerow([self._tbl.item(row, c).text() if self._tbl.item(row, c) else "" for c in range(7)])
        QMessageBox.information(self, "Export Done", f"Saved to:\n{path}")

# ─────────────────────────────────────────────────────────────────────────────
# Users Panel
# ─────────────────────────────────────────────────────────────────────────────
class UsersPanel(QWidget):
    sig_load      = pyqtSignal(int)           # dev_idx
    sig_delete    = pyqtSignal(int, bytes)    # dev_idx, uid_bytes
    sig_transfer  = pyqtSignal(int, int, list)# src, dst, persons

    def __init__(self):
        super().__init__()
        self.devices = {}
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(10)
        hdr = QLabel("Users & Enrollment"); hdr.setObjectName("title")
        root.addWidget(hdr)

        tb = QHBoxLayout()
        tb.addWidget(QLabel("Device:"))
        self._dev = QComboBox(); self._dev.setMinimumWidth(220); tb.addWidget(self._dev)
        lb = QPushButton("Load Users"); lb.setObjectName("accent"); lb.clicked.connect(self._load)
        tb.addWidget(lb)
        db = QPushButton("Delete Selected"); db.setObjectName("danger"); db.clicked.connect(self._delete)
        tb.addWidget(db)
        xb = QPushButton("Transfer Selected →"); xb.clicked.connect(self._transfer)
        tb.addWidget(xb)
        tb.addStretch()
        self._sl = QLabel(""); self._sl.setObjectName("subtitle"); tb.addWidget(self._sl)
        root.addLayout(tb)

        self._prog = QProgressBar(); self._prog.setVisible(False)
        root.addWidget(self._prog)

        self._tbl = QTableWidget(0, 5)
        self._tbl.setHorizontalHeaderLabels(["User ID","Name","Card ID","FP Templates","Dept"])
        self._tbl.horizontalHeader().setStretchLastSection(True)
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        root.addWidget(self._tbl)

    def refresh_devices(self, devices: dict):
        self.devices = devices
        self._dev.clear()
        for idx, info in devices.items():
            self._dev.addItem(f"DevIdx={idx}  {info['model']}  {info['addr']}", idx)

    def _dev_idx(self):
        if self._dev.count() == 0:
            QMessageBox.warning(self, "No Device", "No device connected.")
            return None
        return self._dev.currentData()

    def _load(self):
        di = self._dev_idx()
        if di is None: return
        self._tbl.setRowCount(0)
        self._sl.setText("Loading...")
        self._prog.setVisible(True); self._prog.setRange(0, 0)
        self.sig_load.emit(di)

    def add_person(self, info: dict):
        r = self._tbl.rowCount(); self._tbl.insertRow(r)
        self._tbl.setItem(r, 0, QTableWidgetItem(str(info["uid"])))
        self._tbl.setItem(r, 1, QTableWidgetItem(info["name"]))
        self._tbl.setItem(r, 2, QTableWidgetItem(str(info["card_id"])))
        self._tbl.setItem(r, 3, QTableWidgetItem(str(info["fp_count"])))
        self._tbl.setItem(r, 4, QTableWidgetItem(str(info["dept"])))
        self._tbl.item(r, 0).setData(Qt.ItemDataRole.UserRole, info)
        if info.get("total"):
            self._prog.setRange(0, info["total"]); self._prog.setValue(info["cur"])
            if info["cur"] >= info["total"]:
                self._prog.setVisible(False)
                self._sl.setText(f"{info['total']} users loaded")

    def _delete(self):
        rows = sorted(set(i.row() for i in self._tbl.selectedItems()), reverse=True)
        if not rows:
            QMessageBox.information(self, "Delete", "Select users to delete."); return
        di = self._dev_idx()
        if di is None: return
        names = [self._tbl.item(r, 0).text() for r in rows]
        if QMessageBox.question(self, "Confirm Delete",
            f"Delete {len(rows)} user(s):\n{', '.join(names)}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        for row in rows:
            uid = int(self._tbl.item(row, 0).text())
            self.sig_delete.emit(di, int_to_emp(uid))

    def _transfer(self):
        rows = set(i.row() for i in self._tbl.selectedItems())
        if not rows:
            QMessageBox.information(self, "Transfer", "Select users first."); return
        src = self._dev_idx()
        targets = {k: v for k, v in self.devices.items() if k != src}
        if not targets:
            QMessageBox.warning(self, "Transfer", "Need at least 2 connected devices."); return
        dlg = QDialog(self); dlg.setWindowTitle("Select Target Device"); dlg.setMinimumWidth(300)
        vl = QVBoxLayout(dlg)
        cb = QComboBox()
        for idx, info in targets.items():
            cb.addItem(f"DevIdx={idx}  {info['model']}  {info['addr']}", idx)
        vl.addWidget(QLabel("Transfer selected users to:")); vl.addWidget(cb)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        vl.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted: return
        persons = [self._tbl.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in rows]
        self.sig_transfer.emit(src, cb.currentData(), persons)

    def mark_deleted(self, uid, ok):
        for row in range(self._tbl.rowCount()):
            item = self._tbl.item(row, 0)
            if item and item.text() == str(uid):
                if ok: self._tbl.removeRow(row)
                self._sl.setText(f"Delete user {uid}: {'OK' if ok else 'FAILED'}")
                break

# ─────────────────────────────────────────────────────────────────────────────
# Fingerprints Panel
# ─────────────────────────────────────────────────────────────────────────────
class FingerprintsPanel(QWidget):
    sig_start_dl = pyqtSignal(int, str)       # dev_idx, save_dir
    sig_dl_fp    = pyqtSignal(int, bytes, int) # dev_idx, uid_bytes, fi
    sig_ul_fp    = pyqtSignal(int, bytes, int, bytes, int) # dev_idx, uid_bytes, fi, data, len

    def __init__(self):
        super().__init__()
        self.devices   = {}
        self._save_dir = APP_DIR
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(10)
        hdr = QLabel("Fingerprint Templates"); hdr.setObjectName("title")
        root.addWidget(hdr)

        tabs = QTabWidget()

        # ── Download tab ──────────────────────────────────────────────
        dl_w = QWidget(); dl = QVBoxLayout(dl_w)
        r1 = QHBoxLayout()
        self._dl_dev = QComboBox(); r1.addWidget(QLabel("Source Device:")); r1.addWidget(self._dl_dev); r1.addStretch()
        dl.addLayout(r1)
        r2 = QHBoxLayout()
        self._dl_dir = QLineEdit(APP_DIR)
        r2.addWidget(QLabel("Save to Folder:")); r2.addWidget(self._dl_dir)
        bb = QPushButton("Browse..."); bb.clicked.connect(self._browse_save); r2.addWidget(bb)
        dl.addLayout(r2)
        self._dl_note = QLabel("Note: click 'Load Users' in the Users panel first, then click Download All.")
        self._dl_note.setObjectName("subtitle"); dl.addWidget(self._dl_note)
        self._dl_prog = QProgressBar(); dl.addWidget(self._dl_prog)
        self._dl_stat = QLabel("Ready"); self._dl_stat.setObjectName("subtitle"); dl.addWidget(self._dl_stat)
        db2 = QPushButton("Download All Fingerprints"); db2.setObjectName("accent")
        db2.clicked.connect(self._start_dl); dl.addWidget(db2)
        dl.addStretch(); tabs.addTab(dl_w, "Download")

        # ── Upload tab ────────────────────────────────────────────────
        ul_w = QWidget(); ul = QVBoxLayout(ul_w)
        r3 = QHBoxLayout()
        self._ul_dev = QComboBox(); r3.addWidget(QLabel("Target Device:")); r3.addWidget(self._ul_dev); r3.addStretch()
        ul.addLayout(r3)
        r4 = QHBoxLayout()
        self._ul_dir = QLineEdit(APP_DIR)
        r4.addWidget(QLabel("Load from Folder:")); r4.addWidget(self._ul_dir)
        bb2 = QPushButton("Browse..."); bb2.clicked.connect(self._browse_load); r4.addWidget(bb2)
        ul.addLayout(r4)
        ul.addWidget(QLabel("Files must be named:  <UserID>_finger<0-9>.fp"))
        self._ul_prog = QProgressBar(); ul.addWidget(self._ul_prog)
        self._ul_stat = QLabel("Ready"); self._ul_stat.setObjectName("subtitle"); ul.addWidget(self._ul_stat)
        ub = QPushButton("Upload All Fingerprints from Folder"); ub.setObjectName("accent")
        ub.clicked.connect(self._start_ul); ul.addWidget(ub)
        ul.addStretch(); tabs.addTab(ul_w, "Upload")

        root.addWidget(tabs)

    def refresh_devices(self, devices: dict):
        self.devices = devices
        for combo in (self._dl_dev, self._ul_dev):
            combo.clear()
            for idx, info in devices.items():
                combo.addItem(f"DevIdx={idx}  {info['model']}  {info['addr']}", idx)

    def _browse_save(self):
        d = QFileDialog.getExistingDirectory(self, "Select Save Folder", self._dl_dir.text())
        if d: self._dl_dir.setText(d)

    def _browse_load(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder with .fp Files", self._ul_dir.text())
        if d: self._ul_dir.setText(d)

    def _start_dl(self):
        if self._dl_dev.count() == 0:
            QMessageBox.warning(self, "No Device", "No device connected."); return
        di = self._dl_dev.currentData()
        save_dir = self._dl_dir.text()
        os.makedirs(save_dir, exist_ok=True)
        self._save_dir = save_dir
        self._dl_stat.setText("Requesting user list — fingerprints will auto-download per user...")
        self.sig_start_dl.emit(di, save_dir)

    def _start_ul(self):
        if self._ul_dev.count() == 0:
            QMessageBox.warning(self, "No Device", "No device connected."); return
        di   = self._ul_dev.currentData()
        folder = self._ul_dir.text()
        files  = [f for f in os.listdir(folder) if f.endswith(".fp")]
        if not files:
            QMessageBox.warning(self, "No Files", "No .fp files found."); return
        self._ul_prog.setRange(0, len(files)); self._ul_prog.setValue(0)
        done = 0
        for fn in files:
            try:
                parts = fn.replace(".fp", "").split("_finger")
                uid = int(parts[0]); fi = int(parts[1])
                with open(os.path.join(folder, fn), "rb") as f:
                    data = f.read()
                self.sig_ul_fp.emit(di, int_to_emp(uid), fi, data, len(data))
                done += 1; self._ul_prog.setValue(done)
                self._ul_stat.setText(f"Queued {done}/{len(files)}: {fn}")
            except Exception as e:
                self._ul_stat.setText(f"Skip {fn}: {e}")

    def save_fp(self, uid, fi, data: bytes):
        if not data: return
        path = os.path.join(self._save_dir, f"{uid}_finger{fi}.fp")
        with open(path, "wb") as f:
            f.write(data)
        self._dl_stat.setText(f"Saved {uid}_finger{fi}.fp  ({len(data)} bytes)")

    def trigger_user_fp(self, di, uid, fp_status):
        """Called for each user after user list loads — queues per-finger download."""
        uid_bytes = int_to_emp(uid)
        for fi in range(10):
            if fp_status & (1 << fi):
                self.sig_dl_fp.emit(di, uid_bytes, fi)

# ─────────────────────────────────────────────────────────────────────────────
# Network Panel
# ─────────────────────────────────────────────────────────────────────────────
class NetworkPanel(QWidget):
    sig_scan    = pyqtSignal()
    sig_get_net = pyqtSignal(int)
    sig_set_net = pyqtSignal(int, object)

    def __init__(self):
        super().__init__()
        self.devices = {}
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(10)
        hdr = QLabel("Network Management"); hdr.setObjectName("title")
        root.addWidget(hdr)

        tb = QHBoxLayout()
        sb = QPushButton("Scan Network  (UDP Broadcast)"); sb.setObjectName("accent")
        sb.clicked.connect(self.sig_scan.emit); tb.addWidget(sb)
        tb.addSpacing(20)
        tb.addWidget(QLabel("Connected Device:"))
        self._dev = QComboBox(); self._dev.setMinimumWidth(220); tb.addWidget(self._dev)
        rb = QPushButton("Read Network Config"); rb.clicked.connect(self._read)
        tb.addWidget(rb); tb.addStretch()
        root.addLayout(tb)

        # UDP scan results
        sg = QGroupBox("Devices Found on Network  (UDP scan)")
        sl = QVBoxLayout(sg)
        self._scan = QTableWidget(0, 9)
        self._scan.setHorizontalHeaderLabels(["MachineId","Model","Serial","IP","Mask","Gateway","ServIP","Port","Mode"])
        self._scan.horizontalHeader().setStretchLastSection(True)
        self._scan.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._scan.setMaximumHeight(160)
        sl.addWidget(self._scan)
        root.addWidget(sg)

        # Config edit form
        cg = QGroupBox("Edit Network Configuration  (select connected device above)")
        cf = QFormLayout(cg)
        self._ip   = QLineEdit(); cf.addRow("Device IP:",    self._ip)
        self._mask = QLineEdit(); cf.addRow("Subnet Mask:",  self._mask)
        self._gw   = QLineEdit(); cf.addRow("Gateway:",      self._gw)
        self._srv  = QLineEdit(); cf.addRow("Server IP:",    self._srv)
        self._port = QLineEdit(); cf.addRow("Port:",         self._port)
        self._mode = QComboBox()
        self._mode.addItems(["0 — Client (device connects to server)",
                             "1 — Server (device acts as server)"])
        cf.addRow("Network Mode:", self._mode)
        apply_b = QPushButton("Apply Changes to Device"); apply_b.setObjectName("accent")
        apply_b.clicked.connect(self._apply); cf.addRow("", apply_b)
        root.addWidget(cg)
        root.addStretch()

    def refresh_devices(self, devices: dict):
        self.devices = devices
        self._dev.clear()
        for idx, info in devices.items():
            self._dev.addItem(f"DevIdx={idx}  {info['model']}  {info['addr']}", idx)

    def _read(self):
        if self._dev.count() == 0:
            QMessageBox.warning(self, "No Device", "No connected device."); return
        self.sig_get_net.emit(self._dev.currentData())

    def populate(self, cfg: NetCfgInfo):
        self._ip.setText(ip_str(cfg.IpAddr))
        self._mask.setText(ip_str(cfg.IpMask))
        self._gw.setText(ip_str(cfg.GwAddr))
        self._srv.setText(ip_str(cfg.ServAddr))
        self._port.setText(str(port_int(cfg.Port)))
        self._mode.setCurrentIndex(min(cfg.Mode, 1))

    def _apply(self):
        if self._dev.count() == 0: return
        di = self._dev.currentData()
        cfg = NetCfgInfo()
        try:
            for i, v in enumerate(ip_bytes(self._ip.text())):   cfg.IpAddr[i]   = v
            for i, v in enumerate(ip_bytes(self._mask.text())): cfg.IpMask[i]   = v
            for i, v in enumerate(ip_bytes(self._gw.text())):   cfg.GwAddr[i]   = v
            for i, v in enumerate(ip_bytes(self._srv.text())):  cfg.ServAddr[i] = v
            for i, v in enumerate(port_bytes(int(self._port.text()))): cfg.Port[i] = v
            cfg.Mode = self._mode.currentIndex()
        except Exception as e:
            QMessageBox.warning(self, "Invalid Input", str(e)); return
        if QMessageBox.question(self, "Confirm",
            "Apply these network settings to the device?\n"
            "The device will need to reconnect afterwards.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.sig_set_net.emit(di, cfg)

    def show_scan(self, devs: list):
        self._scan.setRowCount(0)
        for d in devs:
            r = self._scan.rowCount(); self._scan.insertRow(r)
            for ci, key in enumerate(["machine_id","model","serial","ip","mask","gateway","serv","port","mode"]):
                self._scan.setItem(r, ci, QTableWidgetItem(str(d.get(key, ""))))

# ─────────────────────────────────────────────────────────────────────────────
# Settings Panel
# ─────────────────────────────────────────────────────────────────────────────
class SettingsPanel(QWidget):
    sig_saved = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setSpacing(14)
        hdr = QLabel("Settings"); hdr.setObjectName("title")
        root.addWidget(hdr)

        # Connection group
        cg = QGroupBox("Connection")
        cf = QFormLayout(cg)
        self._mode = QComboBox()
        self._mode.addItem("Client Mode  —  SDK connects TO the device  (device is Server)", "client")
        self._mode.addItem("Server Mode  —  device connects TO this PC  (SDK is Server)", "server")
        self._mode.currentIndexChanged.connect(self._mode_changed)
        cf.addRow("Connection Mode:", self._mode)
        self._ip   = QLineEdit("192.168.1.218"); cf.addRow("Device IP  (Client):", self._ip)
        self._port = QSpinBox(); self._port.setRange(1, 65535); self._port.setValue(5010)
        cf.addRow("Device Port  (Client):", self._port)
        self._srv_port = QSpinBox(); self._srv_port.setRange(1, 65535); self._srv_port.setValue(5010)
        cf.addRow("SDK Listen Port  (Server):", self._srv_port)
        root.addWidget(cg)

        # Log folder group
        lg = QGroupBox("Log File Storage")
        lf = QFormLayout(lg)
        lr = QHBoxLayout()
        self._log_dir = QLineEdit(APP_DIR); lr.addWidget(self._log_dir)
        bb = QPushButton("Browse..."); bb.clicked.connect(self._browse); lr.addWidget(bb)
        lf.addRow("Log Folder:", lr)
        lf.addRow("", QLabel("Supports local paths and mapped network drives (e.g. Z:\\Attendance)"))
        root.addWidget(lg)

        # Dedup group
        dg = QGroupBox("Duplicate Punch Filter")
        df = QFormLayout(dg)
        self._dedup = QSpinBox(); self._dedup.setRange(0, 3600); self._dedup.setValue(60)
        self._dedup.setSuffix(" seconds")
        df.addRow("Ignore same UserID + same punch type within:", self._dedup)
        df.addRow("", QLabel("Set to 0 to disable."))
        root.addWidget(dg)

        save_b = QPushButton("Save Settings  (connection changes require restart)")
        save_b.setObjectName("accent"); save_b.clicked.connect(self._save)
        root.addWidget(save_b)
        root.addStretch()

    def _mode_changed(self, _):
        is_c = self._mode.currentData() == "client"
        self._ip.setEnabled(is_c); self._port.setEnabled(is_c)
        self._srv_port.setEnabled(not is_c)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Log Folder", self._log_dir.text())
        if d: self._log_dir.setText(d)

    def load(self, cfg: dict):
        self._mode.setCurrentIndex(0 if cfg.get("conn_mode","client") == "client" else 1)
        self._ip.setText(cfg.get("device_ip", "192.168.1.218"))
        self._port.setValue(cfg.get("device_port", 5010))
        self._srv_port.setValue(cfg.get("server_port", 5010))
        self._log_dir.setText(cfg.get("log_dir", APP_DIR))
        self._dedup.setValue(cfg.get("dedup_seconds", 60))
        self._mode_changed(0)

    def _save(self):
        cfg = {
            "conn_mode":     self._mode.currentData(),
            "device_ip":     self._ip.text(),
            "device_port":   self._port.value(),
            "server_port":   self._srv_port.value(),
            "log_dir":       self._log_dir.text(),
            "dedup_seconds": self._dedup.value(),
        }
        save_cfg(cfg)
        self.sig_saved.emit(cfg)
        QMessageBox.information(self, "Saved",
            "Settings saved.\nRestart InterXDB_FFServer to apply connection changes.")

# ─────────────────────────────────────────────────────────────────────────────
# Add / Edit User Dialog
# ─────────────────────────────────────────────────────────────────────────────
class AddEditUserDialog(QDialog):
    """Dialog for adding a new or editing an existing ac_users record."""

    def __init__(self, parent=None, row: dict = None):
        super().__init__(parent)
        self._editing = row is not None
        self.setWindowTitle("Edit Person" if self._editing else "Add Person")
        self.setMinimumWidth(380)
        self._build(row or {})

    def _build(self, row: dict):
        vl = QVBoxLayout(self)
        vl.setSpacing(10)

        # ── Main row: form left, photo right ──────────────────────────
        main_row = QHBoxLayout()

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # User ID — read-only when editing (it's the primary key)
        self._uid = QSpinBox()
        self._uid.setRange(1, 9999999)
        self._uid.setValue(int(row.get("user_id", 1)))
        self._uid.setEnabled(not self._editing)   # lock PK on edit
        form.addRow("User ID:", self._uid)

        self._fname = QLineEdit(row.get("first_name", ""))
        self._fname.setPlaceholderText("First name")
        form.addRow("First Name:", self._fname)

        self._lname = QLineEdit(row.get("last_name", ""))
        self._lname.setPlaceholderText("Last name")
        form.addRow("Last Name:", self._lname)

        self._org = QLineEdit(row.get("org_name", ""))
        self._org.setPlaceholderText("Company / organisation")
        form.addRow("Organisation:", self._org)

        self._dept = QLineEdit(row.get("department", ""))
        self._dept.setPlaceholderText("Department")
        form.addRow("Department:", self._dept)

        # Photo path row
        photo_row = QHBoxLayout()
        self._photo_path = QLineEdit(row.get("photo_path", ""))
        self._photo_path.setPlaceholderText("No photo selected")
        self._photo_path.setReadOnly(True)
        photo_row.addWidget(self._photo_path)
        browse_b = QPushButton("Browse...")
        browse_b.setMaximumWidth(80)
        browse_b.clicked.connect(self._browse_photo)
        photo_row.addWidget(browse_b)
        clr_b = QPushButton("Clear")
        clr_b.setMaximumWidth(55)
        clr_b.clicked.connect(self._clear_photo)
        photo_row.addWidget(clr_b)
        form.addRow("Photo:", photo_row)

        main_row.addLayout(form, stretch=2)

        # Photo preview panel (right side)
        self._preview = QLabel()
        self._preview.setFixedSize(110, 130)
        self._preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._preview.setStyleSheet(
            "background:#2a2a4a; border:1px solid #3a3a5a; border-radius:4px; color:#506070;"
        )
        self._preview.setText("No\nPhoto")
        self._preview.setWordWrap(True)
        main_row.addWidget(self._preview, stretch=0,
                           alignment=Qt.AlignmentFlag.AlignTop)

        vl.addLayout(main_row)

        # Load existing photo preview if editing
        if row.get("photo_path"):
            self._update_preview(row["photo_path"])

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        vl.addWidget(btns)

    def _browse_photo(self):
        """Open file dialog to select a photo, then copy it to ac_photos folder."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Photo", "",
            "Images (*.jpg *.jpeg *.png *.bmp *.gif)"
        )
        if not path:
            return
        # Copy photo into APP_DIR/ac_photos/ so it stays alongside the DB
        import shutil
        photos_dir = os.path.join(APP_DIR, "ac_photos")
        os.makedirs(photos_dir, exist_ok=True)
        dest = os.path.join(photos_dir, os.path.basename(path))
        try:
            shutil.copy2(path, dest)
        except Exception:
            dest = path   # Fall back to original path if copy fails
        self._photo_path.setText(dest)
        self._update_preview(dest)

    def _clear_photo(self):
        """Remove the selected photo."""
        self._photo_path.setText("")
        self._preview.setPixmap(QPixmap())
        self._preview.setText("No\nPhoto")

    def _update_preview(self, path: str):
        """Show a scaled thumbnail in the preview label."""
        if path and os.path.isfile(path):
            pix = QPixmap(path).scaled(
                108, 128,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self._preview.setPixmap(pix)
            self._preview.setText("")
        else:
            self._preview.setPixmap(QPixmap())
            self._preview.setText("No\nPhoto")

    def _accept(self):
        """Validate before accepting."""
        if not self._fname.text().strip() and not self._lname.text().strip():
            QMessageBox.warning(self, "Missing Name",
                                "Please enter at least a first or last name.")
            return
        self.accept()

    def get_values(self) -> dict:
        """Return the entered values as a dict."""
        return {
            "user_id":    self._uid.value(),
            "first_name": self._fname.text().strip(),
            "last_name":  self._lname.text().strip(),
            "org_name":   self._org.text().strip(),
            "department": self._dept.text().strip(),
            "photo_path": self._photo_path.text().strip(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Manage Users Panel  (ac_users table — person directory for SmartBuild)
# ─────────────────────────────────────────────────────────────────────────────
class ManageUsersPanel(QWidget):
    """
    CRUD panel for the ac_users table.
    This is the person directory that SmartBuild reads (read-only) for
    Access Control — matching punch user_ids to real names/departments.
    """

    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self._build()
        self._load()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(10)

        hdr = QLabel("Manage Users  (Access Control Directory)")
        hdr.setObjectName("title")
        root.addWidget(hdr)

        note = QLabel(
            "This directory links User IDs (from the fingerprint reader) to person details.\n"
            "SmartBuild reads this data in read-only mode for its Access Control panel."
        )
        note.setObjectName("subtitle")
        note.setWordWrap(True)
        root.addWidget(note)

        # Toolbar
        tb = QHBoxLayout()
        add_b = QPushButton("Add Person"); add_b.setObjectName("accent")
        add_b.clicked.connect(self._add)
        tb.addWidget(add_b)

        edit_b = QPushButton("Edit Selected"); edit_b.clicked.connect(self._edit)
        tb.addWidget(edit_b)

        del_b = QPushButton("Delete Selected"); del_b.setObjectName("danger")
        del_b.clicked.connect(self._delete)
        tb.addWidget(del_b)

        tb.addStretch()

        ref_b = QPushButton("Refresh"); ref_b.clicked.connect(self._load)
        tb.addWidget(ref_b)

        self._cnt = QLabel("0 persons")
        self._cnt.setObjectName("subtitle")
        tb.addWidget(self._cnt)

        root.addLayout(tb)

        # Table
        self._tbl = QTableWidget(0, 6)
        self._tbl.setHorizontalHeaderLabels(
            ["User ID", "First Name", "Last Name", "Organisation", "Department", "Photo"]
        )
        self._tbl.horizontalHeader().setStretchLastSection(False)
        self._tbl.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._tbl.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.ResizeToContents
        )
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tbl.doubleClicked.connect(self._edit)
        root.addWidget(self._tbl)

    def _load(self):
        """Reload all rows from ac_users."""
        rows = self.db.ac_get_all()
        self._tbl.setRowCount(0)
        self._tbl.setRowHeight(0, 48)
        for r in rows:
            row = self._tbl.rowCount()
            self._tbl.insertRow(row)
            self._tbl.setRowHeight(row, 48)
            self._tbl.setItem(row, 0, QTableWidgetItem(str(r["user_id"])))
            self._tbl.setItem(row, 1, QTableWidgetItem(r["first_name"]))
            self._tbl.setItem(row, 2, QTableWidgetItem(r["last_name"]))
            self._tbl.setItem(row, 3, QTableWidgetItem(r["org_name"]))
            self._tbl.setItem(row, 4, QTableWidgetItem(r["department"]))

            # Photo thumbnail cell
            photo = r.get("photo_path", "")
            if photo and os.path.isfile(photo):
                pix = QPixmap(photo).scaled(
                    36, 44,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                lbl = QLabel()
                lbl.setPixmap(pix)
                lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self._tbl.setCellWidget(row, 5, lbl)
                self._tbl.setItem(row, 5, QTableWidgetItem(""))   # for selection
            else:
                self._tbl.setItem(row, 5, QTableWidgetItem("—"))

            # Store original row dict for edit dialog pre-fill
            self._tbl.item(row, 0).setData(Qt.ItemDataRole.UserRole, r)
        self._cnt.setText(f"{len(rows)} person{'s' if len(rows) != 1 else ''}")

    def _selected_row(self) -> int:
        """Return the currently selected table row index, or -1."""
        rows = list(set(i.row() for i in self._tbl.selectedItems()))
        return rows[0] if len(rows) == 1 else -1

    def _add(self):
        dlg = AddEditUserDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.get_values()
        try:
            self.db.ac_upsert(
                v["user_id"], v["first_name"], v["last_name"],
                v["org_name"], v["department"], v["photo_path"]
            )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save:\n{e}")
            return
        self._load()

    def _edit(self):
        row = self._selected_row()
        if row < 0:
            QMessageBox.information(self, "Edit", "Select a single row to edit.")
            return
        data = self._tbl.item(row, 0).data(Qt.ItemDataRole.UserRole)
        dlg  = AddEditUserDialog(self, row=data)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.get_values()
        try:
            self.db.ac_upsert(
                v["user_id"], v["first_name"], v["last_name"],
                v["org_name"], v["department"], v["photo_path"]
            )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save:\n{e}")
            return
        self._load()

    def _delete(self):
        rows = sorted(set(i.row() for i in self._tbl.selectedItems()), reverse=True)
        if not rows:
            QMessageBox.information(self, "Delete", "Select rows to delete.")
            return
        names = []
        for r in rows:
            fn = self._tbl.item(r, 1).text()
            ln = self._tbl.item(r, 2).text()
            names.append(f"{fn} {ln}".strip() or self._tbl.item(r, 0).text())
        if QMessageBox.question(
            self, "Confirm Delete",
            f"Delete {len(rows)} person(s)?\n" + "\n".join(names),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        for r in rows:
            uid = int(self._tbl.item(r, 0).text())
            self.db.ac_delete(uid)
        self._load()


# ─────────────────────────────────────────────────────────────────────────────
# Backup & Restore Panel
# ─────────────────────────────────────────────────────────────────────────────
class BackupRestorePanel(QWidget):
    """
    Backup and restore the full InterXDB dataset:
      - interxdb.db  (all punches + ac_users person directory)
      - ac_photos/   (person ID photos)
      - fingerprints/ (all .fp fingerprint template files)

    Backup is saved as a single ZIP:
      InterXDB_Backup_YYYY-MM-DD_HHMMSS.zip

    Supports local drives and mapped network drives.
    'Scan for Backups' searches all available drives + common folders
    for existing backup ZIPs and lists them for one-click restore.
    """

    BACKUP_PREFIX = "InterXDB_Backup_"

    def __init__(self, db: Database):
        super().__init__()
        self.db = db
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)

        hdr = QLabel("Backup && Restore")
        hdr.setObjectName("title")
        root.addWidget(hdr)

        note = QLabel(
            "Backup includes: database (punches + person directory), "
            "ID photos, and fingerprint templates.\n"
            "Backups are saved as a single ZIP file."
        )
        note.setObjectName("subtitle")
        note.setWordWrap(True)
        root.addWidget(note)

        # ── Backup group ──────────────────────────────────────────────
        bg = QGroupBox("Create Backup")
        bf = QVBoxLayout(bg)

        dest_row = QHBoxLayout()
        dest_row.addWidget(QLabel("Save to:"))
        self._dest = QLineEdit()
        self._dest.setPlaceholderText("Select destination folder...")
        dest_row.addWidget(self._dest)
        dest_browse = QPushButton("Browse...")
        dest_browse.setMaximumWidth(80)
        dest_browse.clicked.connect(self._browse_dest)
        dest_row.addWidget(dest_browse)
        bf.addLayout(dest_row)

        backup_btn = QPushButton("  Create Backup Now")
        backup_btn.setObjectName("accent")
        backup_btn.setFixedHeight(36)
        backup_btn.clicked.connect(self._do_backup)
        bf.addWidget(backup_btn)

        self._backup_status = QLabel("")
        self._backup_status.setObjectName("subtitle")
        self._backup_status.setWordWrap(True)
        bf.addWidget(self._backup_status)
        root.addWidget(bg)

        # ── Restore group ─────────────────────────────────────────────
        rg = QGroupBox("Restore from Backup")
        rf = QVBoxLayout(rg)

        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("Backup file:"))
        self._src = QLineEdit()
        self._src.setPlaceholderText("Select a backup ZIP file or double-click from scan below...")
        src_row.addWidget(self._src)
        src_browse = QPushButton("Browse...")
        src_browse.setMaximumWidth(80)
        src_browse.clicked.connect(self._browse_src)
        src_row.addWidget(src_browse)
        rf.addLayout(src_row)

        restore_btn = QPushButton("  Restore Selected Backup")
        restore_btn.setObjectName("danger")
        restore_btn.setFixedHeight(36)
        restore_btn.clicked.connect(self._do_restore)
        rf.addWidget(restore_btn)

        self._restore_status = QLabel("")
        self._restore_status.setObjectName("subtitle")
        self._restore_status.setWordWrap(True)
        rf.addWidget(self._restore_status)
        root.addWidget(rg)

        # ── Recent backups scanner ────────────────────────────────────
        sg = QGroupBox("Recent Backups Found on This PC")
        sl = QVBoxLayout(sg)

        scan_row = QHBoxLayout()
        scan_btn = QPushButton("Scan for Backups")
        scan_btn.setObjectName("accent")
        scan_btn.clicked.connect(self._scan_backups)
        scan_row.addWidget(scan_btn)
        self._scan_status = QLabel("Click 'Scan' to search all drives for backup files.")
        self._scan_status.setObjectName("subtitle")
        scan_row.addWidget(self._scan_status)
        scan_row.addStretch()
        sl.addLayout(scan_row)

        self._scan_tbl = QTableWidget(0, 3)
        self._scan_tbl.setHorizontalHeaderLabels(["Backup File", "Size", "Location"])
        self._scan_tbl.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self._scan_tbl.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self._scan_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._scan_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._scan_tbl.setMaximumHeight(180)
        self._scan_tbl.doubleClicked.connect(self._use_scanned)
        sl.addWidget(QLabel("Double-click a row to load it into the Restore field above."))
        sl.addWidget(self._scan_tbl)
        root.addWidget(sg)

        root.addStretch()

    # ── Backup ────────────────────────────────────────────────────────

    def _browse_dest(self):
        d = QFileDialog.getExistingDirectory(self, "Select Backup Destination")
        if d:
            self._dest.setText(d)

    def _do_backup(self):
        import zipfile

        dest_dir = self._dest.text().strip()
        if not dest_dir:
            QMessageBox.warning(self, "No Destination",
                                "Please select a destination folder first.")
            return
        if not os.path.isdir(dest_dir):
            QMessageBox.warning(self, "Invalid Folder",
                                f"Folder not found:\n{dest_dir}")
            return

        ts       = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        zip_name = f"{self.BACKUP_PREFIX}{ts}.zip"
        zip_path = os.path.join(dest_dir, zip_name)

        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:

                # 1. Database
                if os.path.isfile(self.db.path):
                    zf.write(self.db.path, "interxdb.db")

                # 2. ID photos
                photos_dir = os.path.join(APP_DIR, "ac_photos")
                if os.path.isdir(photos_dir):
                    for fn in os.listdir(photos_dir):
                        fp = os.path.join(photos_dir, fn)
                        if os.path.isfile(fp):
                            zf.write(fp, os.path.join("ac_photos", fn))

                # 3. Fingerprint templates — APP_DIR root .fp files
                #    and fingerprints/ subfolder if it exists
                fp_sub = os.path.join(APP_DIR, "fingerprints")
                for search_dir in [APP_DIR] + ([fp_sub] if os.path.isdir(fp_sub) else []):
                    for fn in os.listdir(search_dir):
                        if fn.endswith(".fp"):
                            full = os.path.join(search_dir, fn)
                            zf.write(full, os.path.join("fingerprints", fn))

            size_kb = os.path.getsize(zip_path) // 1024
            self._backup_status.setStyleSheet("color:#4caf50;")
            self._backup_status.setText(
                f"Backup created  ({size_kb} KB):\n{zip_path}"
            )

        except Exception as e:
            self._backup_status.setStyleSheet("color:#f44336;")
            self._backup_status.setText(f"Backup failed: {e}")

    # ── Restore ───────────────────────────────────────────────────────

    def _browse_src(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Backup ZIP", "",
            "InterXDB Backup (*.zip);;All Files (*)"
        )
        if path:
            self._src.setText(path)

    def _do_restore(self):
        import zipfile, shutil as _sh

        zip_path = self._src.text().strip()
        if not zip_path or not os.path.isfile(zip_path):
            QMessageBox.warning(self, "No File",
                                "Please select a valid backup ZIP file.")
            return

        if QMessageBox.question(
            self, "Confirm Restore",
            "Restoring will REPLACE the current database, photos, and "
            "fingerprint files with the backup contents.\n\n"
            "A safety copy of the current database will be saved first.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        try:
            # Safety backup of current DB before overwriting
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
            bak = self.db.path + f".pre_restore_{ts}.bak"
            if os.path.isfile(self.db.path):
                _sh.copy2(self.db.path, bak)

            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()

                # Restore database
                if "interxdb.db" in names:
                    with zf.open("interxdb.db") as src:
                        with open(self.db.path, "wb") as dst:
                            dst.write(src.read())

                # Restore ID photos
                photo_files = [n for n in names if n.startswith("ac_photos/")]
                if photo_files:
                    photos_dir = os.path.join(APP_DIR, "ac_photos")
                    os.makedirs(photos_dir, exist_ok=True)
                    for name in photo_files:
                        fn = os.path.basename(name)
                        if fn:
                            with zf.open(name) as src:
                                with open(os.path.join(photos_dir, fn), "wb") as dst:
                                    dst.write(src.read())

                # Restore fingerprint templates
                fp_files = [n for n in names if n.startswith("fingerprints/")]
                if fp_files:
                    fp_dir = os.path.join(APP_DIR, "fingerprints")
                    os.makedirs(fp_dir, exist_ok=True)
                    for name in fp_files:
                        fn = os.path.basename(name)
                        if fn:
                            with zf.open(name) as src:
                                with open(os.path.join(fp_dir, fn), "wb") as dst:
                                    dst.write(src.read())

            # Re-run DB setup so any new schema additions are applied
            self.db._setup()

            self._restore_status.setStyleSheet("color:#4caf50;")
            self._restore_status.setText(
                "Restore complete. Please restart InterXDB_FFServer to reload all data.\n"
                f"Safety backup: {os.path.basename(bak)}"
            )

        except Exception as e:
            self._restore_status.setStyleSheet("color:#f44336;")
            self._restore_status.setText(f"Restore failed: {e}")

    # ── Scanner ───────────────────────────────────────────────────────

    def _scan_backups(self):
        """Search all available drives + common user folders for backup ZIPs."""
        import string

        self._scan_tbl.setRowCount(0)
        self._scan_status.setText("Scanning...")
        QApplication.processEvents()

        search_dirs = []

        # Every drive letter — covers local SSDs, USB drives, mapped network drives
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                search_dirs.append(drive)
                # One level deep on each drive
                try:
                    for sub in os.listdir(drive):
                        full = os.path.join(drive, sub)
                        if os.path.isdir(full):
                            search_dirs.append(full)
                except (PermissionError, OSError):
                    pass

        # Common user folders
        home = os.path.expanduser("~")
        for folder in ("Desktop", "Documents", "Downloads", "Backup", "Backups"):
            p = os.path.join(home, folder)
            if os.path.isdir(p):
                search_dirs.append(p)

        # APP_DIR itself
        search_dirs.append(APP_DIR)

        found = []
        seen  = set()
        for d in search_dirs:
            try:
                for fn in os.listdir(d):
                    if fn.startswith(self.BACKUP_PREFIX) and fn.endswith(".zip"):
                        full = os.path.join(d, fn)
                        if full not in seen and os.path.isfile(full):
                            seen.add(full)
                            found.append(full)
            except (PermissionError, OSError):
                pass

        # Sort newest first (timestamp is in the filename)
        found.sort(reverse=True)

        for path in found:
            row = self._scan_tbl.rowCount()
            self._scan_tbl.insertRow(row)
            fn      = os.path.basename(path)
            size_kb = os.path.getsize(path) // 1024
            self._scan_tbl.setItem(row, 0, QTableWidgetItem(fn))
            self._scan_tbl.setItem(row, 1, QTableWidgetItem(f"{size_kb} KB"))
            self._scan_tbl.setItem(row, 2, QTableWidgetItem(os.path.dirname(path)))
            # Store full path for double-click
            self._scan_tbl.item(row, 0).setData(Qt.ItemDataRole.UserRole, path)

        count = len(found)
        self._scan_status.setText(
            f"{count} backup{'s' if count != 1 else ''} found."
        )

    def _use_scanned(self):
        """Double-click: load selected scan result into the Restore field."""
        row = self._scan_tbl.currentRow()
        if row < 0:
            return
        path = self._scan_tbl.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if path:
            self._src.setText(path)
            self._restore_status.setStyleSheet("color:#4a9eff;")
            self._restore_status.setText(
                "Backup loaded — click 'Restore Selected Backup' to proceed."
            )


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg    = load_cfg()
        self.sdk    = AnvizSDK()
        self.db     = Database()
        self.poller = None
        self._dedup = {}          # (uid, code) -> datetime
        self._fp_dl_dev  = -1    # dev_idx active for FP download, -1 = inactive
        self._fp_dl_dir  = APP_DIR
        self._log_path   = ""
        self._init_log()
        self._build()
        self._start_sdk()

    # ── Log file ─────────────────────────────────────────────────────────────
    def _init_log(self):
        ip  = self.cfg.get("device_ip", "192.168.1.218")
        ld  = self.cfg.get("log_dir", APP_DIR)
        os.makedirs(ld, exist_ok=True)
        self._log_path = os.path.join(ld, f"Punchtypes format {ip}.log")
        if not os.path.isfile(self._log_path):
            with open(self._log_path, "w") as f:
                f.write("C,GetAllLogs,SUCCESSFUL\n")

    def _write_log(self, uid, ts: datetime, rec_type):
        short, _ = punch_short(rec_type)
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(f'{uid},{short},"{ts.strftime("%Y-%m-%d %H:%M:%S")}",0,0\n')

    def _is_dup(self, uid, rec_type, ts: datetime) -> bool:
        window = self.cfg.get("dedup_seconds", 60)
        if window == 0: return False
        short, _ = punch_short(rec_type)
        key = (uid, short)
        last = self._dedup.get(key)
        if last and abs((ts - last).total_seconds()) < window:
            return True
        self._dedup[key] = ts
        return False

    # ── UI ───────────────────────────────────────────────────────────────────
    def _build(self):
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.setMinimumSize(1150, 740)
        # Window/taskbar icon — ICO only, no JPG fallback
        if os.path.isfile(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        central = QWidget()
        self.setCentralWidget(central)
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0); row.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────
        sidebar = QWidget(); sidebar.setObjectName("sidebar"); sidebar.setFixedWidth(205)
        sl = QVBoxLayout(sidebar); sl.setContentsMargins(0, 0, 0, 0); sl.setSpacing(0)

        # Logo
        logo_frame = QWidget(); logo_frame.setStyleSheet("background:#090914;")
        ll = QVBoxLayout(logo_frame); ll.setContentsMargins(10, 14, 10, 10)
        if os.path.isfile(LOGO_PATH):
            pix = QPixmap(LOGO_PATH).scaledToWidth(160, Qt.TransformationMode.SmoothTransformation)
            logo_lbl = QLabel(); logo_lbl.setPixmap(pix)
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ll.addWidget(logo_lbl)
        app_lbl = QLabel(APP_NAME)
        app_lbl.setStyleSheet("color:#4a9eff; font-size:17px; font-weight:bold;")
        app_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.addWidget(app_lbl)
        ver_lbl = QLabel(f"v{APP_VERSION}")
        ver_lbl.setStyleSheet("color:#405080; font-size:11px;")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.addWidget(ver_lbl)
        sl.addWidget(logo_frame)

        # Connection status
        self._conn_dot = QLabel("● Disconnected")
        self._conn_dot.setStyleSheet("color:#f44336; padding:8px 16px; font-size:12px;")
        sl.addWidget(self._conn_dot)

        # Nav buttons
        self._nav = {}
        nav_items = [
            ("dashboard",    "  Dashboard"),
            ("punchlog",     "  Punch Log"),
            ("users",        "  Users"),
            ("fingerprints", "  Fingerprints"),
            ("network",      "  Network"),
            ("manage_users", "  Manage Users"),
            ("backup",       "  Backup & Restore"),
            ("settings",     "  Settings"),
        ]
        for key, label in nav_items:
            btn = QPushButton(label); btn.setObjectName("nav")
            btn.clicked.connect(lambda _, k=key: self._nav_to(k))
            sl.addWidget(btn); self._nav[key] = btn

        sl.addStretch()

        self._dev_info = QLabel("")
        self._dev_info.setStyleSheet("color:#405080; padding:8px 12px; font-size:10px;")
        self._dev_info.setWordWrap(True)
        sl.addWidget(self._dev_info)

        # Exit button at the bottom of the sidebar
        exit_btn = QPushButton("  Exit")
        exit_btn.setObjectName("nav")
        exit_btn.setStyleSheet(
            "QPushButton { color:#f44336; text-align:left; padding:13px 20px; "
            "border:none; border-top:1px solid #2a2a4a; background:transparent; }"
            "QPushButton:hover { background:#2a1a1a; color:#ff6b6b; }"
        )
        exit_btn.clicked.connect(self.close)
        sl.addWidget(exit_btn)

        row.addWidget(sidebar)

        # ── Content stack ──────────────────────────────────────────────
        self._stack = QStackedWidget()
        self._p_dash = DashboardPanel(self.db)
        self._p_log  = PunchLogPanel(self.db)
        self._p_usr  = UsersPanel()
        self._p_fp   = FingerprintsPanel()
        self._p_net  = NetworkPanel()
        self._p_mgt  = ManageUsersPanel(self.db)    # person directory (ac_users)
        self._p_bak  = BackupRestorePanel(self.db)  # backup & restore
        self._p_set  = SettingsPanel()

        for w in (self._p_dash, self._p_log, self._p_usr, self._p_fp, self._p_net, self._p_mgt, self._p_bak, self._p_set):
            wrap = QWidget(); wl = QVBoxLayout(wrap)
            wl.setContentsMargins(20, 16, 20, 16); wl.addWidget(w)
            self._stack.addWidget(wrap)

        row.addWidget(self._stack)

        # ── Wire up panel signals ──────────────────────────────────────
        self._p_set.sig_saved.connect(self._on_settings_saved)
        self._p_usr.sig_load.connect(lambda di: self.sdk.list_persons(di))
        self._p_usr.sig_delete.connect(lambda di, ub: self.sdk.delete_person(di, ub))
        self._p_usr.sig_transfer.connect(self._do_transfer)
        self._p_fp.sig_start_dl.connect(self._fp_start_dl)
        self._p_fp.sig_dl_fp.connect(lambda di, ub, fi: self.sdk.dl_fp(di, ub, fi))
        self._p_fp.sig_ul_fp.connect(lambda di, ub, fi, d, l: self.sdk.ul_fp(di, ub, fi, d, l))
        self._p_net.sig_scan.connect(lambda: self.sdk.udp_scan())
        self._p_net.sig_get_net.connect(lambda di: self.sdk.get_net(di))
        self._p_net.sig_set_net.connect(lambda di, c: self.sdk.set_net(di, c))

        # Status bar
        self.statusBar().showMessage(f"Log: {self._log_path}")

        # Load settings into Settings panel
        self._p_set.load(self.cfg)

        self._nav_to("dashboard")

    def _nav_to(self, key):
        order = ["dashboard", "punchlog", "users", "fingerprints", "network", "manage_users", "backup", "settings"]
        self._stack.setCurrentIndex(order.index(key) if key in order else 0)
        for k, btn in self._nav.items():
            btn.setProperty("active", k == key)
            btn.style().unpolish(btn); btn.style().polish(btn)
        if key == "punchlog":
            self._p_log._search()

    # ── SDK startup ───────────────────────────────────────────────────────────
    def _start_sdk(self):
        try:
            self.sdk.load()
            mode     = self.cfg.get("conn_mode", "client")
            srv_port = self.cfg.get("server_port", 5010) if mode == "server" else None
            listen   = self.sdk.start(server_port=srv_port)
            self.statusBar().showMessage(
                f"SDK started  listen_port={listen}  mode={mode.upper()}  |  Log: {self._log_path}")
        except Exception as e:
            QMessageBox.critical(self, "SDK Error", f"Failed to start SDK:\n{e}")
            return

        self.poller = Poller(self.sdk)
        self.poller.dev_login.connect(self._on_login)
        self.poller.dev_logout.connect(self._on_logout)
        self.poller.punch.connect(self._on_punch)
        self.poller.person.connect(self._on_person)
        self.poller.fp_dl.connect(self._on_fp_dl)
        self.poller.fp_ul.connect(self._on_fp_ul)
        self.poller.net_cfg.connect(self._on_netcfg)
        self.poller.udp_devs.connect(self._on_udp)
        self.poller.del_ok.connect(self._on_delete)
        self.poller.log_msg.connect(lambda m: (self.statusBar().showMessage(m), self._p_dash.add_log(m)))
        self.poller.connected.connect(self._on_connected)
        self.poller.start()

        if self.cfg.get("conn_mode", "client") == "client":
            ip   = self.cfg.get("device_ip",   "192.168.1.218")
            port = self.cfg.get("device_port",  5010)
            ret  = self.sdk.connect(ip, port)
            self.statusBar().showMessage(f"Connecting to {ip}:{port}  (ret={ret})  |  Log: {self._log_path}")

    # ── Poller signal handlers ────────────────────────────────────────────────
    def _on_connected(self, ok: bool):
        if ok:
            self._conn_dot.setText("● Connected")
            self._conn_dot.setStyleSheet("color:#4caf50; padding:8px 16px; font-size:12px;")
        else:
            self._conn_dot.setText("● Disconnected")
            self._conn_dot.setStyleSheet("color:#f44336; padding:8px 16px; font-size:12px;")

    def _on_login(self, dev_idx, info_str, type_flag):
        dev = self.poller.devices.get(dev_idx, {})
        m   = dev.get("model", "")
        a   = dev.get("addr", "")
        mid = dev.get("machine_id", "")
        self._dev_info.setText(f"{m}\n{a}\nID:{mid}")
        self._p_dash.update_device(dev_idx, mid, m, a, True)
        self._p_dash.add_log(f"Device connected: {info_str}")
        for p in (self._p_usr, self._p_fp, self._p_net):
            p.refresh_devices(self.poller.devices)
        self.sdk.dl_new(dev_idx)

    def _on_logout(self, dev_idx):
        self._p_dash.update_device(dev_idx, 0, "", "", False)
        self._dev_info.setText("")
        for p in (self._p_usr, self._p_fp, self._p_net):
            p.refresh_devices(self.poller.devices)

    def _on_punch(self, uid, ts, rec_type, is_live):
        if self._is_dup(uid, rec_type, ts):
            return
        short, label = punch_short(rec_type)
        method = verify_str(rec_type)
        dev_id = next(iter(self.poller.devices), 0) if self.poller else 0
        src    = "LIVE" if is_live else "STORE"
        self.db.insert(uid, short, label, method, ts, dev_id, src)
        self._write_log(uid, ts, rec_type)
        self._p_dash.add_punch(uid, ts, rec_type, is_live)

    def _on_person(self, info: dict):
        self._p_usr.add_person(info)
        # If FP download is active, schedule per-finger downloads for this user
        if self._fp_dl_dev >= 0:
            self._p_fp.trigger_user_fp(self._fp_dl_dev, info["uid"], info.get("fp_status", 0))

    def _on_fp_dl(self, uid, fi, data, fp_len):
        self._p_fp.save_fp(uid, fi, data)

    def _on_fp_ul(self, uid, fi, ok):
        msg = f"Upload FP user={uid} finger={fi}: {'OK' if ok else 'FAILED'}"
        self.statusBar().showMessage(msg)

    def _on_netcfg(self, dev_idx, cfg):
        self._p_net.populate(cfg)

    def _on_udp(self, devs: list):
        self._p_net.show_scan(devs)
        self.statusBar().showMessage(f"UDP scan: {len(devs)} device(s) found")

    def _on_delete(self, uid, ok):
        self._p_usr.mark_deleted(uid, ok)

    # ── Panel actions ─────────────────────────────────────────────────────────
    def _on_settings_saved(self, cfg: dict):
        self.cfg = cfg
        self._init_log()
        self.statusBar().showMessage(f"Settings saved  |  Log: {self._log_path}")

    def _fp_start_dl(self, di, save_dir):
        self._fp_dl_dev = di
        self._fp_dl_dir = save_dir
        self._p_fp._save_dir = save_dir
        # Load all users — _on_person will trigger FP download per user
        self.sdk.list_persons(di)

    def _do_transfer(self, src, dst, persons):
        ok = 0
        for p in persons:
            raw = p.get("_raw")
            if raw:
                self.sdk.modify_person(dst, raw)
                ok += 1
        QMessageBox.information(self, "Transfer Complete",
            f"Transferred {ok} user record(s) to DevIdx={dst}.\n\n"
            "To also transfer fingerprint templates:\n"
            "1. Download fingerprints from source in the Fingerprints panel.\n"
            "2. Upload that folder to the target device.")

    # ── Shutdown ──────────────────────────────────────────────────────────────
    def closeEvent(self, event):
        if self.poller:
            self.poller.stop()
            self.poller.wait(2000)
        if self.poller:
            for di in list(self.poller.devices.keys()):
                try: self.sdk.disconnect(di)
                except Exception: pass
        self.sdk.stop()
        event.accept()

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if struct.calcsize("P") != 8:
        print("[ERROR] InterXDB_FFServer requires 64-bit Python.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(STYLE)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
