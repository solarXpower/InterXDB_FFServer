#!/usr/bin/env python3
"""
Anviz V300 Fingerprint Reader — Punch Record Capture Test
==========================================================
Device  : 192.168.1.218 port 5010  (Server Mode — SDK connects as client)
Target  : User ID 900

The V300 is in "Server Mode", meaning the device exposes a TCP server on
port 5010 and the host PC connects TO it using CCHex_ClientConnect().

SDK DLL : TC_B_SDK_V64  (64-bit — must run with 64-bit Python)

Flow
----
1. CChex_Init()
2. CChex_Start()                        -- start SDK engine
3. CChex_SetSdkConfig(AutoDownload=1, RecordFlag=1, LogFile=1)  -- per Anviz support
4. CCHex_ClientConnect(IP, Port)        -- connect to the device
5. Poll CChex_Update() in a tight loop
   - CCHEX_RET_DEV_LOGIN_TYPE  (2)  : device acknowledged; trigger DownloadAllNewRecords
   - CCHEX_RET_RECORD_INFO_TYPE (1) : stored records being downloaded
   - CCHEX_RET_LIVE_SEND_ATTENDANCE_TYPE (54) : real-time punch event
6. Print every record; highlight when UserID == 900
7. Ctrl+C → graceful shutdown
"""

import ctypes
import os
import struct
import sys
import time
from datetime import datetime, timedelta

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
TARGET_USER_ID = 900
DEVICE_IP      = "192.168.1.218"
DEVICE_PORT    = 5010
POLL_SLEEP_MS  = 10   # milliseconds between CChex_Update calls when idle

# 64-bit SDK DLL and its sibling support DLLs live in this folder
SDK_DIR  = r"C:\AI Software\anviz\TC_B_SDK_V64_20250611\SDK FILES"
DLL_NAME = "tc-b_new_sdk.dll"
DLL_PATH = os.path.join(SDK_DIR, DLL_NAME)

# Buffer size for CChex_Update (matches the demo)
BUFF_SIZE = 32000

# ──────────────────────────────────────────────────────────────
# SDK message type constants
# ──────────────────────────────────────────────────────────────
MSG_RECORD_INFO      = 1    # Downloaded stored attendance record
MSG_DEV_LOGIN        = 2    # Device connected / logged in
MSG_DEV_LOGOUT       = 3    # Device disconnected
MSG_NEW_RECORD_INFO  = 71   # New (unread) record returned after DownloadAllNewRecords
MSG_LIVE_ATTENDANCE  = 54   # Real-time punch pushed by device the moment it happens
MSG_LOGIN_CHANGE     = 201  # Device re-login (reconnect)

# ──────────────────────────────────────────────────────────────
# ctypes Structures  (match AnvizNew.cs exactly; _pack_=1 = no padding)
# ──────────────────────────────────────────────────────────────

class DevLoginInfo(ctypes.Structure):
    """CCHEX_RET_DEV_LOGIN_STRU — 52 bytes"""
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
    """CCHEX_RET_RECORD_INFO_STRU — 28 bytes
    Used for MSG_RECORD_INFO and MSG_NEW_RECORD_INFO"""
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
    """CCHEX_RET_LIVE_SEND_ATTENDANCE_STRU — 22 bytes
    Pushed in real time the moment a user punches"""
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

# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────

# Attendance status — lower 4 bits of RecordType byte
# Short code matches CrossChex log format (I, O, BO, BI, LO, LI)
ATTEND_STATUS = {
    0: ("I",  "Check-In"),
    1: ("O",  "Check-Out"),
    2: ("BO", "Break-Out"),
    3: ("BI", "Break-In"),
    4: ("LO", "OT-In"),
    5: ("LI", "OT-Out"),
}

# Verification method — upper 4 bits of RecordType byte
VERIFY_METHOD = {
    0: "FP",        # Fingerprint
    1: "Card",
    2: "PIN",
    3: "FP+Card",
    4: "FP+PIN",
    5: "Card+PIN",
    6: "FP+Card+PIN",
    8: "FP",        # Fingerprint (alternate code used by some firmware)
    15: "Auto",
}

def record_type_label(code: int) -> str:
    """Decode combined RecordType byte: upper nibble = verify method, lower nibble = status.
    Returns e.g.  'I  (Check-In)  [FP]'
    """
    status = code & 0x0F           # lower 4 bits
    method = (code >> 4) & 0x0F   # upper 4 bits
    short, long_name = ATTEND_STATUS.get(status, (f"?{status}", f"Status-{status}"))
    method_str = VERIFY_METHOD.get(method, f"Verify-{method}")
    return f"{short:<3} ({long_name}) [{method_str}]"


# Housekeeping message types (not errors — just informational)
SDK_MSG_LABELS = {
    19: "Device Status Update",
    33: "Record Flag Cleared",
    25: "Get SN",
    29: "Basic Config",
    39: "Get Time",
    68: "Record Count",
}


def employee_id_to_int(emp_bytes) -> int:
    """Convert 5-byte big-endian Employee ID to a decimal integer.
    Replicates the C# Employee_array_to_srring() function:
      temp[4-i] = EmployeeId[i] → BitConverter.ToInt64(temp, 0)
    which is simply a big-endian read of the 5 bytes.
    """
    result = 0
    for b in emp_bytes:
        result = (result << 8) | int(b)
    return result


def decode_timestamp(date_bytes) -> datetime:
    """Decode the 4-byte date field used by the SDK.

    Steps (from SDK C# source):
      1. BitConverter.ToUInt32(date, 0)  — interpret bytes as little-endian uint32
      2. swapInt32(value)               — reverse byte order (big↔little endian swap)
      3. new DateTime(2000, 1, 2).AddSeconds(swapped)

    Result is local device time as a Python datetime.
    """
    # Step 1 – little-endian uint32
    val = struct.unpack('<I', bytes(date_bytes))[0]
    # Step 2 – byte-swap (swapInt32)
    swapped = (
        ((val & 0x000000FF) << 24) |
        ((val & 0x0000FF00) <<  8) |
        ((val & 0x00FF0000) >>  8) |
        ((val & 0xFF000000) >> 24)
    )
    # Step 3 – add seconds to base date
    base = datetime(2000, 1, 2)
    return base + timedelta(seconds=swapped)


# Duplicate-punch filter:
# Tracks last accepted punch per (user_id, punch_short_code).
# Key: (uid, short_code)  Value: datetime of last accepted punch
_last_punch: dict = {}
DEDUP_WINDOW_SECONDS = 60   # ignore same user + same punch type within this window


def is_duplicate(uid: int, rec_type: int, ts: datetime) -> bool:
    """Return True if this punch is a duplicate within the dedup window.
    A duplicate is defined as: same UserID + same punch type code within 60 seconds.
    """
    status = rec_type & 0x0F
    short_code, _ = ATTEND_STATUS.get(status, (f"?{status}", ""))
    key = (uid, short_code)
    last_ts = _last_punch.get(key)
    if last_ts is not None:
        diff = abs((ts - last_ts).total_seconds())
        if diff < DEDUP_WINDOW_SECONDS:
            return True   # duplicate — reject
    # Accept: update the last-seen time for this key
    _last_punch[key] = ts
    return False


def get_log_path() -> str:
    """Build log file path: 'Punchtypes format <IP>.log' in the script folder."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, f"Punchtypes format {DEVICE_IP}.log")


def init_log(log_path: str):
    """Create the log file and write the CrossChex header line if the file is new."""
    is_new = not os.path.isfile(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        if is_new:
            f.write("C,GetAllLogs,SUCCESSFUL\n")
    print(f"[LOG]  Appending punches to: {log_path}")


def append_log(log_path: str, uid: int, ts: datetime, rec_type: int):
    """Append one punch record in CrossChex CSV format:
       UserID,PunchCode,"YYYY-MM-DD HH:MM:SS",0,0
    """
    status = rec_type & 0x0F
    short_code, _ = ATTEND_STATUS.get(status, (f"?{status}", ""))
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    line = f'{uid},{short_code},"{ts_str}",0,0\n'
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


def print_record(prefix: str, uid: int, ts: datetime, rec_type: int,
                 cur_idx: int = 0, total: int = 0):
    """Print one attendance record to console, highlighting User 900."""
    label  = record_type_label(rec_type)
    match  = "  <<< USER 900 MATCHED >>>" if uid == TARGET_USER_ID else ""
    index  = f"  ({cur_idx}/{total})" if total > 0 else ""
    print(f"{prefix}  UserID={uid:>6}  {ts.strftime('%Y-%m-%d %H:%M:%S')}"
          f"  {label:<12}{index}{match}")


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  Anviz V300 Fingerprint Reader — Punch Record Capture")
    print(f"  Device  : {DEVICE_IP}:{DEVICE_PORT}")
    print(f"  Watching: User ID {TARGET_USER_ID}")
    print("=" * 65)

    # ── Validate Python is 64-bit (required for 64-bit DLL) ──────
    if struct.calcsize("P") != 8:
        print("[ERROR] This script requires 64-bit Python to match the SDK DLL.")
        sys.exit(1)

    # ── Add SDK folder to DLL search path (loads msvcr120.dll etc.) ─
    if not os.path.isdir(SDK_DIR):
        print(f"[ERROR] SDK folder not found: {SDK_DIR}")
        sys.exit(1)
    os.add_dll_directory(SDK_DIR)   # Python 3.8+ Windows-only

    if not os.path.isfile(DLL_PATH):
        print(f"[ERROR] DLL not found: {DLL_PATH}")
        sys.exit(1)

    # ── Load DLL ─────────────────────────────────────────────────
    try:
        sdk = ctypes.CDLL(DLL_PATH)
        print(f"[OK]   Loaded {DLL_NAME}")
    except OSError as e:
        print(f"[ERROR] Could not load DLL: {e}")
        sys.exit(1)

    # ── Declare function signatures (prevents ctypes default c_int return) ──

    sdk.CChex_Version.restype  = ctypes.c_uint
    sdk.CChex_Version.argtypes = []

    sdk.CChex_Init.restype  = None
    sdk.CChex_Init.argtypes = []

    sdk.CChex_Start.restype  = ctypes.c_void_p
    sdk.CChex_Start.argtypes = []

    sdk.CChex_Stop.restype  = None
    sdk.CChex_Stop.argtypes = [ctypes.c_void_p]

    # AutoDownload=1  → SDK auto-pulls new records when device connects
    # RecordFlag=1    → SDK clears new-record flag on device after download
    # LogFile=1       → SDK writes a log file (useful for Anviz support)
    sdk.CChex_SetSdkConfig.restype  = None
    sdk.CChex_SetSdkConfig.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,  # SetAutoDownload
        ctypes.c_int,  # SetRecordflag
        ctypes.c_int,  # SetLogFile
    ]

    # Connect SDK (as TCP client) to the V300 which is running as a server
    sdk.CCHex_ClientConnect.restype  = ctypes.c_int
    sdk.CCHex_ClientConnect.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,   # IP address as ASCII bytes
        ctypes.c_int,      # port
    ]

    sdk.CCHex_ClientDisconnect.restype  = ctypes.c_int
    sdk.CCHex_ClientDisconnect.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,   # DevIdx
    ]

    # Polling function — retrieves next pending message from the SDK queue
    sdk.CChex_Update.restype  = ctypes.c_int
    sdk.CChex_Update.argtypes = [
        ctypes.c_void_p,                    # handle
        ctypes.POINTER(ctypes.c_int),       # [out] DevIdx
        ctypes.POINTER(ctypes.c_int),       # [out] MsgType
        ctypes.c_void_p,                    # [out] data buffer
        ctypes.c_int,                       # buffer length
    ]

    # Trigger download of all records not yet retrieved by SDK
    sdk.CChex_DownloadAllNewRecords.restype  = ctypes.c_int
    sdk.CChex_DownloadAllNewRecords.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,   # DevIdx
    ]

    # ── Initialise SDK ───────────────────────────────────────────
    ver = sdk.CChex_Version()
    print(f"[INFO] SDK version code : {ver}")

    sdk.CChex_Init()
    print("[INFO] CChex_Init() done")

    handle = sdk.CChex_Start()
    if not handle:
        print("[ERROR] CChex_Start() returned NULL — cannot continue.")
        sys.exit(1)
    print(f"[INFO] CChex_Start()  handle = 0x{handle:X}")

    # Apply config recommended by Anviz support for log capture
    sdk.CChex_SetSdkConfig(handle, 1, 1, 1)
    print("[INFO] CChex_SetSdkConfig(AutoDownload=1, RecordFlag=1, LogFile=1)")

    # ── Connect to the V300 device (device is the TCP server) ────
    ip_bytes = DEVICE_IP.encode("ascii")
    ret = sdk.CCHex_ClientConnect(handle, ip_bytes, DEVICE_PORT)
    if ret < 0:
        print(f"[WARN] CCHex_ClientConnect returned {ret} — check IP/port and network.")
    else:
        print(f"[INFO] CCHex_ClientConnect({DEVICE_IP}:{DEVICE_PORT}) → ret={ret}")

    # ── Open / create the punch log file ────────────────────────
    log_path = get_log_path()
    init_log(log_path)

    # ── Allocate polling buffers ─────────────────────────────────
    buff         = ctypes.create_string_buffer(BUFF_SIZE)
    dev_idx_out  = (ctypes.c_int * 1)(0)
    msg_type_out = (ctypes.c_int * 1)(0)

    device_idx    = -1   # filled when DEV_LOGIN arrives
    dev_type_flag = 0    # 0x40 = VER_4_NEWID, check before parsing

    print()
    print("[WAIT] Waiting for device login and punch events.")
    print("       Place your finger on the reader at any time.")
    print("       Press Ctrl+C to exit.\n")

    try:
        while True:
            # CChex_Update returns >0 when a message is available, <=0 when idle
            ret = sdk.CChex_Update(
                handle,
                dev_idx_out,
                msg_type_out,
                ctypes.cast(buff, ctypes.c_void_p),
                BUFF_SIZE,
            )

            if ret <= 0:
                time.sleep(POLL_SLEEP_MS / 1000.0)
                continue

            msg_type = msg_type_out[0]
            d_idx    = dev_idx_out[0]

            # ── Device connected ─────────────────────────────────
            if msg_type in (MSG_DEV_LOGIN, MSG_LOGIN_CHANGE):
                info          = DevLoginInfo.from_buffer_copy(buff.raw)
                device_idx    = info.DevIdx
                dev_type_flag = info.DevTypeFlag
                dev_type_str  = info.DevType.decode("ascii", errors="ignore").rstrip("\x00")
                version_str   = info.Version.decode("ascii", errors="ignore").rstrip("\x00")
                addr_str      = info.Addr.decode("ascii",   errors="ignore").rstrip("\x00")

                print(f"[CONNECTED]  MachineId={info.MachineId}  DevIdx={device_idx}"
                      f"  Model={dev_type_str}  FW={version_str}  Addr={addr_str}"
                      f"  TypeFlag=0x{dev_type_flag:08X}")

                # Pull any stored records the device has not yet sent
                r = sdk.CChex_DownloadAllNewRecords(handle, device_idx)
                print(f"[INFO]       CChex_DownloadAllNewRecords() → {r}\n")

            # ── Device disconnected ──────────────────────────────
            elif msg_type == MSG_DEV_LOGOUT:
                print(f"[DISCONNECTED]  DevIdx={d_idx}")
                device_idx = -1

            # ── Stored record downloaded ─────────────────────────
            elif msg_type in (MSG_RECORD_INFO, MSG_NEW_RECORD_INFO):
                # Use standard 5-byte EmployeeId struct for V300
                rec = RecordInfo.from_buffer_copy(buff.raw)
                uid = employee_id_to_int(rec.EmployeeId)
                ts  = decode_timestamp(rec.Date)
                if is_duplicate(uid, rec.RecordType, ts):
                    print(f"[SKIP]    UserID={uid}  {ts}  duplicate within {DEDUP_WINDOW_SECONDS}s — ignored")
                else:
                    print_record("[RECORD]  ", uid, ts, rec.RecordType,
                                 rec.CurIdx, rec.TotalCnt)
                    append_log(log_path, uid, ts, rec.RecordType)

            # ── Real-time punch (fired the moment finger is read) ─
            elif msg_type == MSG_LIVE_ATTENDANCE:
                rec = LiveAttendanceInfo.from_buffer_copy(buff.raw)
                uid = employee_id_to_int(rec.EmployeeId)
                ts  = decode_timestamp(rec.Date)
                if is_duplicate(uid, rec.RecordType, ts):
                    print(f"[SKIP]    UserID={uid}  {ts}  duplicate within {DEDUP_WINDOW_SECONDS}s — ignored")
                else:
                    print()
                    print_record("[LIVE PUNCH]", uid, ts, rec.RecordType)
                    print()
                    append_log(log_path, uid, ts, rec.RecordType)

            # ── Housekeeping / informational messages ────────────
            else:
                label = SDK_MSG_LABELS.get(msg_type, f"Unknown-{msg_type}")
                print(f"[INFO] {label}  (Type={msg_type}  DevIdx={d_idx})")

    except KeyboardInterrupt:
        print("\n[STOP] Ctrl+C — shutting down cleanly.")

    finally:
        if device_idx >= 0:
            sdk.CCHex_ClientDisconnect(handle, device_idx)
            print(f"[INFO] Disconnected DevIdx={device_idx}")
        sdk.CChex_Stop(handle)
        print("[INFO] CChex_Stop() — session ended.")


if __name__ == "__main__":
    main()
