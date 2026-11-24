// TrimFlow - Context-Aware Subprocess Memory, Role & EcoQoS Optimizer for Windows
// Copyright (c) 2026. Released under the MIT License.

#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "heuristics.h"
#include "strings.h"

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
struct PROCESS_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
};
#endif

namespace {

// NT Native API definitions for zero-injection command-line inspection (ProcessCommandLineInformation = 60)
// and optional Standby List maintenance.
struct UNICODE_STRING_LOCAL {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetSystemInformationFn    = LONG(NTAPI*)(ULONG, PVOID, ULONG);
constexpr ULONG kProcessCommandLineInformation = 60;
constexpr ULONG kSystemMemoryListInformation   = 80;
constexpr ULONG kMemoryPurgeLowPriorityStandbyList = 5;

struct MEMORY_PRIORITY_INFO_LOCAL {
    ULONG MemoryPriority;
};
constexpr ULONG kMemoryPriorityVeryLow = 1;
constexpr ULONG kMemoryPriorityNormal  = 5;

constexpr UINT WM_TRAY        = WM_APP + 1;
constexpr UINT WM_PASS_DONE   = WM_APP + 2;
constexpr UINT WM_SECOND_LAUNCH = WM_APP + 3;
constexpr UINT_PTR TIMER_UI   = 1;
constexpr UINT_PTR TIMER_MINIMIZE_DEBOUNCE = 2;
constexpr UINT_PTR TIMER_TOAST_HIDE = 3;

enum MenuId : UINT {
    ID_OPTIMIZE_NOW = 100,
    ID_AUTO_ENABLE,
    ID_PROTECT_VISIBLE,
    ID_GAME_BOOST,
    ID_MULTI_ONLY,
    ID_AUTOSTART,
    ID_INTERVAL_15,
    ID_INTERVAL_30,
    ID_INTERVAL_60,
    ID_EXIT,
    ID_APP_FIRST = 500
};

const wchar_t* kAppName     = L"TrimFlow";
const wchar_t* kSettingsKey = L"Software\\TrimFlow";
const wchar_t* kRunKey      = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const wchar_t* kRunValue    = L"TrimFlow";

using trimflow::SubprocRole;

struct ProcHistory {
    SIZE_T lastPostTrimBytes = 0;
    ULONGLONG lastTrimTick = 0;
    bool throttled = false;
};

struct AppSummary {
    int totalProcs = 0;
    int trimmedProcs = 0;
    int activeProcs = 0;
    SIZE_T beforeBytes = 0;
    SIZE_T afterBytes = 0;
};

struct DiagRow {
    DWORD pid = 0;
    std::wstring name;
    SubprocRole role = SubprocRole::MainOrStandalone;
    bool isForegroundApp = false;
    bool protectedProc = false;
    std::wstring reason;
};

const wchar_t* RoleName(SubprocRole r) {
    switch (r) {
        case SubprocRole::GpuCompositor:    return L"GpuCompositor";
        case SubprocRole::AudioOrNetwork:   return L"AudioOrNetwork";
        case SubprocRole::RendererOrWorker: return L"RendererOrWorker";
        default:                            return L"MainOrStandalone";
    }
}

struct PassReport {
    std::vector<DiagRow> diag;
    std::map<std::wstring, AppSummary> apps;
    SIZE_T totalSavedBytes = 0;
    bool fullscreenGameDetected = false;
};

HINSTANCE g_inst = nullptr;
HWND      g_hwnd = nullptr;
HWND      g_toastWnd = nullptr;
std::wstring g_toastTitle;
std::wstring g_toastSub;
bool      g_firstPassToastPending = true;
HANDLE    g_wakeEvt = nullptr;
HANDLE    g_stopEvt = nullptr;
HANDLE    g_worker  = nullptr;
HICON     g_icon    = nullptr;
HWINEVENTHOOK g_hookFg  = nullptr;
HWINEVENTHOOK g_hookMin = nullptr;

bool      g_autoOptimize   = true;
bool      g_protectVisible = true;
bool      g_gameBoost      = true;
bool      g_multiProcOnly  = false;
DWORD     g_intervalSec    = 30;
double    g_sessionSavedMB = 0.0;
PassReport g_lastReport;
std::set<std::wstring> g_excludedApps;
std::map<DWORD, ProcHistory> g_procHistory;
SRWLOCK   g_histLock = SRWLOCK_INIT;

// ---- NT Native Helpers ------------------------------------------------------------------------

NtQueryInformationProcessFn GetNtQueryInfoProc() {
    static NtQueryInformationProcessFn fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}

std::wstring QueryProcessCommandLine(HANDLE h) {
    auto fn = GetNtQueryInfoProc();
    if (!fn) return L"";
    ULONG need = 0;
    fn(h, kProcessCommandLineInformation, nullptr, 0, &need);
    if (need < sizeof(UNICODE_STRING_LOCAL) || need > 65536) return L"";
    std::vector<BYTE> buf(need, 0);
    if (fn(h, kProcessCommandLineInformation, buf.data(), need, &need) != 0) return L"";
    auto* us = reinterpret_cast<const UNICODE_STRING_LOCAL*>(buf.data());
    if (!us->Buffer || !us->Length) return L"";
    return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
}

SubprocRole ClassifySubprocessRole(HANDLE h, int groupCount) {
    if (groupCount <= 1) return SubprocRole::MainOrStandalone;
    return trimflow::ClassifyCommandLine(QueryProcessCommandLine(h), groupCount);
}

void PurgeLowPriorityStandbyIfHighPressure() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (!GlobalMemoryStatusEx(&ms) || ms.dwMemoryLoad < 80) return;
    static NtSetSystemInformationFn setSys = reinterpret_cast<NtSetSystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetSystemInformation"));
    if (!setSys) return;
    ULONG cmd = kMemoryPurgeLowPriorityStandbyList;
    setSys(kSystemMemoryListInformation, &cmd, sizeof(cmd));
}

// ---- Registry helpers -------------------------------------------------------------------------

std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool LoadBool(const wchar_t* name, bool def) {
    DWORD v = def ? 1 : 0, sz = sizeof(v);
    RegGetValueW(HKEY_CURRENT_USER, kSettingsKey, name, RRF_RT_REG_DWORD, nullptr, &v, &sz);
    return v != 0;
}

void SaveBool(const wchar_t* name, bool on) {
    DWORD v = on ? 1 : 0;
    RegSetKeyValueW(HKEY_CURRENT_USER, kSettingsKey, name, REG_DWORD, &v, sizeof(v));
}

DWORD LoadDword(const wchar_t* name, DWORD def) {
    DWORD v = def, sz = sizeof(v);
    RegGetValueW(HKEY_CURRENT_USER, kSettingsKey, name, RRF_RT_REG_DWORD, nullptr, &v, &sz);
    return v;
}

void SaveDword(const wchar_t* name, DWORD v) {
    RegSetKeyValueW(HKEY_CURRENT_USER, kSettingsKey, name, REG_DWORD, &v, sizeof(v));
}

void LoadExcluded() {
    g_excludedApps.clear();
    DWORD sz = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, kSettingsKey, L"ExcludedApps", RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &sz) != ERROR_SUCCESS || !sz)
        return;
    std::vector<wchar_t> buf(sz / sizeof(wchar_t) + 1, 0);
    if (RegGetValueW(HKEY_CURRENT_USER, kSettingsKey, L"ExcludedApps", RRF_RT_REG_MULTI_SZ, nullptr, buf.data(), &sz) != ERROR_SUCCESS)
        return;
    for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) g_excludedApps.insert(Lower(p));
}

void SaveExcluded() {
    std::wstring multi;
    for (const auto& a : g_excludedApps) { multi += a; multi.push_back(L'\0'); }
    multi.push_back(L'\0');
    RegSetKeyValueW(HKEY_CURRENT_USER, kSettingsKey, L"ExcludedApps", REG_MULTI_SZ,
                    multi.data(), (DWORD)(multi.size() * sizeof(wchar_t)));
}

std::wstring ExePath() {
    wchar_t p[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    return p;
}

bool AutostartEnabled() {
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD sz = sizeof(buf);
    if (RegGetValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ, nullptr, buf, &sz) != ERROR_SUCCESS) return false;
    return _wcsicmp(buf, (L"\"" + ExePath() + L"\"").c_str()) == 0;
}

void SetAutostart(bool on) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return;
    if (on) {
        std::wstring v = L"\"" + ExePath() + L"\"";
        RegSetValueExW(k, kRunValue, 0, REG_SZ, (const BYTE*)v.c_str(), (DWORD)((v.size() + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(k, kRunValue);
    }
    RegCloseKey(k);
}

// ---- Dynamic Process & Window Discovery -------------------------------------------------------

bool IsSystemProtected(const std::wstring& exeLower) {
    return trimflow::IsSystemProtectedProcess(exeLower);
}

ULONGLONG FileTimeToU64(const FILETIME& ft) {
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

SIZE_T QueryWorkingSet(HANDLE h) {
    PROCESS_MEMORY_COUNTERS pmc{ sizeof(pmc) };
    return K32GetProcessMemoryInfo(h, &pmc, sizeof(pmc)) ? pmc.WorkingSetSize : 0;
}

ULONGLONG QueryCpuTime(HANDLE h) {
    FILETIME create{}, exit{}, kern{}, user{};
    return GetProcessTimes(h, &create, &exit, &kern, &user) ? (FileTimeToU64(kern) + FileTimeToU64(user)) : 0;
}

void SetProcessThrottleState(HANDLE h, bool throttle) {
    MEMORY_PRIORITY_INFO_LOCAL mp{ throttle ? kMemoryPriorityVeryLow : kMemoryPriorityNormal };
    SetProcessInformation(h, ProcessMemoryPriority, &mp, sizeof(mp));

    PROCESS_POWER_THROTTLING_STATE pts{};
    pts.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    pts.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    pts.StateMask = throttle ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0;
    SetProcessInformation(h, ProcessPowerThrottling, &pts, sizeof(pts));

    SetPriorityClass(h, throttle ? BELOW_NORMAL_PRIORITY_CLASS : NORMAL_PRIORITY_CLASS);
}

// Restores all previously throttled processes on exit so TrimFlow leaves zero trace.
void RestoreAllThrottledProcesses() {
    AcquireSRWLockExclusive(&g_histLock);
    for (const auto& [pid, hist] : g_procHistory) {
        if (!hist.throttled) continue;
        HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
        if (h) {
            SetProcessThrottleState(h, false);
            CloseHandle(h);
        }
    }
    g_procHistory.clear();
    ReleaseSRWLockExclusive(&g_histLock);
}

struct WindowEnumerationState {
    std::set<DWORD> visiblePids;
    DWORD fgPid = 0;
    bool fullscreenForeignApp = false;
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    auto* st = reinterpret_cast<WindowEnumerationState*>(lParam);
    if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) return TRUE;
    RECT rc{};
    if (!GetWindowRect(hwnd, &rc) || rc.right - rc.left < 100 || rc.bottom - rc.top < 100) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid) st->visiblePids.insert(pid);
    return TRUE;
}

WindowEnumerationState InspectWindows() {
    WindowEnumerationState st;
    if (HWND fg = GetForegroundWindow()) {
        GetWindowThreadProcessId(fg, &st.fgPid);
        RECT rc{};
        HMONITOR mon = MonitorFromWindow(fg, MONITOR_DEFAULTTOPRIMARY);
        MONITORINFO mi{ sizeof(mi) };
        if (GetWindowRect(fg, &rc) && GetMonitorInfoW(mon, &mi)) {
            bool coversMonitor = rc.left <= mi.rcMonitor.left && rc.top <= mi.rcMonitor.top &&
                                 rc.right >= mi.rcMonitor.right && rc.bottom >= mi.rcMonitor.bottom;
            wchar_t cls[64] = {};
            GetClassNameW(fg, cls, 63);
            if (coversMonitor && wcscmp(cls, L"Progman") != 0 && wcscmp(cls, L"WorkerW") != 0 &&
                wcscmp(cls, L"Shell_TrayWnd") != 0) {
                st.fullscreenForeignApp = true;
            }
        }
    }
    EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&st));
    return st;
}

struct SampledProc {
    DWORD pid = 0;
    std::wstring name;
    SubprocRole role = SubprocRole::MainOrStandalone;
    ULONGLONG cpu1 = 0;
    SIZE_T wsBefore = 0;
};

PassReport RunOptimizationPass(bool statusOnly, bool forceTrimVisible, bool diagnose = false) {
    PassReport rep;
    WindowEnumerationState winState = InspectWindows();
    rep.fullscreenGameDetected = winState.fullscreenForeignApp;

    DWORD mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return rep;

    std::vector<SampledProc> rawProcs;
    std::map<std::wstring, int> groupCounts;
    std::map<std::wstring, SIZE_T> groupBytes;
    std::set<std::wstring> visibleAppGroups;
    std::wstring fgExeName;

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;
            DWORD sess = 0;
            if (!ProcessIdToSessionId(pe.th32ProcessID, &sess) || sess != mySession) continue;

            std::wstring exeLower = Lower(pe.szExeFile);
            if (IsSystemProtected(exeLower)) continue;
            if (pe.th32ProcessID == winState.fgPid) fgExeName = exeLower;
            if (winState.visiblePids.count(pe.th32ProcessID)) visibleAppGroups.insert(exeLower);

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!h) continue;
            SampledProc sp;
            sp.pid = pe.th32ProcessID;
            sp.name = exeLower;
            sp.cpu1 = QueryCpuTime(h);
            sp.wsBefore = QueryWorkingSet(h);
            CloseHandle(h);

            rawProcs.push_back(sp);
            groupCounts[exeLower]++;
            groupBytes[exeLower] += sp.wsBefore;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    constexpr SIZE_T kMinGroupBytes  = 15ULL * 1024 * 1024;  // 15 MB minimum group footprint
    constexpr SIZE_T kMinSingleBytes = 25ULL * 1024 * 1024;  // 25 MB for single-process apps
    constexpr SIZE_T kReTrimGrowthBytes = 8ULL * 1024 * 1024; // Hysteresis: don't re-trim unless grown by +8 MB

    std::vector<SampledProc> procs;
    for (auto& sp : rawProcs) {
        int cnt = groupCounts[sp.name];
        SIZE_T tot = groupBytes[sp.name];
        bool isExcluded = g_excludedApps.count(sp.name) != 0;
        bool qualifies = isExcluded ||
                         (cnt >= 2 && tot >= kMinGroupBytes) ||
                         (!g_multiProcOnly && tot >= kMinSingleBytes);
        if (!qualifies) continue;
        if (rep.fullscreenGameDetected && sp.name == fgExeName && cnt == 1) continue;

        if ((!statusOnly || diagnose) && cnt >= 2) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sp.pid);
            if (h) {
                sp.role = ClassifySubprocessRole(h, cnt);
                CloseHandle(h);
            }
        }
        procs.push_back(sp);
    }

    if ((statusOnly && !diagnose) || procs.empty()) {
        for (const auto& sp : procs) {
            auto& a = rep.apps[sp.name];
            a.totalProcs++;
            a.beforeBytes += sp.wsBefore;
            a.afterBytes += sp.wsBefore;
        }
        return rep;
    }

    // 1.0-second CPU delta telemetry window
    Sleep(1000);

    ULONGLONG nowTick = GetTickCount64();

    // Identify the single most active renderer/worker per foreground application so only the active tab
    // stays uncompressed while all other background tabs and background app helpers are compressed.
    std::map<DWORD, ULONGLONG> pidDeltas;
    DWORD topForegroundRendererPid = 0;
    ULONGLONG topForegroundRendererDelta = 0;

    for (const auto& sp : procs) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sp.pid);
        if (!h) continue;
        ULONGLONG cpu2 = QueryCpuTime(h);
        CloseHandle(h);
        ULONGLONG delta = cpu2 >= sp.cpu1 ? (cpu2 - sp.cpu1) : 0;
        pidDeltas[sp.pid] = delta;
        if (sp.name == fgExeName && sp.role == SubprocRole::RendererOrWorker && delta > topForegroundRendererDelta) {
            topForegroundRendererDelta = delta;
            topForegroundRendererPid = sp.pid;
        }
    }

        if (diagnose) {
        // Read-only: report the decision each process would get, without changing any process state.
        for (const auto& sp : procs) {
            DiagRow r;
            r.pid = sp.pid;
            r.name = sp.name;
            r.role = sp.role;
            r.isForegroundApp = (sp.name == fgExeName);
            bool fgWindow = (sp.pid == winState.fgPid);
            if (g_excludedApps.count(sp.name)) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: Excluded by user";
            } else if (sp.role == SubprocRole::AudioOrNetwork) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: AudioOrNetwork";
            } else if (fgWindow) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: Foreground window";
            } else if (r.isForegroundApp && sp.role == SubprocRole::MainOrStandalone) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: Foreground main process";
            } else if (r.isForegroundApp && sp.role == SubprocRole::GpuCompositor) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: Foreground GPU Compositor";
            } else if (r.isForegroundApp && sp.pid == topForegroundRendererPid) {
                r.protectedProc = true;
                r.reason = L"PROTECTED: Foreground active renderer";
            } else {
                r.reason = std::wstring(L"ELIGIBLE: Background ") + RoleName(sp.role);
            }
            rep.diag.push_back(r);
        }
        return rep;
    }

    AcquireSRWLockExclusive(&g_histLock);
    for (const auto& sp : procs) {
        auto& a = rep.apps[sp.name];
        a.totalProcs++;
        a.beforeBytes += sp.wsBefore;

        if (g_excludedApps.count(sp.name)) {
            a.afterBytes += sp.wsBefore;
            continue;
        }

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA, FALSE, sp.pid);
        if (!h) {
            a.afterBytes += sp.wsBefore;
            continue;
        }

        ULONGLONG delta = pidDeltas[sp.pid];
        bool isForegroundWindowProc = (sp.pid == winState.fgPid);
        bool isForegroundApp = (sp.name == fgExeName);

        // Protection policy:
        // 1. Audio & Network services (audio.mojom.AudioService / network.mojom.NetworkService) are NEVER throttled.
        // 2. For the currently focused foreground application (isForegroundApp):
        //    - Protect its main UI window process, its GPU compositor, and its #1 active renderer tab.
        // 3. For any application in the background (behind the active window or minimized):
        //    - Compress and enable Efficiency Mode (EcoQoS) across the entire app group (unless a subprocess is
        //      actively compiling/rendering at > 20% single-core CPU), so Task Manager shows Efficiency Mode
        //      and reclaims maximum RAM! When you click/Alt-Tab back to that app, WinEventProc promotes it in < 1 ms.
        bool protectedProc = (sp.role == SubprocRole::AudioOrNetwork) ||
                             isForegroundWindowProc ||
                             (isForegroundApp && sp.role == SubprocRole::MainOrStandalone) ||
                             (isForegroundApp && sp.role == SubprocRole::GpuCompositor) ||
                             (isForegroundApp && sp.pid == topForegroundRendererPid) ||
                             (!forceTrimVisible && delta > 2000000ULL);

        ProcHistory& hist = g_procHistory[sp.pid];
        if (protectedProc) {
            a.activeProcs++;
            if (hist.throttled) {
                SetProcessThrottleState(h, false);
                hist.throttled = false;
            }
        } else {
            // Demote priority + EcoQoS
            if (!hist.throttled) {
                SetProcessThrottleState(h, true);
                hist.throttled = true;
            }
            // Hysteresis: only call EmptyWorkingSet if never trimmed, or if Working Set grew by >= 8 MB since last trim
            bool needsTrim = (hist.lastTrimTick == 0) ||
                             (sp.wsBefore > hist.lastPostTrimBytes + kReTrimGrowthBytes) ||
                             forceTrimVisible;
            if (needsTrim) {
                K32EmptyWorkingSet(h);
                hist.lastTrimTick = nowTick;
                a.trimmedProcs++;
            }
        }
        CloseHandle(h);
    }

    Sleep(200);
    SIZE_T totalBefore = 0, totalAfter = 0;
    for (const auto& sp : procs) {
        if (g_excludedApps.count(sp.name)) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, sp.pid);
        SIZE_T after = sp.wsBefore;
        if (h) {
            after = QueryWorkingSet(h);
            CloseHandle(h);
        }
        if (g_procHistory.count(sp.pid) && g_procHistory[sp.pid].lastTrimTick == nowTick) {
            g_procHistory[sp.pid].lastPostTrimBytes = after;
        }
        rep.apps[sp.name].afterBytes += after;
        totalBefore += sp.wsBefore;
        totalAfter += after;
    }
    ReleaseSRWLockExclusive(&g_histLock);

    if (totalBefore > totalAfter) rep.totalSavedBytes = totalBefore - totalAfter;
    PurgeLowPriorityStandbyIfHighPressure();
    return rep;
}

// Instant un-throttle of the entire process group when the user switches to or restores a window
void PromoteProcessTreeImmediate(DWORD fgPid) {
    if (!fgPid) return;
    HANDLE hFg = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, fgPid);
    std::wstring fgName;
    if (hFg) {
        wchar_t path[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hFg, 0, path, &sz)) {
            const wchar_t* base = wcsrchr(path, L'\\');
            fgName = Lower(base ? base + 1 : path);
        }
        CloseHandle(hFg);
    }
    AcquireSRWLockExclusive(&g_histLock);
    auto it = g_procHistory.find(fgPid);
    if (it != g_procHistory.end() && it->second.throttled) {
        HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, fgPid);
        if (h) {
            SetProcessThrottleState(h, false);
            CloseHandle(h);
        }
        it->second.throttled = false;
    }
    ReleaseSRWLockExclusive(&g_histLock);
}

void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD event, HWND hwnd, LONG idObject, LONG, DWORD, DWORD) {
    if (idObject != OBJID_WINDOW || !hwnd) return;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (event == EVENT_SYSTEM_FOREGROUND || event == EVENT_SYSTEM_MINIMIZEEND) {
        PromoteProcessTreeImmediate(pid);
    } else if (event == EVENT_SYSTEM_MINIMIZESTART) {
        // Trigger a debounced optimization pass 1.5s after any window is minimized
        if (g_hwnd && g_autoOptimize) SetTimer(g_hwnd, TIMER_MINIMIZE_DEBOUNCE, 1500, nullptr);
    }
}

// ---- Tray Icon & UI ---------------------------------------------------------------------------

HICON CreateTrayIcon(int memLoadPct) {
    const int S = GetSystemMetrics(SM_CXSMICON);
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = S;
    bi.bmiHeader.biHeight = -S;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC dc = CreateCompatibleDC(nullptr);
    void* bits = nullptr;
    HBITMAP color = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    auto* px = static_cast<DWORD*>(bits);
    memset(px, 0, (size_t)S * S * 4);

    int pad = std::max(1, S / 8);
    int fillH = std::clamp(memLoadPct, 5, 100) * (S - 2 * pad - 4) / 100;
    int fillTop = S - pad - 2 - fillH;
    for (int y = pad; y < S - pad; y++) {
        for (int x = pad; x < S - pad; x++) {
            bool border = (y == pad || y == S - pad - 1 || x == pad || x == S - pad - 1);
            if (border) {
                px[y * S + x] = 0xFF3A3F45;
            } else if (y >= fillTop && x >= pad + 2 && x < S - pad - 2) {
                px[y * S + x] = 0xFF34D399;  // #34D399 emerald
            } else {
                px[y * S + x] = 0xFF17191C;  // #17191C dark bg
            }
        }
    }
    DeleteDC(dc);

    HBITMAP mask = CreateBitmap(S, S, 1, 1, nullptr);
    ICONINFO ii{ TRUE, 0, 0, mask, color };
    HICON ic = CreateIconIndirect(&ii);
    DeleteObject(mask);
    DeleteObject(color);
    return ic;
}

void UpdateTrayIcon(bool add = false) {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (g_icon) DestroyIcon(g_icon);
    g_icon = CreateTrayIcon((int)ms.dwMemoryLoad);

    NOTIFYICONDATAW nid{ sizeof(nid) };
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = g_icon;
    double usedGB = (ms.ullTotalPhys - ms.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
    double totalGB = ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    swprintf(nid.szTip, ARRAYSIZE(nid.szTip), GetStrings().tooltipFmt,
             usedGB, totalGB, ms.dwMemoryLoad, g_sessionSavedMB);
    Shell_NotifyIconW(add ? NIM_ADD : NIM_MODIFY, &nid);
}

void TrimSelfMemory() {
    HeapCompact(GetProcessHeap(), 0);
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

// ---- Floating Bottom-Right Status Toast Banner ------------------------------------------------

static bool SystemUsesLightTheme() {
    DWORD v = 0, sz = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &v, &sz) != ERROR_SUCCESS)
        return false;  // can't read it -> keep the current dark look
    return v != 0;
}

struct ToastTheme { COLORREF bg, border, dot, title, sub; };

static ToastTheme GetToastTheme() {
    if (SystemUsesLightTheme())
        return { RGB(0xFF, 0xFF, 0xFF), RGB(0xD9, 0xDD, 0xE1), RGB(0x10, 0xB9, 0x81),
                 RGB(0x17, 0x19, 0x1C), RGB(0x5B, 0x63, 0x6B) };
    return { RGB(0x17, 0x19, 0x1C), RGB(0x25, 0x28, 0x2C), RGB(0x34, 0xD3, 0x99),
             RGB(0xF0, 0xF3, 0xF6), RGB(0xA3, 0xA9, 0xB0) };
}

LRESULT CALLBACK ToastWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        int dpi = (int)GetDpiForWindow(h);
        auto S = [&](int v) { return MulDiv(v, dpi, 96); };

        // Card + 1px border, colors from the system theme
        const ToastTheme th = GetToastTheme();
        HBRUSH bg = CreateSolidBrush(th.bg);
        HBRUSH brd = CreateSolidBrush(th.border);
        FillRect(dc, &rc, bg);
        FrameRect(dc, &rc, brd);
        DeleteObject(bg);
        DeleteObject(brd);

        // Emerald indicator dot (#34D399)
        HBRUSH dotBrush = CreateSolidBrush(th.dot);
        HPEN nullPen = (HPEN)GetStockObject(NULL_PEN);
        HGDIOBJ oldB = SelectObject(dc, dotBrush);
        HGDIOBJ oldP = SelectObject(dc, nullPen);
        Ellipse(dc, S(14), S(16), S(24), S(26));
        SelectObject(dc, oldB);
        SelectObject(dc, oldP);
        DeleteObject(dotBrush);

        SetBkMode(dc, TRANSPARENT);
        HFONT fBold = CreateFontW(-S(13), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HFONT fSub  = CreateFontW(-S(12), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HGDIOBJ of = SelectObject(dc, fBold);
        SetTextColor(dc, th.title);
        RECT r1{ S(32), S(11), rc.right - S(12), S(30) };
        DrawTextW(dc, g_toastTitle.c_str(), -1, &r1, DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

        SelectObject(dc, fSub);
        SetTextColor(dc, th.sub);
        RECT r2{ S(32), S(31), rc.right - S(12), rc.bottom - S(8) };
        DrawTextW(dc, g_toastSub.c_str(), -1, &r2, DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

        SelectObject(dc, of);
        DeleteObject(fBold);
        DeleteObject(fSub);
        EndPaint(h, &ps);
        return 0;
    }
    if (msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN) {
        ShowWindow(h, SW_HIDE);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

void ShowStatusToast(const std::wstring& title, const std::wstring& subtitle, UINT durationMs = 4000) {
    g_toastTitle = title;
    g_toastSub = subtitle;
    static bool reg = false;
    if (!reg) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = ToastWndProc;
        wc.hInstance = g_inst;
        wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        wc.lpszClassName = L"TrimFlowToastWnd";
        RegisterClassExW(&wc);
        reg = true;
    }
    int dpi = (int)GetDpiForSystem();
    int w = MulDiv(310, dpi, 96);
    int h = MulDiv(58, dpi, 96);
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int x = work.right - w - MulDiv(16, dpi, 96);
    int y = work.bottom - h - MulDiv(12, dpi, 96);

    if (!g_toastWnd || !IsWindow(g_toastWnd)) {
        g_toastWnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                                     L"TrimFlowToastWnd", L"", WS_POPUP,
                                     x, y, w, h, nullptr, nullptr, g_inst, nullptr);
    }
    SetWindowPos(g_toastWnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    InvalidateRect(g_toastWnd, nullptr, TRUE);
    UpdateWindow(g_toastWnd);
    if (g_hwnd) SetTimer(g_hwnd, TIMER_TOAST_HIDE, durationMs, nullptr);
}

void ShowTrayMenu() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    double usedGB = (ms.ullTotalPhys - ms.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
    double totalGB = ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);

    const UiStrings& str = GetStrings();
    HMENU m = CreatePopupMenu();
    wchar_t header[128];
    swprintf(header, 128, str.menuHeaderFmt,
             usedGB, totalGB, ms.dwMemoryLoad, g_sessionSavedMB);
    AppendMenuW(m, MF_STRING | MF_GRAYED, 0, header);
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(m, MF_STRING, ID_OPTIMIZE_NOW, str.menuOptimizeNow);
    AppendMenuW(m, MF_STRING | (g_autoOptimize ? MF_CHECKED : 0), ID_AUTO_ENABLE, str.menuAutoOptimize);
    {
        HMENU intSub = CreatePopupMenu();
        AppendMenuW(intSub, MF_STRING | (g_intervalSec == 15 ? MF_CHECKED : 0), ID_INTERVAL_15, str.menuInterval15);
        AppendMenuW(intSub, MF_STRING | (g_intervalSec == 30 ? MF_CHECKED : 0), ID_INTERVAL_30, str.menuInterval30);
        AppendMenuW(intSub, MF_STRING | (g_intervalSec == 60 ? MF_CHECKED : 0), ID_INTERVAL_60, str.menuInterval60);
        AppendMenuW(m, MF_POPUP, (UINT_PTR)intSub, str.menuInterval);
    }
    AppendMenuW(m, MF_STRING | (g_protectVisible ? MF_CHECKED : 0), ID_PROTECT_VISIBLE,
                str.menuProtectVisible);
    AppendMenuW(m, MF_STRING | (g_gameBoost ? MF_CHECKED : 0), ID_GAME_BOOST,
                str.menuGameBoost);
    AppendMenuW(m, MF_STRING | (g_multiProcOnly ? MF_CHECKED : 0), ID_MULTI_ONLY,
                str.menuMultiProcOnly);

    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | MF_GRAYED, 0, str.menuDiscoveredHeader);

    struct Entry { std::wstring name; AppSummary sum; };
    std::vector<Entry> sorted;
    for (const auto& [name, sum] : g_lastReport.apps) sorted.push_back({ name, sum });
    for (const auto& ex : g_excludedApps) {
        if (!g_lastReport.apps.count(ex)) sorted.push_back({ ex, {} });
    }
    std::sort(sorted.begin(), sorted.end(), [](const Entry& a, const Entry& b) {
        if (a.sum.afterBytes != b.sum.afterBytes) return a.sum.afterBytes > b.sum.afterBytes;
        return a.name < b.name;
    });

    std::vector<std::wstring> appNames;
    for (const auto& e : sorted) {
        if (appNames.size() >= 25) break;
        bool excluded = g_excludedApps.count(e.name) != 0;
        wchar_t line[128];
        if (e.sum.totalProcs > 0) {
            double mb = e.sum.afterBytes / (1024.0 * 1024.0);
            swprintf(line, 128, str.menuAppFmt,
                     e.name.c_str(), e.sum.totalProcs,
                     e.sum.totalProcs == 1 ? str.procSingular : str.procPlural,
                     mb, excluded ? str.excludedSuffix : L"");
        } else {
            swprintf(line, 128, str.menuAppExcludedFmt, e.name.c_str());
        }
        AppendMenuW(m, MF_STRING | (excluded ? 0 : MF_CHECKED), ID_APP_FIRST + appNames.size(), line);
        appNames.push_back(e.name);
    }

    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (AutostartEnabled() ? MF_CHECKED : 0), ID_AUTOSTART, str.menuAutostart);
    AppendMenuW(m, MF_STRING, ID_EXIT, str.menuExit);

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    UINT cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, nullptr);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);

    switch (cmd) {
        case ID_OPTIMIZE_NOW: SetEvent(g_wakeEvt); break;
        case ID_AUTO_ENABLE:
            g_autoOptimize = !g_autoOptimize;
            SaveBool(L"AutoOptimize", g_autoOptimize);
            break;
        case ID_PROTECT_VISIBLE:
            g_protectVisible = !g_protectVisible;
            SaveBool(L"ProtectVisible", g_protectVisible);
            break;
        case ID_GAME_BOOST:
            g_gameBoost = !g_gameBoost;
            SaveBool(L"GameBoost", g_gameBoost);
            break;
        case ID_MULTI_ONLY:
            g_multiProcOnly = !g_multiProcOnly;
            SaveBool(L"MultiProcOnly", g_multiProcOnly);
            SetEvent(g_wakeEvt);
            break;
        case ID_INTERVAL_15: g_intervalSec = 15; SaveDword(L"IntervalSec", 15); break;
        case ID_INTERVAL_30: g_intervalSec = 30; SaveDword(L"IntervalSec", 30); break;
        case ID_INTERVAL_60: g_intervalSec = 60; SaveDword(L"IntervalSec", 60); break;
        case ID_AUTOSTART:   SetAutostart(!AutostartEnabled()); break;
        case ID_EXIT:        DestroyWindow(g_hwnd); break;
        default:
            if (cmd >= ID_APP_FIRST && cmd < ID_APP_FIRST + appNames.size()) {
                const std::wstring& app = appNames[cmd - ID_APP_FIRST];
                if (!g_excludedApps.erase(app)) g_excludedApps.insert(app);
                SaveExcluded();
                SetEvent(g_wakeEvt);
            }
            break;
    }
    TrimSelfMemory();
}

DWORD WINAPI WorkerThread(LPVOID) {
    HANDLE events[2] = { g_stopEvt, g_wakeEvt };
    for (;;) {
        if (g_autoOptimize) {
            auto* rep = new PassReport(RunOptimizationPass(false, false));
            if (!PostMessageW(g_hwnd, WM_PASS_DONE, 0, reinterpret_cast<LPARAM>(rep))) delete rep;
        }
        TrimSelfMemory();
        DWORD waitMs = std::clamp(g_intervalSec, (DWORD)10, (DWORD)300) * 1000;
        DWORD r = WaitForMultipleObjects(2, events, FALSE, waitMs);
        if (r == WAIT_OBJECT_0) return 0;
        if (r == WAIT_OBJECT_0 + 1 && !g_autoOptimize) {
            auto* rep = new PassReport(RunOptimizationPass(false, false));
            if (!PostMessageW(g_hwnd, WM_PASS_DONE, 0, reinterpret_cast<LPARAM>(rep))) delete rep;
            TrimSelfMemory();
        }
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_PASS_DONE: {
            auto* rep = reinterpret_cast<PassReport*>(lp);
            g_lastReport = *rep;
            double passSavedMB = rep->totalSavedBytes / (1024.0 * 1024.0);
            g_sessionSavedMB += passSavedMB;
            int appCount = (int)rep->apps.size();
            delete rep;
            UpdateTrayIcon(false);
            if (g_firstPassToastPending) {
                g_firstPassToastPending = false;
                const UiStrings& str = GetStrings();
                wchar_t sub[128];
                if (passSavedMB >= 1.0)
                    swprintf(sub, 128, str.toastReclaimedFmt, passSavedMB, appCount);
                else
                    swprintf(sub, 128, str.toastMonitoringFmt, appCount);
                ShowStatusToast(str.toastRunningTitle, sub, 4500);
            }
            TrimSelfMemory();
            return 0;
        }
        case WM_SECOND_LAUNCH: {
            MEMORYSTATUSEX ms{ sizeof(ms) };
            GlobalMemoryStatusEx(&ms);
            double usedGB = (ms.ullTotalPhys - ms.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
            double totalGB = ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
            const UiStrings& str = GetStrings();
            wchar_t sub[128];
            swprintf(sub, 128, str.toastAlreadyRunningFmt,
                     usedGB, totalGB, ms.dwMemoryLoad, g_sessionSavedMB);
            ShowStatusToast(str.toastAlreadyRunningTitle, sub, 4500);
            SetEvent(g_wakeEvt);
            return 0;
        }
        case WM_TRAY:
            if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU) {
                ShowTrayMenu();
            }
            return 0;
        case WM_TIMER:
            if (wp == TIMER_UI) {
                UpdateTrayIcon(false);
                TrimSelfMemory();
            } else if (wp == TIMER_MINIMIZE_DEBOUNCE) {
                KillTimer(h, TIMER_MINIMIZE_DEBOUNCE);
                SetEvent(g_wakeEvt);
            } else if (wp == TIMER_TOAST_HIDE) {
                KillTimer(h, TIMER_TOAST_HIDE);
                if (g_toastWnd && IsWindow(g_toastWnd)) ShowWindow(g_toastWnd, SW_HIDE);
                TrimSelfMemory();
            }
            return 0;
        case WM_DESTROY: {
            if (g_hookFg) UnhookWinEvent(g_hookFg);
            if (g_hookMin) UnhookWinEvent(g_hookMin);
            NOTIFYICONDATAW nid{ sizeof(nid) };
            nid.hWnd = h;
            nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &nid);
            SetEvent(g_stopEvt);
            if (g_worker) WaitForSingleObject(g_worker, 3000);
            RestoreAllThrottledProcesses();
            if (g_icon) DestroyIcon(g_icon);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::string JsonEscape(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); out += b; }
        else out += (char)c;
    }
    return out;
}

int RunCli(bool statusOnly, bool json, bool diagnose = false) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) {
        if (AttachConsole(ATTACH_PARENT_PROCESS))
            out = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    auto print = [&](const char* s) {
        if (!out || out == INVALID_HANDLE_VALUE) return;
        DWORD w = 0;
        WriteFile(out, s, (DWORD)strlen(s), &w, nullptr);
    };

    PassReport rep = RunOptimizationPass(statusOnly, true, diagnose);

        if (diagnose) {
        char dl[320];
        snprintf(dl, sizeof(dl), "%-8s %-28s %-18s %-4s %s\n", "PID", "Executable", "Role", "FG", "Decision");
        print(dl);
        for (const auto& r : rep.diag) {
            snprintf(dl, sizeof(dl), "%-8lu %-28ls %-18ls %-4s %ls\n",
                     (unsigned long)r.pid, r.name.c_str(), RoleName(r.role),
                     r.isForegroundApp ? "yes" : "no", r.reason.c_str());
            print(dl);
        }
        return 0;
    }

    if (json) {
        MEMORYSTATUSEX ms{ sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        double totBef = 0, totAft = 0;
        std::string groups;
        for (const auto& [name, a] : rep.apps) {
            double bef = a.beforeBytes / (1024.0 * 1024.0);
            double aft = a.afterBytes / (1024.0 * 1024.0);
            totBef += bef;
            totAft += aft;
            char buf[160];
            snprintf(buf, sizeof buf, "\",\"processes\":%d,\"trimmed\":%d,\"beforeMB\":%.1f,\"afterMB\":%.1f}",
                     a.totalProcs, a.trimmedProcs, bef, aft);
            if (!groups.empty()) groups += ",";
            groups += "{\"name\":\"" + JsonEscape(ToUtf8(name)) + buf;
        }
        char head[200];
        snprintf(head, sizeof head,
                 "{\"systemMemoryLoadPercent\":%lu,\"totalBeforeMB\":%.1f,\"totalAfterMB\":%.1f,\"reclaimedMB\":%.1f,\"groups\":[",
                 (unsigned long)ms.dwMemoryLoad, totBef, totAft, totBef - totAft);
        std::string json_out = std::string(head) + groups + "]}\n";
        print(json_out.c_str());
        return 0;
    }

    char line[256];
    snprintf(line, sizeof(line), "%-26s %6s %8s %8s %12s %12s %12s\n",
             "Application (Dynamic)", "Procs", "Trimmed", "Active", "Before (MB)", "After (MB)", "Delta (MB)");
    print(line);
    print("--------------------------------------------------------------------------------------------\n");
    double totBef = 0, totAft = 0;
    for (const auto& [name, a] : rep.apps) {
        double bef = a.beforeBytes / (1024.0 * 1024.0);
        double aft = a.afterBytes / (1024.0 * 1024.0);
        totBef += bef;
        totAft += aft;
        snprintf(line, sizeof(line), "%-26ls %6d %8d %8d %11.1fM %11.1fM %+11.1fM\n",
                 name.c_str(), a.totalProcs, a.trimmedProcs, a.activeProcs, bef, aft, aft - bef);
        print(line);
    }
    print("--------------------------------------------------------------------------------------------\n");
    snprintf(line, sizeof(line), "%-26s %6s %8s %8s %11.1fM %11.1fM %+11.1fM\n",
             "TOTAL", "", "", "", totBef, totAft, totAft - totBef);
    print(line);
    return 0;
}



}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR cmdLine, int) {
    g_inst = inst;
    g_autoOptimize   = LoadBool(L"AutoOptimize", true);
    g_protectVisible = LoadBool(L"ProtectVisible", true);
    g_gameBoost      = LoadBool(L"GameBoost", true);
    g_multiProcOnly  = LoadBool(L"MultiProcOnly", false);
    g_intervalSec    = std::clamp(LoadDword(L"IntervalSec", 30), (DWORD)15, (DWORD)60);
    LoadExcluded();

    if (cmdLine && wcsstr(cmdLine, L"--quit")) {
        if (HWND w = FindWindowW(L"TrimFlowTrayWnd", nullptr)) PostMessageW(w, WM_CLOSE, 0, 0);
        return 0;
    }
        bool json = cmdLine && wcsstr(cmdLine, L"--json");    
    if (cmdLine && wcsstr(cmdLine, L"--diagnose")) return RunCli(true, false, true);   
    if (cmdLine && wcsstr(cmdLine, L"--status")) return RunCli(true, json);
    if (cmdLine && wcsstr(cmdLine, L"--once")) return RunCli(false, json);

    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\TrimFlowSingleton");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (HWND w = FindWindowW(L"TrimFlowTrayWnd", nullptr)) {
            PostMessageW(w, WM_SECOND_LAUNCH, 0, 0);
        }
        return 0;
    }

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.lpszClassName = L"TrimFlowTrayWnd";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, kAppName, WS_POPUP,
                             0, 0, 0, 0, nullptr, nullptr, inst, nullptr);
    if (!g_hwnd) return 1;

    // Out-of-context WinEvent hooks for zero-latency window restore/focus promotion & minimize-triggered trim
    g_hookFg  = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, nullptr,
                                WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    g_hookMin = SetWinEventHook(EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND, nullptr,
                                WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    g_wakeEvt = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_stopEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    UpdateTrayIcon(true);
    ShowStatusToast(GetStrings().toastStartedTitle, GetStrings().toastStartedBody, 4000);
    SetTimer(g_hwnd, TIMER_UI, 15000, nullptr);
    g_worker = CreateThread(nullptr, 65536, WorkerThread, nullptr, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    TrimSelfMemory();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    ReleaseMutex(mutex);
    return 0;
}
