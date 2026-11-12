/* Benign activity is confined to the process and windows created by this lab. */
#define COBJMACROS
#include <windows.h>
#include <oleacc.h>
#include <stdint.h>
#include <strsafe.h>

static const COLORREF color = RGB(19, 83, 147);
static volatile LONG handled_exception;

static LONG exception_filter(DWORD code) {
    if (code != 0xe0420801u) return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&handled_exception);
    return EXCEPTION_EXECUTE_HANDLER;
}

static BOOL check_seh(void) {
    __try {
        RaiseException(0xe0420801u, 0, 0, NULL);
    } __except (exception_filter(GetExceptionCode())) {
        return handled_exception == 1;
    }
    return FALSE;
}

static LRESULT CALLBACK paint_fixture(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_PRINT || message == WM_PRINTCLIENT) {
        RECT area;
        HBRUSH brush = CreateSolidBrush(color);
        BOOL result = brush != NULL && GetClientRect(window, &area) &&
            FillRect((HDC)wparam, &area, brush) != 0;
        if (brush != NULL) DeleteObject(brush);
        return result;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static BOOL capture(HWND window) {
    HDC memory = CreateCompatibleDC(NULL);
    BITMAPINFO image = {0};
    image.bmiHeader.biSize = sizeof(image.bmiHeader);
    image.bmiHeader.biWidth = 16;
    image.bmiHeader.biHeight = -16;
    image.bmiHeader.biPlanes = 1;
    image.bmiHeader.biBitCount = 32;
    void *pixels = NULL;
    HBITMAP bitmap = memory != NULL ?
        CreateDIBSection(memory, &image, DIB_RGB_COLORS, &pixels, NULL, 0) : NULL;
    HGDIOBJ previous = bitmap != NULL ? SelectObject(memory, bitmap) : NULL;
    BOOL result = previous != NULL && previous != HGDI_ERROR &&
        SendMessageW(window, WM_PRINTCLIENT, (WPARAM)memory, PRF_CLIENT) != 0 && GetPixel(memory, 8, 8) == color;
    if (previous != NULL && previous != HGDI_ERROR) SelectObject(memory, previous);
    if (bitmap != NULL) DeleteObject(bitmap);
    if (memory != NULL) DeleteDC(memory);
    return result;
}

static BOOL accessibility(HWND window) {
    HWND button = CreateWindowExW(0, L"BUTTON", L"vmkek lab button", WS_CHILD | BS_PUSHBUTTON,
        0, 0, 16, 16, window, NULL, GetModuleHandleW(NULL), NULL);
    IAccessible *accessible = NULL;
    VARIANT child = {0};
    child.vt = VT_I4;
    child.lVal = CHILDID_SELF;
    BSTR name = NULL;
    BOOL result = button != NULL &&
        SUCCEEDED(AccessibleObjectFromWindow(button, (DWORD)OBJID_CLIENT, &IID_IAccessible,
                                             (void **)&accessible)) && accessible != NULL &&
        SUCCEEDED(IAccessible_get_accName(accessible, child, &name)) &&
        name != NULL && wcscmp(name, L"vmkek lab button") == 0;
    SysFreeString(name);
    if (accessible != NULL) IAccessible_Release(accessible);
    if (button != NULL) DestroyWindow(button);
    return result;
}

static BOOL window_activity(BOOL use_capture) {
    HINSTANCE instance = GetModuleHandleW(NULL);
    const wchar_t name[] = L"vmkek-a08-owned-window";
    WNDCLASSW window_class = {0};
    window_class.lpfnWndProc = paint_fixture;
    window_class.hInstance = instance;
    window_class.lpszClassName = name;
    if (!RegisterClassW(&window_class)) return FALSE;
    HWND window = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, name, name, WS_POPUP,
        0, 0, 16, 16, NULL, NULL, instance, NULL);
    BOOL result = window != NULL && (use_capture ? capture(window) : accessibility(window));
    if (window != NULL) DestroyWindow(window);
    UnregisterClassW(name, instance);
    return result;
}

static BOOL overlay(void) {
    HWND window = CreateWindowExW(WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        L"STATIC", L"vmkek-a08-owned-overlay", WS_POPUP, 0, 0, 16, 16,
        NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (window == NULL) return FALSE;
    BYTE alpha = 0;
    DWORD flags = 0;
    BOOL result = SetLayeredWindowAttributes(window, 0, 180, LWA_ALPHA) &&
        GetLayeredWindowAttributes(window, NULL, &alpha, &flags) &&
        alpha == 180 && flags == LWA_ALPHA;
    DestroyWindow(window);
    return result;
}

__declspec(dllexport) DWORD WINAPI compatibility_activity(DWORD scenario) {
    switch (scenario) {
        case 1: return window_activity(FALSE);
        case 2: return window_activity(TRUE);
        case 3: return overlay();
        case 4: return check_seh();
        case 5: {
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {0};
            policy.ProhibitDynamicCode = 1;
            return SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy));
        }
        default: return FALSE;
    }
}
