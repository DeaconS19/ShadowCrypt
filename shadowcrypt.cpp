// shadowcrypt.cpp
// version - v1.18 (REMAKE)

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <random>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <uxtheme.h>

#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "uxtheme.lib")

// GLOBALS
HINSTANCE g_hInst = nullptr;
HWND hwndLog = nullptr;
HWND hwndLoadBtn = nullptr;
HWND hwndCompileBtn = nullptr;
HWND hwndListBox = nullptr;

wchar_t g_szFilePath[MAX_PATH] = { 0 };
std::vector<unsigned char> g_payload;
std::mutex logMutex;
std::atomic<bool> isCompiling(false);

constexpr COLORREF BG_COLOR = RGB(18, 18, 48);
constexpr COLORREF BTN_COLOR = RGB(88, 0, 140);
constexpr COLORREF TXT_COLOR = RGB(220, 220, 255);

// FORWARD DECLARATIONS
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void Log(const std::string& text);
void LoadFile(HWND hwnd);
void CompileCrypter(HWND hwnd);
std::vector<unsigned char> MultiLayerEncrypt(const std::vector<unsigned char>& data);
std::vector<unsigned char> XOR_Encrypt(const std::vector<unsigned char>& data, unsigned char key);
std::string Base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> AES_Encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);
std::vector<unsigned char> GenerateAESKey(size_t length);
void SaveFileDialog(const std::vector<unsigned char>& outputData, const wchar_t* originalExt);
std::string ExtractFileExt(const std::wstring& path);
void AppendLog(const std::string& msg);

// UTILS
std::string ToLower(const std::string& s);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    g_hInst = hInstance;

    const wchar_t CLASS_NAME[] = L"ShadowCryptClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = CreateSolidBrush(BG_COLOR);

    if (!RegisterClass(&wc))
        return 0;

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"SHADOWCRYPT BUILDER",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd)
        return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}

void AppendLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::wstring wmsg(msg.begin(), msg.end());
    SendMessage(hwndListBox, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(wmsg.c_str()));
    SendMessage(hwndListBox, LB_SETCURSEL, SendMessage(hwndListBox, LB_GETCOUNT, 0, 0) - 1, 0);
}

void Log(const std::string& text) {
    AppendLog(text);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        hwndLoadBtn = CreateWindow(L"BUTTON", L"LOAD FILE",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            20, 20, 150, 40, hwnd, reinterpret_cast<HMENU>(1), g_hInst, nullptr);

        hwndCompileBtn = CreateWindow(L"BUTTON", L"COMPILE",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            200, 20, 150, 40, hwnd, reinterpret_cast<HMENU>(2), g_hInst, nullptr);

        hwndListBox = CreateWindow(L"LISTBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_AUTOVSCROLL | WS_BORDER,
            20, 80, 550, 280, hwnd, nullptr, g_hInst, nullptr);

        SetWindowTheme(hwndListBox, L"Explorer", nullptr);

        // Owner-draw buttons for custom colors
        SetWindowLongPtr(hwndLoadBtn, GWL_STYLE,
            GetWindowLongPtr(hwndLoadBtn, GWL_STYLE) | BS_OWNERDRAW);
        SetWindowLongPtr(hwndCompileBtn, GWL_STYLE,
            GetWindowLongPtr(hwndCompileBtn, GWL_STYLE) | BS_OWNERDRAW);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            if (isCompiling.load()) {
                MessageBox(hwnd, L"Already compiling, wait for it to finish.", L"Busy", MB_OK | MB_ICONEXCLAMATION);
                break;
            }
            LoadFile(hwnd);
        }
        else if (LOWORD(wParam) == 2) {
            if (isCompiling.load()) {
                MessageBox(hwnd, L"Already compiling, wait for it to finish.", L"Busy", MB_OK | MB_ICONEXCLAMATION);
                break;
            }
            if (g_payload.empty()) {
                MessageBox(hwnd, L"Load a file first.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            isCompiling.store(true);
            std::thread(CompileCrypter, hwnd).detach();
        }
        break;

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT pdis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);
        if (pdis->CtlID == 1 || pdis->CtlID == 2) {
            HBRUSH hBrush = CreateSolidBrush(BTN_COLOR);
            FillRect(pdis->hDC, &pdis->rcItem, hBrush);
            SetTextColor(pdis->hDC, TXT_COLOR);
            SetBkMode(pdis->hDC, TRANSPARENT);

            wchar_t text[64];
            GetWindowText(pdis->hwndItem, text, _countof(text));

            DrawText(pdis->hDC, text, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(hBrush);
            return TRUE;
        }
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void LoadFile(HWND hwnd) {
    OPENFILENAME ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Executable & Scripts\0*.exe;*.sys;*.bin;*.ps1;*.bat\0All Files\0*.*\0";
    ofn.lpstrFile = g_szFilePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        std::ifstream file(g_szFilePath, std::ios::binary);
        if (!file) {
            MessageBox(hwnd, L"Failed to open file.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        g_payload.assign(std::istreambuf_iterator<char>(file), {});
        Log("Loaded file: " + std::string(g_szFilePath, g_szFilePath + wcslen(g_szFilePath)));
    }
}

void CompileCrypter(HWND hwnd) {
    Log("Starting compilation...");
    try {
        auto encryptedPayload = MultiLayerEncrypt(g_payload);
        Log("Encryption complete.");

        auto ext = ExtractFileExt(g_szFilePath);
        std::wstring wExt(ext.begin(), ext.end());
        SaveFileDialog(encryptedPayload, wExt.c_str());

        Log("Compilation finished.");
    }
    catch (...) {
        Log("Error during compilation.");
        MessageBox(hwnd, L"An error occurred during compilation.", L"Error", MB_OK | MB_ICONERROR);
    }
    isCompiling.store(false);
}

std::vector<unsigned char> MultiLayerEncrypt(const std::vector<unsigned char>& data) {
    Log("Applying multi-layer encryption...");

    // layer 1: xor encryption with randomized key
    std::random_device rd;
    unsigned char xorKey = static_cast<unsigned char>(rd() % 256);
    Log("XOR Key: " + std::to_string(xorKey));

    auto layer1 = XOR_Encrypt(data, xorKey);
    Log("XOR encryption done.");

    // Layer 2: base 64 encode
    std::string base64Str = Base64Encode(layer1);
    Log("Base64 encoding done.");

    // Layer 3: AES XOR encryption with randomized key
    auto aesKey = GenerateAESKey(16);
    Log("AES key generated.");

    std::vector<unsigned char> base64Data(base64Str.begin(), base64Str.end());
    auto encrypted = AES_Encrypt(base64Data, aesKey);
    Log("AES encryption done.");

    // TODO: store AES keys to a file

    return encrypted;
}

std::vector<unsigned char> XOR_Encrypt(const std::vector<unsigned char>& data, unsigned char key) {
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key;
    }
    return result;
}

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string Base64Encode(const std::vector<unsigned char>& data) {
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t pos = 0;
    size_t in_len = data.size();

    while (in_len--) {
        char_array_3[i++] = data[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::vector<unsigned char> GenerateAESKey(size_t length) {
    std::vector<unsigned char> key(length);
    std::random_device rd;
    for (size_t i = 0; i < length; ++i) {
        key[i] = static_cast<unsigned char>(rd() % 256);
    }
    return key;
}

// TODO: improve this AES encryption function
std::vector<unsigned char> AES_Encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> encrypted(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        encrypted[i] = data[i] ^ key[i % key.size()];
    }
    return encrypted;
}

std::string ExtractFileExt(const std::wstring& path) {
    size_t pos = path.find_last_of(L'.');
    if (pos == std::wstring::npos) return "";
    std::wstring ext = path.substr(pos + 1);
    return std::string(ext.begin(), ext.end());
}

void SaveFileDialog(const std::vector<unsigned char>& outputData, const wchar_t* originalExt) {
    wchar_t szSavePath[MAX_PATH] = { 0 };

    OPENFILENAME ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szSavePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"exe";

    if (GetSaveFileName(&ofn)) {
        std::ofstream outFile(szSavePath, std::ios::binary);
        if (outFile) {
            outFile.write(reinterpret_cast<const char*>(outputData.data()), outputData.size());
            outFile.close();
            Log("File saved successfully.");
        }
        else {
            MessageBox(nullptr, L"Failed to save file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

std::string ToLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}
