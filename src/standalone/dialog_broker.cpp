#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <shobjidl.h>
#include <shellapi.h>

#include <cstdint>
#include <string>
#include <vector>

namespace
{
struct com_scope_t
{
    HRESULT hr = E_FAIL;
    bool uninit = false;

    com_scope_t()
    {
        hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        uninit = (hr == S_OK);
    }

    ~com_scope_t()
    {
        if (uninit)
            CoUninitialize();
    }
};

struct arg_state_t
{
    std::wstring mode;
    std::wstring title;
    std::wstring output;
    std::wstring initial;
    std::wstring filter;
};

std::wstring get_arg_value(int argc, wchar_t** argv, const wchar_t* name)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (_wcsicmp(argv[i], name) == 0)
            return argv[i + 1];
    }
    return {};
}

arg_state_t parse_args(int argc, wchar_t** argv)
{
    arg_state_t args;
    args.mode = get_arg_value(argc, argv, L"--mode");
    args.title = get_arg_value(argc, argv, L"--title");
    args.output = get_arg_value(argc, argv, L"--out");
    args.initial = get_arg_value(argc, argv, L"--initial");
    args.filter = get_arg_value(argc, argv, L"--filter");
    return args;
}

std::vector<std::wstring> split_filter(const std::wstring& filter)
{
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= filter.size()) {
        size_t pos = filter.find(L'|', start);
        if (pos == std::wstring::npos) {
            parts.push_back(filter.substr(start));
            break;
        }
        parts.push_back(filter.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

bool write_utf8_file(const std::wstring& path, const std::wstring& value)
{
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
        return false;
    std::string utf8(static_cast<size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1, utf8.data(),
                            needed, nullptr, nullptr) != needed)
        return false;
    utf8.resize(static_cast<size_t>(needed - 1));
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    CloseHandle(h);
    return ok && written == utf8.size();
}

bool set_initial_folder(IFileDialog* dialog, const std::wstring& initial)
{
    if (!dialog || initial.empty())
        return true;
    IShellItem* item = nullptr;
    HRESULT hr = SHCreateItemFromParsingName(initial.c_str(), nullptr, IID_PPV_ARGS(&item));
    if (FAILED(hr) || !item)
        return false;
    dialog->SetFolder(item);
    item->Release();
    return true;
}

bool set_file_filters(IFileOpenDialog* dialog, const std::wstring& filter)
{
    if (!dialog)
        return false;
    std::vector<std::wstring> parts = split_filter(filter.empty() ? L"All files (*.*)|*.*" : filter);
    std::vector<COMDLG_FILTERSPEC> specs;
    for (size_t i = 0; i + 1 < parts.size(); i += 2) {
        if (!parts[i].empty() && !parts[i + 1].empty())
            specs.push_back(COMDLG_FILTERSPEC{ parts[i].c_str(), parts[i + 1].c_str() });
    }
    if (specs.empty())
        return true;
    HRESULT hr = dialog->SetFileTypes(static_cast<UINT>(specs.size()), specs.data());
    if (FAILED(hr))
        return false;
    dialog->SetFileTypeIndex(1);
    return true;
}

int show_dialog(const arg_state_t& args)
{
    if (args.output.empty())
        return 2;
    com_scope_t com;
    if (FAILED(com.hr))
        return 3;

    IFileOpenDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || !dialog)
        return 4;

    DWORD options = 0;
    hr = dialog->GetOptions(&options);
    if (SUCCEEDED(hr)) {
        options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR;
        if (_wcsicmp(args.mode.c_str(), L"folder") == 0)
            options |= FOS_PICKFOLDERS;
        else
            options |= FOS_FILEMUSTEXIST;
        dialog->SetOptions(options);
    }
    if (!args.title.empty())
        dialog->SetTitle(args.title.c_str());
    if (_wcsicmp(args.mode.c_str(), L"folder") != 0)
        set_file_filters(dialog, args.filter);
    set_initial_folder(dialog, args.initial);

    hr = dialog->Show(nullptr);
    if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        dialog->Release();
        return 1;
    }
    if (FAILED(hr)) {
        dialog->Release();
        return 5;
    }

    IShellItem* result = nullptr;
    hr = dialog->GetResult(&result);
    dialog->Release();
    if (FAILED(hr) || !result)
        return 6;

    PWSTR path = nullptr;
    hr = result->GetDisplayName(SIGDN_FILESYSPATH, &path);
    result->Release();
    if (FAILED(hr) || !path)
        return 7;

    std::wstring selected(path);
    CoTaskMemFree(path);
    if (selected.empty())
        return 8;
    return write_utf8_file(args.output, selected) ? 0 : 9;
}
}

int wmain()
{
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return 10;
    arg_state_t args = parse_args(argc, argv);
    LocalFree(argv);
    if (_wcsicmp(args.mode.c_str(), L"file") != 0 && _wcsicmp(args.mode.c_str(), L"folder") != 0)
        return 11;
    return show_dialog(args);
}
