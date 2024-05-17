#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <map>
#include <future>
#include <chrono>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
// 定义需要的结构和枚举

//由于NtQuerySystemInformation是微软未公开的API，得定义一些用到的结构体来解释内存
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* pNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

// 需要预先定义ObjectNameInformation
#ifndef ObjectNameInformation
#define ObjectNameInformation (OBJECT_INFORMATION_CLASS)1
#endif

// 定义OBJECT_NAME_INFORMATION结构
typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION;
std::string GetHandlePath(HANDLE handle) {
    char buffer[MAX_PATH] = { 0 };
    if (GetFinalPathNameByHandleA(handle, buffer, MAX_PATH, FILE_NAME_NORMALIZED) == 0) {
        return "";
    }
    return buffer;
}

bool IsComPort(const std::string& path) {
    return path.find("\\Device\\Serial") != std::string::npos ||
        path.find("COM") != std::string::npos;
}
bool IsComPort(const std::wstring& path) {
    return path.find(L"\\Device\\Serial") != std::string::npos ||
        path.find(L"\\Device\\VSerial") != std::string::npos;
}

bool quer(void* NtQO, HANDLE processID, HANDLE processHandle, HANDLE Handle)
{

    pNtQueryObject NtQueryObject = (pNtQueryObject)NtQO;
    HANDLE duplicatedHandle = NULL;
    DuplicateHandle(processHandle, (HANDLE)Handle, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
    HANDLE hMapFile = CreateFileMapping(duplicatedHandle, NULL, PAGE_READONLY, 0, 1024, L"TestFileMap");
    if (hMapFile)
    {
        CloseHandle(hMapFile);


    }
    else {
        DWORD eCode = GetLastError();

    }



    BYTE objNameInfo[1024];
    ULONG returnLength = 0;
    //std::wcout << L"ProcessID:" << processID << std::endl;
    NtQueryObject(duplicatedHandle, ObjectNameInformation, &objNameInfo, sizeof(objNameInfo), &returnLength);
    //std::wcout << L"--ProcessID:" << processID << std::endl;
    OBJECT_NAME_INFORMATION* nameInfo = reinterpret_cast<OBJECT_NAME_INFORMATION*>(objNameInfo);
    if (nameInfo->Name.Buffer && (PWSTR)0xcccccccc != nameInfo->Name.Buffer) {
        std::wstring str(nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(WCHAR));
        //std::wcout<<L"ProcessID:"<< (int)processID << L",Handle: " << Handle << L",Handle Name: " << str << std::endl;
        if (IsComPort(str)) {
            wchar_t szProcessName[MAX_PATH] = { 0 };
            DWORD dwSize = MAX_PATH;
            std::wstring processName;
            if (QueryFullProcessImageNameW(processHandle, 0, szProcessName, &dwSize)) {
                // 从完整的进程路径中提取进程名称
                std::wstring fullPath = szProcessName;
                size_t pos = fullPath.find_last_of(L"\\");
                if (pos != std::string::npos) {
                    processName = fullPath.substr(pos + 1);
                }
            }
            std::wcout << L"ProcessName:" << processName << L",Handle: " << Handle << L",Handle Name: " << str << std::endl;
        }
    }

    CloseHandle(duplicatedHandle);
    return true;

}


int main() {
    DWORD pid = 8036;


    // 加载ntdll.dll以访问未公开的API
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");//可以从dll里面取出，也可以#pragma comment(lib, "ntdll.lib")从里面直接用
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    // 获取系统句柄信息
    ULONG length = 0;
    std::vector<BYTE> buffer(0x10000);
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, buffer.data(), buffer.size(), &length);//这个微软并没有给出，网上说的
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.resize(length);
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, buffer.data(), buffer.size(), &length);
    }

    if (!NT_SUCCESS(status)) {
        std::cerr << "请求系统的句柄信息失败" << std::endl;
        return 1;
    }

    SYSTEM_HANDLE_INFORMATION* handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer.data());//



    //std::string content = "";
    std::map<ULONG, std::vector<USHORT>> Hmap;
    // 遍历所有句柄
    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {//遍历所有系统句柄
        SYSTEM_HANDLE& handle = handleInfo->Handles[i];
        Hmap[handle.ProcessId].push_back(handle.Handle);

    }
    std::vector<std::future<bool>> buff;
    for (auto it : Hmap) {
        HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, it.first);//得到一个对应进程可以读取句柄的进程句柄
        if (!processHandle) {
            CloseHandle(processHandle);
            continue;
        }

        for (auto Handle : it.second) {

            auto future = std::async(quer, (void*)NtQueryObject, (HANDLE)it.first, processHandle, (HANDLE)Handle);

            auto status = future.wait_for(std::chrono::seconds(2));
            if (status == std::future_status::ready) {
                // 任务已经完成，可以获取结果
                int result = future.get();

            }
            else if (status == std::future_status::timeout) {
                // 超时处理
                // 可以选择取消任务或者采取其他措施
                std::cout << "超时" << std::endl;
                buff.push_back(std::move(future));
            }
            else {
                // 其他情况，例如异步任务异常结束
                std::cout << "Other error!" << std::endl;
            }

        }
        CloseHandle(processHandle);


    }
    std::cout << "遍历完成" << std::endl;


    return 0;
}
