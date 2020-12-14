// OpenAndPinFile.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <memory>
#include <Windows.h>
#include <handleapi.h>

class BuffImpl
{
    int size;
    char* ptr;

public:
    BuffImpl(int s)
    {
        size = s;
        ptr = (char*)malloc(size);

        if (ptr == NULL)
        {
            size = 0;
        }
        else
        {
            memset(ptr, 0, size);
        }
    }

    ~BuffImpl()
    {
        if (ptr)
        {
            memset(ptr, 0, size);
            free(ptr);
            size = 0;
            ptr = NULL;
        }
    }

    char* getBuffer()
    {
        return ptr;
    }

};

static std::shared_ptr<BuffImpl> oldPriv = NULL;
static HANDLE volumehandle = NULL;
static HANDLE filehandle = NULL;
static int filesize = 4096;
static bool fileAlreadyExists = false;

bool setPrivileges()
{
    HANDLE token = NULL;

    SetLastError(0);
    BOOL tokenResult = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

    if (!tokenResult)
    {
        std::cout << "Failed to open process token.." << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_MANAGE_VOLUME_NAME, &luid))
    {
        std::cout << "Failed to lookup id for desired privilege.." << std::endl;
        CloseHandle(token);
        return false;
    }

    DWORD requiredSize = 0;
    if (!GetTokenInformation(token, TokenPrivileges, NULL, NULL, &requiredSize))
    {
        if (requiredSize > 0)
        {
            std::shared_ptr<BuffImpl> currPrivBuff = std::make_shared<BuffImpl>(requiredSize);
            if (GetTokenInformation(token, TokenPrivileges, (TOKEN_PRIVILEGES*)currPrivBuff->getBuffer(), requiredSize, &requiredSize))
            {
                bool found = false;
                bool enabled = false;
                TOKEN_PRIVILEGES* currPriv = reinterpret_cast<TOKEN_PRIVILEGES*>(currPrivBuff->getBuffer());
                for (unsigned int index = 0; index < currPriv->PrivilegeCount; index++)
                {
                    if (currPriv->Privileges[index].Luid.HighPart == luid.HighPart &&
                        currPriv->Privileges[index].Luid.LowPart == luid.LowPart)
                    {
                        found = true;

                        if (currPriv->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED)
                        {
                            enabled = true;
                        }
                        break;
                    }
                }

                if (!found)
                {
                    std::cout << "Failed to find token.." << std::endl;
                    return false;
                }

                if (!enabled)
                {
                    TOKEN_PRIVILEGES newPriv;
                    newPriv.PrivilegeCount = 1;
                    newPriv.Privileges[0].Luid = luid;
                    newPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    
                    if (!AdjustTokenPrivileges(token, FALSE, &newPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
                    {
                        return false;
                    }

                    oldPriv = currPrivBuff;
                }
            }
            else
            {
                int lastErr = GetLastError();
                std::cout << "Could not get token info... Error: " << lastErr << std::endl;
                return false;
            }
        }
        else
        {
            std::cout << "Something went wrong while setting privileges..." << std::endl;
            return false;
        }
    }
    else
    {
        std::cout << "Could not get token info..." << std::endl;
        return false;
    }

    return true;
}

void restorePrivileges()
{
    if (oldPriv)
    {
        HANDLE token = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            AdjustTokenPrivileges(token, FALSE, (TOKEN_PRIVILEGES*)oldPriv->getBuffer(), 0, NULL, NULL);
            CloseHandle(token);
        }

        oldPriv = NULL;
    }
}

bool openVolumeHandle(const std::string& volumename)
{
    volumehandle = CreateFile(volumename.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    if (volumehandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    return true;
}

bool openFileHandle(const std::string& filename)
{
    filehandle = CreateFile(filename.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_FLAG_NO_BUFFERING,
        NULL);

    if (filehandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    int lastErr = GetLastError();
    if (lastErr == ERROR_ALREADY_EXISTS)
    {
        std::cout << "File already exists.." << std::endl;
        fileAlreadyExists = true;
        return false;
    }

    // Set size
    LARGE_INTEGER size;
    size.QuadPart = filesize;

    if (!SetFilePointerEx(filehandle, size, NULL, FILE_BEGIN))
    {
        return false;
    }

    if (!SetEndOfFile(filehandle))
    {
        return false;
    }

    return true;
}

bool pinFile()
{
    MARK_HANDLE_INFO markInfo;
    markInfo.HandleInfo = MARK_HANDLE_PROTECT_CLUSTERS;
    markInfo.VolumeHandle = volumehandle;
    markInfo.UsnSourceInfo = 0;

    DWORD returned;
    SetLastError(0);

    BOOL result = DeviceIoControl(filehandle,
        FSCTL_MARK_HANDLE,
        &markInfo,
        sizeof(markInfo),
        NULL,
        0,
        &returned,
        NULL);

    if (!result)
    {
        int error = GetLastError();
        std::cout << "System error when pinning. Error val: " << error << std::endl;
        return false;
    }

    return true;
}

void cleanup(const std::string& msg, std::string filename = "")
{
    restorePrivileges();

    if (volumehandle != NULL && volumehandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(volumehandle);
        volumehandle = NULL;
    }
    if (filehandle != NULL && filehandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(filehandle);
        filehandle = NULL;
    }
    if (filename != "" && !fileAlreadyExists)
    {
        std::cout << "Deleting file: " << filename << std::endl;
        DeleteFile(filename.c_str());
    }

    std::cout << msg << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        std::cout << "Specify a filename.." << std::endl;
        return -1;
    }
    if (argc <= 2)
    {
        std::cout << "Specify a volume name." << std::endl;
    }

    std::string filename = argv[1];
    std::string volumename = argv[2];

    // Set the privileges
    if (!setPrivileges())
    {
        cleanup("Setting privileges failed..");
        return -1;
    }

    // Create volume handle
    if (!openVolumeHandle(volumename))
    {
        cleanup("Opening volume failed..");
        return -1;
    }

    if (!openFileHandle(filename))
    {
        cleanup("Opening filename failed", filename);
        return -1;
    }

    if (!pinFile())
    {
        cleanup("Failed to pin file.", filename);
        return -1;
    }

    cleanup("Pinning successful!", filename);
    return 0;
}