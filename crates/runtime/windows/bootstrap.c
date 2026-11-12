#include "bootstrap.h"

#include <appmodel.h>
#include <bcrypt.h>
#include <string.h>
#include <wchar.h>

#define VMK_DLL_MAX (64u * 1024u * 1024u)
#define VMK_METADATA_SIZE 60u
#define VMK_SIGNATURE_SIZE 64u
#define VMK_ENVELOPE_SIZE (VMK_METADATA_SIZE + VMK_SIGNATURE_SIZE)
#define VMK_MAX_ANCESTORS MAX_PATH

static SRWLOCK loader_guard = SRWLOCK_INIT;

static const uint8_t magic[8] = {'V', 'M', 'K', 'D', 'L', 'L', '1', 0};
static const uint8_t domain[] = "vmkek.runtime.v1.windows-dll-signature";

static uint16_t read_u16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | (uint16_t)bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t read_u64(const uint8_t *bytes) {
    return read_u32(bytes) | (uint64_t)read_u32(bytes + 4) << 32;
}

static int local_directory(const wchar_t *path) {
    wchar_t full[MAX_PATH];
    DWORD length = GetFullPathNameW(path, MAX_PATH, full, NULL);
    return length > 3 && length < MAX_PATH && full[1] == L':' && full[2] == L'\\' &&
           full[length - 1] != L'\\' && wcschr(full + 2, L':') == NULL &&
           wcscmp(path, full) == 0 && GetDriveTypeW((wchar_t[]){full[0], L':', L'\\', 0}) == DRIVE_FIXED;
}

static HANDLE pinned_path(const wchar_t *path, int directory) {
    DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if (directory) {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, flags, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return file;
    }
    BY_HANDLE_FILE_INFORMATION attributes;
    wchar_t final_path[MAX_PATH + 4];
    DWORD length = GetFinalPathNameByHandleW(file, final_path, MAX_PATH + 4, FILE_NAME_NORMALIZED);
    if (GetFileType(file) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file, &attributes) ||
        (!directory && attributes.nNumberOfLinks != 1) ||
        (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        length <= 4 || length >= MAX_PATH + 4 ||
        wcsncmp(final_path, L"\\\\?\\", 4) != 0 || _wcsicmp(final_path + 4, path) != 0) {
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    return file;
}

typedef struct PinnedDirectories {
    HANDLE handles[VMK_MAX_ANCESTORS];
    size_t used;
} PinnedDirectories;

static void close_directories(PinnedDirectories *pins) {
    while (pins->used != 0) {
        CloseHandle(pins->handles[--pins->used]);
    }
}

static int pin_directories(const wchar_t *directory, PinnedDirectories *pins) {
    wchar_t path[MAX_PATH];
    if (wcscpy_s(path, MAX_PATH, directory) != 0) {
        return 0;
    }
    for (size_t index = 3;; ++index) {
        wchar_t separator = path[index];
        if (separator != L'\\' && separator != 0) {
            continue;
        }
        if (pins->used == VMK_MAX_ANCESTORS) {
            return 0;
        }
        path[index] = 0;
        HANDLE file = pinned_path(path, 1);
        path[index] = separator;
        if (file == INVALID_HANDLE_VALUE) {
            return 0;
        }
        pins->handles[pins->used++] = file;
        if (separator == 0) {
            return 1;
        }
    }
}

static int append_path(wchar_t out[MAX_PATH], const wchar_t *base, const wchar_t *suffix) {
    size_t left = wcslen(base);
    size_t right = wcslen(suffix);
    if (left >= MAX_PATH || right >= MAX_PATH - left) {
        return 0;
    }
    memcpy(out, base, left * sizeof(*out));
    memcpy(out + left, suffix, (right + 1) * sizeof(*out));
    return 1;
}

static HANDLE pin_launcher(PinnedDirectories *pins) {
    UINT32 package_name_length = 0;
    if (GetCurrentPackageFullName(&package_name_length, NULL) != APPMODEL_ERROR_NO_PACKAGE) {
        return INVALID_HANDLE_VALUE;
    }
    wchar_t executable[MAX_PATH];
    wchar_t directory[MAX_PATH];
    wchar_t marker[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || wcscpy_s(directory, MAX_PATH, executable) != 0) {
        return INVALID_HANDLE_VALUE;
    }
    wchar_t *separator = wcsrchr(directory, L'\\');
    if (!separator || separator <= directory + 2) {
        return INVALID_HANDLE_VALUE;
    }
    *separator = 0;
    if (!local_directory(directory) || !pin_directories(directory, pins)) {
        return INVALID_HANDLE_VALUE;
    }
    HANDLE launcher = pinned_path(executable, 0);
    if (launcher == INVALID_HANDLE_VALUE) {
        return launcher;
    }
    // A .local file or directory can override even a fully qualified DLL path.
    if (!append_path(marker, executable, L".local") ||
        GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_FILE_NOT_FOUND) {
        CloseHandle(launcher);
        return INVALID_HANDLE_VALUE;
    }
    return launcher;
}

static int read_at(HANDLE file, uint64_t offset, uint8_t *buffer, DWORD count) {
    LARGE_INTEGER position;
    position.QuadPart = (LONGLONG)offset;
    DWORD actual = 0;
    return SetFilePointerEx(file, position, NULL, FILE_BEGIN) &&
           ReadFile(file, buffer, count, &actual, NULL) && actual == count;
}

static int is_x64_dll(HANDLE file, uint64_t length) {
    uint8_t dos[64];
    uint8_t pe[26];
    if (length < sizeof(dos) + sizeof(pe) || !read_at(file, 0, dos, sizeof(dos)) ||
        dos[0] != 'M' || dos[1] != 'Z') {
        return 0;
    }
    uint32_t offset = read_u32(dos + 60);
    if (offset < sizeof(dos) || (uint64_t)offset + sizeof(pe) > length ||
        !read_at(file, offset, pe, sizeof(pe))) {
        return 0;
    }
    uint16_t sections = read_u16(pe + 6);
    uint16_t optional = read_u16(pe + 20);
    uint64_t headers_end = (uint64_t)offset + 24 + optional + (uint64_t)sections * IMAGE_SIZEOF_SECTION_HEADER;
    return memcmp(pe, "PE\0\0", 4) == 0 &&
           read_u16(pe + 4) == IMAGE_FILE_MACHINE_AMD64 && sections != 0 &&
           (read_u16(pe + 22) & IMAGE_FILE_DLL) != 0 && optional >= 112 &&
           read_u16(pe + 24) == IMAGE_NT_OPTIONAL_HDR64_MAGIC && headers_end <= length;
}

static int read_envelope(HANDLE file, uint8_t bytes[VMK_ENVELOPE_SIZE]) {
    LARGE_INTEGER size;
    DWORD read = 0;
    return GetFileSizeEx(file, &size) && size.QuadPart == VMK_ENVELOPE_SIZE &&
           ReadFile(file, bytes, VMK_ENVELOPE_SIZE, &read, NULL) && read == VMK_ENVELOPE_SIZE;
}

static int hash_image(HANDLE file, uint64_t expected, uint8_t digest[32]) {
    BCRYPT_HASH_HANDLE hash = NULL;
    LARGE_INTEGER size;
    if (expected == 0 || expected > VMK_DLL_MAX || !GetFileSizeEx(file, &size) ||
        size.QuadPart < 0 || (uint64_t)size.QuadPart != expected ||
        BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, NULL, 0, NULL, 0, 0) < 0) {
        return 0;
    }
    uint8_t buffer[8192];
    int ok = 1;
    for (uint64_t remaining = expected; remaining != 0;) {
        DWORD read = 0;
        DWORD amount = remaining < sizeof(buffer) ? (DWORD)remaining : (DWORD)sizeof(buffer);
        if (!ReadFile(file, buffer, amount, &read, NULL) || read != amount ||
            BCryptHashData(hash, buffer, read, 0) < 0) {
            ok = 0;
            break;
        }
        remaining -= read;
    }
    ok = ok && BCryptFinishHash(hash, digest, 32, 0) >= 0;
    BCryptDestroyHash(hash);
    return ok;
}

static int verify_metadata(uint8_t envelope[VMK_ENVELOPE_SIZE], const uint8_t pin[65]) {
    if (pin[0] != 4) {
        return 0;
    }
    struct {
        BCRYPT_ECCKEY_BLOB header;
        uint8_t coordinates[64];
    } blob = {{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32}, {0}};
    memcpy(blob.coordinates, pin + 1, sizeof(blob.coordinates));
    BCRYPT_KEY_HANDLE key = NULL;
    if (BCryptImportKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, NULL, BCRYPT_ECCPUBLIC_BLOB,
                            &key, (uint8_t *)&blob, sizeof(blob), 0) < 0) {
        return 0;
    }
    uint8_t message[sizeof(domain) + VMK_METADATA_SIZE];
    memcpy(message, domain, sizeof(domain));
    memcpy(message + sizeof(domain), envelope, VMK_METADATA_SIZE);
    uint8_t digest[32];
    int ok = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, message, sizeof(message),
                        digest, sizeof(digest)) >= 0 &&
             BCryptVerifySignature(key, NULL, digest, sizeof(digest),
                                   envelope + VMK_METADATA_SIZE, VMK_SIGNATURE_SIZE, 0) >= 0;
    BCryptDestroyKey(key);
    return ok;
}

static int resolve(HMODULE image, const char *name, void *output) {
    FARPROC address = GetProcAddress(image, name);
    if (address == NULL) {
        return 0;
    }
    MEMORY_BASIC_INFORMATION region;
    if (VirtualQuery((const void *)address, &region, sizeof(region)) != sizeof(region) ||
        region.AllocationBase != image || region.Type != MEM_IMAGE ||
        (region.Protect != PAGE_EXECUTE && region.Protect != PAGE_EXECUTE_READ)) {
        return 0;
    }
    memcpy(output, &address, sizeof(address));
    return 1;
}

static VmkStatus verified_image(HANDLE file, HANDLE signature, const uint8_t pin[65],
                                uint32_t abi) {
    uint8_t envelope[VMK_ENVELOPE_SIZE];
    if (!read_envelope(signature, envelope) || memcmp(envelope, magic, sizeof(magic)) != 0 ||
        read_u16(envelope + 8) != 1 || read_u16(envelope + 10) != IMAGE_FILE_MACHINE_AMD64 ||
        !verify_metadata(envelope, pin)) {
        return VMK_INVALID_PACKAGE;
    }
    uint32_t minimum = read_u32(envelope + 12);
    uint32_t maximum = read_u32(envelope + 16);
    if (minimum == 0 || minimum > maximum || abi < minimum || abi > maximum) {
        return VMK_INCOMPATIBLE;
    }
    uint8_t digest[32];
    uint64_t length = read_u64(envelope + 20);
    if (!hash_image(file, length, digest) ||
        memcmp(digest, envelope + 28, sizeof(digest)) != 0 || !is_x64_dll(file, length)) {
        return VMK_INVALID_PACKAGE;
    }
    return VMK_OK;
}

static int same_file(HANDLE left, HANDLE right) {
    FILE_ID_INFO a;
    FILE_ID_INFO b;
    return GetFileInformationByHandleEx(left, FileIdInfo, &a, sizeof(a)) &&
           GetFileInformationByHandleEx(right, FileIdInfo, &b, sizeof(b)) &&
           a.VolumeSerialNumber == b.VolumeSerialNumber &&
           memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier)) == 0;
}

static int mapped_image(HMODULE image, const wchar_t *path, HANDLE pin) {
    wchar_t actual[MAX_PATH];
    DWORD length = GetModuleFileNameW(image, actual, MAX_PATH);
    if (length == 0 || length >= MAX_PATH || _wcsicmp(path, actual) != 0) {
        return 0;
    }
    HANDLE loaded = pinned_path(actual, 0);
    if (loaded == INVALID_HANDLE_VALUE) {
        return 0;
    }
    int ok = same_file(pin, loaded);
    CloseHandle(loaded);
    return ok;
}

static VmkStatus load_runtime(const wchar_t *path, HANDLE file, VmkWindowsRuntime *runtime) {
    if (GetModuleHandleW(L"vmkek_runtime.dll") != NULL) {
        return VMK_DENIED;
    }
    runtime->image = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!runtime->image || !mapped_image(runtime->image, path, file) ||
        !resolve(runtime->image, "vmk_initialize", &runtime->initialize) ||
        !resolve(runtime->image, "vmk_invoke", &runtime->invoke) ||
        !resolve(runtime->image, "vmk_cancel", &runtime->cancel) ||
        !resolve(runtime->image, "vmk_shutdown", &runtime->shutdown)) {
        vmk_windows_close(runtime);
        return VMK_INCOMPATIBLE;
    }
    runtime->image_pin = file;
    return VMK_OK;
}

VmkStatus vmk_windows_open(const wchar_t *directory, const uint8_t manufacturer[65],
                           uint32_t initialize_abi, VmkWindowsRuntime *out) {
    if (!directory || !manufacturer || !out || !local_directory(directory)) {
        return VMK_INVALID_ARGUMENT;
    }
    if (initialize_abi != VMK_ABI_VERSION && initialize_abi != VMK_ONLINE_ABI_VERSION) {
        return VMK_INCOMPATIBLE;
    }
    wchar_t image_path[MAX_PATH];
    wchar_t signature_path[MAX_PATH];
    if (!append_path(image_path, directory, L"\\vmkek_runtime.dll") ||
        !append_path(signature_path, directory, L"\\vmkek_runtime.dll.sig")) {
        return VMK_INVALID_ARGUMENT;
    }
    PinnedDirectories pins = {0};
    if (!pin_directories(directory, &pins)) {
        close_directories(&pins);
        return VMK_UNAVAILABLE;
    }
    HANDLE file = pinned_path(image_path, 0);
    HANDLE signature = pinned_path(signature_path, 0);
    VmkWindowsRuntime runtime = {0};
    VmkStatus status = VMK_UNAVAILABLE;
    if (file != INVALID_HANDLE_VALUE && signature != INVALID_HANDLE_VALUE) {
        status = verified_image(file, signature, manufacturer, initialize_abi);
    }
    if (status == VMK_OK) {
        AcquireSRWLockExclusive(&loader_guard);
        HANDLE launcher = pin_launcher(&pins);
        if (launcher == INVALID_HANDLE_VALUE) {
            status = VMK_DENIED;
        } else {
            status = load_runtime(image_path, file, &runtime);
            CloseHandle(launcher);
        }
        ReleaseSRWLockExclusive(&loader_guard);
    }
    if (signature != INVALID_HANDLE_VALUE) {
        CloseHandle(signature);
    }
    if (status != VMK_OK && file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    close_directories(&pins);
    if (status == VMK_OK) {
        *out = runtime;
    }
    return status;
}

void vmk_windows_close(VmkWindowsRuntime *runtime) {
    if (runtime && runtime->image) {
        FreeLibrary(runtime->image);
        if (runtime->image_pin) {
            CloseHandle(runtime->image_pin);
        }
        memset(runtime, 0, sizeof(*runtime));
    }
}
