#include "precompiled.h"
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0
#endif
#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0
#endif
// Directory holding the metamod shared object (the APK native lib dir) and its
// bare filename. Derived once via dladdr on GiveFnptrsToDll so game DLLs
// shipped beside metamod can be dlopen'd by absolute path on Android, where
// relative config paths do not resolve within the app namespace.
static char g_self_dir[PATH_MAX] = {0};
static bool g_self_init = false;
static void CSysModule_deriveSelfDir()
{
	if (g_self_init) return;
	g_self_init = true;
	Dl_info info;
	if (dladdr((void *)GiveFnptrsToDll, &info) && info.dli_fname) {
		Q_strlcpy(g_self_dir, info.dli_fname);
		char *dir = Q_strrchr(g_self_dir, '/');
		if (dir) *dir = '\0';
	}
}

const module_handle_t CSysModule::INVALID_HANDLE = (module_handle_t)0;

CSysModule::CSysModule() : m_handle(INVALID_HANDLE), m_base(0), m_size(0), m_free(true)
{
}

bool CSysModule::is_opened() const
{
	return m_handle != INVALID_HANDLE;
}

#ifdef _WIN32

module_handle_t CSysModule::load(void *addr)
{
	MEMORY_BASIC_INFORMATION mem;
	if (!VirtualQuery(addr, &mem, sizeof(mem)))
		return INVALID_HANDLE;

	if (mem.State != MEM_COMMIT)
		return INVALID_HANDLE;

	if (!mem.AllocationBase)
		return INVALID_HANDLE;

	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mem.AllocationBase;
	IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((uintptr_t)dos + (uintptr_t)dos->e_lfanew);

	if (pe->Signature != IMAGE_NT_SIGNATURE)
		return INVALID_HANDLE;

	m_free = false;
	m_base = (uintptr_t)mem.AllocationBase;
	m_size = (size_t)pe->OptionalHeader.SizeOfImage;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCTSTR>(addr), &m_handle);
	return m_handle;
}

module_handle_t CSysModule::find(void *addr)
{
	module_handle_t hHandle = INVALID_HANDLE;
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCTSTR>(addr), &hHandle)) {
		return INVALID_HANDLE;
	}

	return hHandle;
}

module_handle_t CSysModule::load(const char *filepath)
{
	if (!m_handle) {
		m_handle = LoadLibrary(filepath);
		if (m_handle) m_free = true;

		MODULEINFO module_info;
		if (GetModuleInformation(GetCurrentProcess(), m_handle, &module_info, sizeof(module_info))) {
			m_base = (uintptr_t)module_info.lpBaseOfDll;
			m_size = module_info.SizeOfImage;
		}
	}

	return m_handle;
}

bool CSysModule::unload()
{
	if (m_handle == INVALID_HANDLE) {
		return false;
	}

	bool ret = true;
	if (m_free) {
		ret = FreeLibrary(m_handle) != ERROR;
	}

	m_handle = INVALID_HANDLE;
	m_base = 0;
	m_size = 0;

	return ret;
}

void *CSysModule::getsym(const char *name) const
{
	return m_handle ? GetProcAddress(m_handle, name) : nullptr;
}
#else

static ElfW(Addr) dlsize(void *base)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Addr) end;

	ehdr = (ElfW(Ehdr) *)base;

	// Find the first program header
	phdr = (ElfW(Phdr)*)((ElfW(Addr))ehdr + ehdr->e_phoff);

	// Find the final PT_LOAD segment's extent
	for (int i = 0; i < ehdr->e_phnum; ++i)
		if (phdr[i].p_type == PT_LOAD)
			end = phdr[i].p_vaddr + phdr[i].p_memsz;

	// The start (virtual) address is always zero, so just return end.
	return end;
}

// Shared by load()/find(): resolve the module an address lives in. The Dl_info
// must start zeroed - bionic leaves it untouched when the address belongs to no
// module, so an uninitialized one hands a garbage path to dlopen() below.
static bool CSysModule_addrInfo(void *addr, Dl_info *info)
{
	*info = Dl_info();
	if (!addr || dladdr(addr, info) == 0 || !info->dli_fname) {
		return false;
	}

	return true;
}

module_handle_t CSysModule::load(void *addr)
{
	Dl_info dlinfo;
	if (!CSysModule_addrInfo(addr, &dlinfo)) {
		return INVALID_HANDLE;
	}

	m_free = false;
	m_base = (uintptr_t)dlinfo.dli_fbase;
	m_size = (size_t)dlsize(dlinfo.dli_fbase);

	m_handle = dlopen(dlinfo.dli_fname, RTLD_NOW | RTLD_NOLOAD);
	return m_handle;
}

module_handle_t CSysModule::find(void *addr)
{
	Dl_info dlinfo;
	if (!CSysModule_addrInfo(addr, &dlinfo)) {
		return INVALID_HANDLE;
	}

	module_handle_t hHandle = dlopen(dlinfo.dli_fname, RTLD_NOW | RTLD_NOLOAD);
	if (!hHandle) {
		return INVALID_HANDLE;
	}

	return hHandle;
}

module_handle_t CSysModule::load(const char *filepath)
{
	if (!m_handle) {
		m_handle = dlopen(filepath, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
		if (m_handle) m_free = true;

		META_CONS("== load: dlopen(%s) -> %s", filepath, m_handle ? "OK" : getloaderror());

		// Android: dlopen only resolves bare library names or absolute paths that
		// live inside the app's trusted native namespace. Relative config paths
		// (e.g. "dlls/libcs_android_arm64.so") will not resolve even though the
		// game DLL sits right beside metamod in the APK native lib dir. On failure,
		// retry by absolute path in that dir.
		if (!m_handle) {
			CSysModule_deriveSelfDir();
			char base[NAME_MAX];
			Q_strlcpy(base, filepath);
			char *cp = Q_strrchr(base, '/');
			if (cp) {
				cp++;
				char full[PATH_MAX];
				if (g_self_dir[0]) {
					Q_sprintf(full, "%s/%s", g_self_dir, cp);
					m_handle = dlopen(full, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
					if (m_handle) m_free = true;
					META_CONS("== load: fallback1(%s) -> %s", full, m_handle ? "OK" : getloaderror());
				}
				if (!m_handle) {
					if (g_self_dir[0]) {
						Q_sprintf(full, "%s/lib%s", g_self_dir, cp);
					} else {
						Q_sprintf(full, "lib%s", cp);
					}
					m_handle = dlopen(full, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
					if (m_handle) m_free = true;
					META_CONS("== load: fallback2(%s) -> %s", full, m_handle ? "OK" : getloaderror());
				}
			}
		}

		char buf[1024], dummy[1024], path[260];
		Q_sprintf(buf, "/proc/%i/maps", getpid());

		FILE* fp = fopen(buf, "r");
		if (fp) {
			while (fgets(buf, sizeof buf, fp)) {
				uintptr_t start, end;

				int args = sscanf(buf, "%lx-%lx %128s %128s %128s %128s %255s", &start, &end, dummy, dummy, dummy, dummy, path);
				if (args != 7) {
					continue;
				}

				if (!Q_stricmp(path, filepath) || (m_handle && (Q_strstr(path, filepath) || Q_strstr(filepath, path)))) {
					m_base = start;
					m_size = end - start;
					break;
				}
			}
			fclose(fp);
		}

		// Prefer the loader's own view of the module: /proc/self/maps stops at
		// the first matching segment, so a plugin whose data lives in a later
		// segment would not be recognized by contain().
		if (m_handle) {
			Dl_info info;
			if (CSysModule_addrInfo(m_handle, &info) && info.dli_fbase) {
				m_base = (uintptr_t)info.dli_fbase;
				m_size = (size_t)dlsize(m_handle);
			}
		}
	}

	return m_handle;
}

bool CSysModule::unload()
{
	if (m_handle == INVALID_HANDLE) {
		return false;
	}

	bool ret = true;
	if (m_free) {
		ret = dlclose(m_handle) == 0;
	}

	m_handle = INVALID_HANDLE;
	m_base = 0;
	m_size = 0;

	return ret;
}

void* CSysModule::getsym(const char *name) const
{
	return m_handle ? dlsym(m_handle, name) : nullptr;
}
#endif

module_handle_t CSysModule::gethandle() const
{
	return m_handle;
}

uintptr_t CSysModule::getbase() const
{
	return m_base;
}

size_t CSysModule::getsize() const
{
	return m_size;
}

bool CSysModule::contain(void *addr) const
{
	return addr && uintptr_t(addr) >= m_base && uintptr_t(addr) < m_base + m_size;
}

const char *CSysModule::getloaderror()
{
#ifdef _WIN32
	static char buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buf, sizeof(buf) - 1, nullptr);
	return buf;
#else
	return dlerror();
#endif
}
