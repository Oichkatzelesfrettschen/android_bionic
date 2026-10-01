#include <dlfcn.h>
#include <gtest/gtest.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "core_shared_libs.h"
#include "dlext_private.h"
#include "gtest_globals.h"

static constexpr const char* kPublicLib = "libnstest_public.so";

static bool InstallPathLookupFilter() {
  // Kill the child if the lookup opens or resolves a filesystem path.
  const sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
#define KILL_PATH_SYSCALL(number) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
      KILL_PATH_SYSCALL(__NR_openat),
#ifdef __NR_open
      KILL_PATH_SYSCALL(__NR_open),
#endif
#ifdef __NR_openat2
      KILL_PATH_SYSCALL(__NR_openat2),
#endif
#ifdef __NR_access
      KILL_PATH_SYSCALL(__NR_access),
#endif
#ifdef __NR_faccessat
      KILL_PATH_SYSCALL(__NR_faccessat),
#endif
#ifdef __NR_faccessat2
      KILL_PATH_SYSCALL(__NR_faccessat2),
#endif
#ifdef __NR_stat
      KILL_PATH_SYSCALL(__NR_stat),
#endif
#ifdef __NR_stat64
      KILL_PATH_SYSCALL(__NR_stat64),
#endif
#ifdef __NR_lstat
      KILL_PATH_SYSCALL(__NR_lstat),
#endif
#ifdef __NR_lstat64
      KILL_PATH_SYSCALL(__NR_lstat64),
#endif
#ifdef __NR_statx
      KILL_PATH_SYSCALL(__NR_statx),
#endif
#ifdef __NR_newfstatat
      KILL_PATH_SYSCALL(__NR_newfstatat),
#endif
#ifdef __NR_fstatat64
      KILL_PATH_SYSCALL(__NR_fstatat64),
#endif
#ifdef __NR_readlink
      KILL_PATH_SYSCALL(__NR_readlink),
#endif
      KILL_PATH_SYSCALL(__NR_readlinkat),
#undef KILL_PATH_SYSCALL
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program = {
      .len = static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0])),
      .filter = const_cast<sock_filter*>(instructions),
  };
  return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
         prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

TEST(dlext, loaded_soname_namespace_and_lifetime) {
  const std::string library_path = GetTestLibRoot() + "/public_namespace_libs/" + kPublicLib;
  android_namespace_t* owner = android_create_namespace(
      "loaded-soname-owner", nullptr, (GetTestLibRoot() + "/public_namespace_libs").c_str(),
      ANDROID_NAMESPACE_TYPE_ISOLATED, GetTestLibRoot().c_str(), nullptr);
  android_namespace_t* observer =
      android_create_namespace("loaded-soname-observer", nullptr, nullptr,
                               ANDROID_NAMESPACE_TYPE_ISOLATED, GetTestLibRoot().c_str(), nullptr);
  ASSERT_NE(nullptr, owner) << dlerror();
  ASSERT_NE(nullptr, observer) << dlerror();
  ASSERT_TRUE(android_link_namespaces(owner, nullptr, kCoreSharedLibs)) << dlerror();
  ASSERT_TRUE(android_link_namespaces(observer, nullptr, kCoreSharedLibs)) << dlerror();
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(kPublicLib, owner));
  android_dlextinfo extinfo = {};
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = owner;
  void* original = android_dlopen_ext(library_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_NE(nullptr, original) << dlerror();
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(kPublicLib, observer));
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(library_path.c_str(), owner));
  ASSERT_TRUE(android_link_namespaces(observer, owner, kPublicLib)) << dlerror();
  void* reference = android_get_loaded_library_by_soname(kPublicLib, observer);
  ASSERT_EQ(original, reference);
  ASSERT_EQ(0, dlclose(original));
  void* retained = android_get_loaded_library_by_soname(kPublicLib, owner);
  ASSERT_EQ(reference, retained);
  auto public_string = static_cast<const char**>(dlsym(retained, "g_public_extern_string"));
  ASSERT_NE(nullptr, public_string) << dlerror();
  ASSERT_STREQ("This string is from public namespace", *public_string);
  ASSERT_EQ(0, dlclose(retained));
  ASSERT_EQ(0, dlclose(reference));
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(kPublicLib, owner));
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(kPublicLib, observer));
  original = android_dlopen_ext(library_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_NE(nullptr, original) << dlerror();
  reference = android_get_loaded_library_by_soname(kPublicLib, observer);
  ASSERT_EQ(original, reference);
  ASSERT_EQ(0, dlclose(reference));
  ASSERT_EQ(0, dlclose(original));
}

TEST(dlext, loaded_soname_avoids_filesystem_lookup) {
  ASSERT_EXIT(([] {
                if (!InstallPathLookupFilter()) _exit(1);
                if (android_get_loaded_library_by_soname("lib-not-loaded.so", nullptr) != nullptr)
                  _exit(2);
                if (android_get_loaded_library_by_soname(nullptr, nullptr) != nullptr) _exit(3);
                if (android_get_loaded_library_by_soname("", nullptr) != nullptr) _exit(4);
                if (android_get_loaded_library_by_soname("/system/lib/libc.so", nullptr) != nullptr)
                  _exit(5);
                void* reference = android_get_loaded_library_by_soname("libc.so", nullptr);
                if (reference == nullptr || dlclose(reference) != 0) _exit(6);
                _exit(0);
              }()),
              ::testing::ExitedWithCode(0), "");
}

TEST(dlext, loaded_soname_filter_detects_path_lookup) {
  ASSERT_EXIT(([] {
                if (!InstallPathLookupFilter()) _exit(1);
                dlopen("lib-not-loaded.so", RTLD_NOW | RTLD_NOLOAD);
                _exit(2);
              }()),
              ::testing::KilledBySignal(SIGSYS), "");
}

TEST(dlext, loaded_soname_preserves_dlerror) {
  ASSERT_EQ(nullptr, dlopen("lib-not-loaded.so", -1));
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname("lib-not-loaded.so", nullptr));
  ASSERT_EQ(nullptr, android_get_loaded_library_by_soname(nullptr, nullptr));
  ASSERT_NE(nullptr, dlerror());
  ASSERT_EQ(nullptr, dlerror());
}

static bool unloading_lookup_executed = false;
static void* unloading_lookup_handle = nullptr;

static void QueryUnloadingInstance() {
  unloading_lookup_executed = true;
  unloading_lookup_handle =
      android_get_loaded_library_by_soname("libloaded_soname_destructor.so", nullptr);
}

TEST(dlext, loaded_soname_ignores_unloading_instance) {
  const std::string path = GetTestLibRoot() + "/libloaded_soname_destructor.so";
  void* owner = dlopen(path.c_str(), RTLD_NOW);
  ASSERT_NE(nullptr, owner) << dlerror();
  using SetUnloadCallback = void (*)(void (*)());
  auto set_callback =
      reinterpret_cast<SetUnloadCallback>(dlsym(owner, "loaded_soname_set_unload_callback"));
  ASSERT_NE(nullptr, set_callback) << dlerror();
  set_callback(QueryUnloadingInstance);
  unloading_lookup_executed = false;
  unloading_lookup_handle = nullptr;
  ASSERT_EQ(0, dlclose(owner));
  EXPECT_TRUE(unloading_lookup_executed);
  EXPECT_EQ(nullptr, unloading_lookup_handle);
  EXPECT_EQ(nullptr,
            android_get_loaded_library_by_soname("libloaded_soname_destructor.so", nullptr));
}
