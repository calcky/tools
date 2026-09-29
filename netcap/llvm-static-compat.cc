#include <llvm/Support/DynamicLibrary.h>

#include <string>

extern "C" llvm::sys::DynamicLibrary
__real__ZN4llvm3sys14DynamicLibrary19getPermanentLibraryEPKcPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    const char *, std::string *);

extern "C" llvm::sys::DynamicLibrary
__wrap__ZN4llvm3sys14DynamicLibrary19getPermanentLibraryEPKcPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    const char *filename, std::string *error) {
  // musl's static dlopen(NULL) fails; BCC's BPF JIT does not need that handle.
  if (filename == nullptr)
    return llvm::sys::DynamicLibrary(reinterpret_cast<void *>(1));
  return __real__ZN4llvm3sys14DynamicLibrary19getPermanentLibraryEPKcPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
      filename, error);
}
