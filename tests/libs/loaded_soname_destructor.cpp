static void (*unload_callback)() = nullptr;

extern "C" void loaded_soname_set_unload_callback(void (*callback)()) {
  unload_callback = callback;
}

__attribute__((destructor)) static void NotifyUnload() {
  if (unload_callback != nullptr) unload_callback();
}
