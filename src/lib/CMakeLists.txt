add_library(fatrace_backend fatrace_backend.c)

target_include_directories(fatrace_backend PUBLIC includes)
set_target_properties(fatrace_backend PROPERTIES PUBLIC_HEADER includes/fatrace_backend.h)

set_target_properties(fatrace_backend PROPERTIES SOVERSION 1)

install(TARGETS fatrace_backend
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        )