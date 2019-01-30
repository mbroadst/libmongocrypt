cmake_minimum_required(VERSION 3.8)

message(WARNING "Fooo " ${CMAKE_CURRENT_LIST_DIR})

configure_file(lib/lib.csproj lib/lib.csproj COPYONLY)
configure_file(lib/Package.include.template.csproj lib/Package.csproj.include)
