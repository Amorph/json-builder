
cmake_minimum_required (VERSION 2.6)
project (json-builder)

add_subdirectory(../json-parser ./json-parser)

set (CMAKE_C_FLAGS "-std=c89 -ansi -pedantic -Wall ${CMAKE_C_FLAGS}")

set (SOURCES ${SOURCES} json-builder.c json-builder.h )

add_library (jsonbuilder ${SOURCES})

set_target_properties (jsonbuilder PROPERTIES VERSION 0.1.0
                                              SOVERSION 0.1)
target_include_directories(jsonbuilder
	PUBLIC ${PROJECT_SOURCE_DIR}/../json-parser/
)

target_link_libraries (jsonbuilder jsonparser ${LIBS})
target_include_directories(jsonbuilder PRIVATE ../json-parser PUBLIC .)

#install (TARGETS jsonbuilder DESTINATION lib)
#install (FILES json-builder.h DESTINATION include)

#project (json-builder)

#add_executable(jsonbuildertest "test/main.cc")
#target_include_directories(jsonbuildertest
#	PUBLIC ${PROJECT_SOURCE_DIR}/../json-parser/
#)
#target_link_libraries(jsonbuildertest jsonbuilder)

