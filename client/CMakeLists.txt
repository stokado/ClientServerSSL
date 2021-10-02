project ("client")

add_executable (${PROJECT_NAME} "main.cpp")

target_include_directories (${PROJECT_NAME}
		PUBLIC
			mylib
)

target_link_libraries (${PROJECT_NAME}
		PUBLIC
			mylib
)

message (STATUS ${CMAKE_SOURCE_DIR})

set_target_properties (${PROJECT_NAME}
		PROPERTIES
			ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/lib"
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/lib"
			RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/bin"
)