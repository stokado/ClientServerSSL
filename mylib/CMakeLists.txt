project ("mylib")

add_library (${PROJECT_NAME} "src/client.cpp" "src/server.cpp" "src/session.cpp")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_include_directories (${PROJECT_NAME}
		PUBLIC
			$<INSTALL_INTERFACE:include>
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
			${Boost_INCLUDE_DIRS}
			${OPENSSL_INCLUDE_DIR}
)

target_link_libraries (${PROJECT_NAME} 
		PRIVATE
			${Boost_LIBRARIES}
			${OPENSSL_LIBRARIES}
			Threads::Threads
)

set_target_properties (${PROJECT_NAME}
		PROPERTIES
			ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/lib"
			LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/lib"
			RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/install/bin"
)