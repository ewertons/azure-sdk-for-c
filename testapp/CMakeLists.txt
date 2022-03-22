cmake_minimum_required (VERSION 3.10)
	project (testapp LANGUAGES C)
	set(CMAKE_C_STANDARD 99)
	
	add_executable (testapp
	  ${CMAKE_CURRENT_LIST_DIR}/main.c
	)
	
	target_link_libraries(testapp
	  PUBLIC
	    az::iot::hub
	    az::iot::provisioning
)
