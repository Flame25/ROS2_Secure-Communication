cmake_minimum_required(VERSION 3.8)
project(secure_node)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find build and runtime dependencies
find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(custom_msgs REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(publisher_node src/publisher_node.cpp)
add_executable(subscriber_node src/subscriber_node.cpp)
add_executable(attacker_node src/attacker_node.cpp)

ament_target_dependencies(publisher_node
  rclcpp
  std_msgs
  custom_msgs
  OpenSSL
)

ament_target_dependencies(subscriber_node
  rclcpp
  std_msgs
  custom_msgs
  OpenSSL
)

ament_target_dependencies(attacker_node
  rclcpp
  std_msgs
  custom_msgs
  OpenSSL
)

target_link_libraries(publisher_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)


target_link_libraries(attacker_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)

target_link_libraries(subscriber_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)

install(TARGETS
  publisher_node
  DESTINATION lib/${PROJECT_NAME}
)

install(TARGETS
  attacker_node
  DESTINATION lib/${PROJECT_NAME}
)

install(TARGETS
  subscriber_node
  DESTINATION lib/${PROJECT_NAME}
)

install(DIRECTORY keys/
  DESTINATION share/${PROJECT_NAME}/keys
)

ament_package()
