cmake_minimum_required(VERSION 3.8)
project(custom_nodes)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# find dependencies
find_package(ament_cmake REQUIRED)
find_package(std_msgs REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(custom_msgs REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(px4_msgs REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(setpoint_node src/setpoint_node.cpp)
add_executable(control_node src/control_node.cpp) 
add_executable(attacker_node src/attacker_node.cpp) 
add_executable(offboard_node src/offboard_node.cpp)

ament_target_dependencies(setpoint_node
  rclcpp
  std_msgs
  px4_msgs
  custom_msgs
  OpenSSL
)

ament_target_dependencies(control_node
  rclcpp
  std_msgs
  px4_msgs
  custom_msgs
  OpenSSL
)

ament_target_dependencies(attacker_node
  rclcpp
  std_msgs
  px4_msgs
  custom_msgs
  OpenSSL
)

ament_target_dependencies(offboard_node
  rclcpp
  std_msgs
  px4_msgs
)

target_link_libraries(setpoint_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)


target_link_libraries(control_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)

target_link_libraries(attacker_node
  OpenSSL::SSL
  OpenSSL::Crypto 
)


target_link_libraries(offboard_node)

install(TARGETS
  setpoint_node
  DESTINATION lib/${PROJECT_NAME}
)

install(TARGETS
  offboard_node
  DESTINATION lib/${PROJECT_NAME}
)

install(TARGETS
  control_node
  DESTINATION lib/${PROJECT_NAME}
)

install(TARGETS
  attacker_node
  DESTINATION lib/${PROJECT_NAME}
)

install(DIRECTORY keys/
  DESTINATION share/${PROJECT_NAME}/keys
)

ament_package()
