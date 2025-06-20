/**
 * @brief Offboard Mode Spammer Node
 *
 * This node continuously sends PX4 VehicleCommand messages to:
 * - Set the flight mode to OFFBOARD
 * - Arm the vehicle
 *
 * This is required by PX4 to remain in OFFBOARD mode via ROS 2 / DDS bridge
 * (px4_ros_com).
 */

#include <chrono>
#include <px4_msgs/msg/offboard_control_mode.hpp>
#include <px4_msgs/msg/trajectory_setpoint.hpp>
#include <px4_msgs/msg/vehicle_command.hpp>
#include <px4_msgs/msg/vehicle_local_position.hpp>
#include <rclcpp/rclcpp.hpp>

using namespace std::chrono_literals;
using std::placeholders::_1;

class OffboardTakeoffNode : public rclcpp::Node {
public:
  OffboardTakeoffNode()
      : Node("offboard_takeoff_node"), counter_(0), armed_(false),
        done_takeoff_(false) {
    vehicle_command_pub_ = create_publisher<px4_msgs::msg::VehicleCommand>(
        "/fmu/in/vehicle_command", 10);
    offboard_control_mode_pub_ =
        create_publisher<px4_msgs::msg::OffboardControlMode>(
            "/fmu/in/offboard_control_mode", 10);
    trajectory_setpoint_pub_ =
        create_publisher<px4_msgs::msg::TrajectorySetpoint>(
            "/fmu/in/trajectory_setpoint", 10);
    vehicle_local_pos_sub_ =
        create_subscription<px4_msgs::msg::VehicleLocalPosition>(
            "/fmu/out/vehicle_local_position",
            rclcpp::QoS(rclcpp::QoSInitialization::from_rmw(
                            rmw_qos_profile_sensor_data))
                .best_effort(),
            std::bind(&OffboardTakeoffNode::position_callback, this, _1));

    timer_ = create_wall_timer(
        100ms, std::bind(&OffboardTakeoffNode::timer_callback, this));
    RCLCPP_INFO(this->get_logger(), "🚁 Offboard takeoff node initialized");
  }

private:
  rclcpp::Publisher<px4_msgs::msg::VehicleCommand>::SharedPtr
      vehicle_command_pub_;
  rclcpp::Publisher<px4_msgs::msg::OffboardControlMode>::SharedPtr
      offboard_control_mode_pub_;
  rclcpp::Publisher<px4_msgs::msg::TrajectorySetpoint>::SharedPtr
      trajectory_setpoint_pub_;
  rclcpp::Subscription<px4_msgs::msg::VehicleLocalPosition>::SharedPtr
      vehicle_local_pos_sub_;
  rclcpp::TimerBase::SharedPtr timer_;

  int counter_;
  bool armed_;
  bool done_takeoff_;

  float current_z_ = 0.0;

  void
  position_callback(const px4_msgs::msg::VehicleLocalPosition::SharedPtr msg) {
    current_z_ = msg->dist_bottom;
    RCLCPP_INFO(this->get_logger(), "AAAA");
  }

  void timer_callback() {
    uint64_t timestamp = this->get_clock()->now().nanoseconds() / 1000;

    // Always publish OffboardControlMode to keep in offboard
    px4_msgs::msg::OffboardControlMode ctrl_mode{};
    ctrl_mode.timestamp = timestamp;
    ctrl_mode.position = true;
    offboard_control_mode_pub_->publish(ctrl_mode);
    send_vehicle_command(
        px4_msgs::msg::VehicleCommand::VEHICLE_CMD_COMPONENT_ARM_DISARM,
        1.0); // ARM

    // Send takeoff setpoint continuously until we reach -0.95m
    if (!done_takeoff_) {
      px4_msgs::msg::TrajectorySetpoint setpoint{};
      setpoint.timestamp = timestamp;

      if (current_z_ < -0.95) {
        RCLCPP_INFO(this->get_logger(),
                    "✅ Takeoff complete, altitude reached: %.2f m",
                    current_z_);
        done_takeoff_ = true;
      }
    }

    // After a few cycles, send ARM and OFFBOARD mode
    if (counter_ == 5 && !armed_) {
      send_vehicle_command(
          px4_msgs::msg::VehicleCommand::VEHICLE_CMD_DO_SET_MODE, 1.0,
          6.0); // OFFBOARD
      send_vehicle_command(
          px4_msgs::msg::VehicleCommand::VEHICLE_CMD_COMPONENT_ARM_DISARM,
          1.0); // ARM
      RCLCPP_INFO(this->get_logger(),
                  "🛫 Arming and switching to OFFBOARD mode...");
      armed_ = true;
    }

    counter_++;
  }

  void send_vehicle_command(uint16_t command, float param1 = 0.0,
                            float param2 = 0.0) {
    px4_msgs::msg::VehicleCommand cmd{};
    cmd.timestamp = this->get_clock()->now().nanoseconds() / 1000;
    cmd.param1 = param1;
    cmd.param2 = param2;
    cmd.command = command;
    cmd.target_system = 1;
    cmd.target_component = 1;
    cmd.source_system = 1;
    cmd.source_component = 1;
    cmd.from_external = true;
    vehicle_command_pub_->publish(cmd);
  }
};

int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<OffboardTakeoffNode>());
  rclcpp::shutdown();
  return 0;
}
