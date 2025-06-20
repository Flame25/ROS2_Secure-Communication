# ROS 2 Secure Communication (Publisher-Subscriber)

This repository contains a simple demonstration of secure communication in a ROS 2 system using RSA encryption and digital signatures. Each message is signed and encrypted to ensure integrity, authenticity, and confidentiality.

---

✅ **Now Working and Tested with PX4 Simulation**  
🚧 **Still a Proof of Concept** — Not production-grade yet  
🔐 Focuses on encryption, digital signatures, and ROS 2 integration

---

## 📽️ Demo Video

Watch the demo on YouTube:  
🎬 [https://www.youtube.com/watch?v=Co018TFREB4&feature=youtu.be](https://www.youtube.com/watch?v=Co018TFREB4&feature=youtu.be)


## 📝 Paper

📄 You can read the detailed paper here:  
👉 [https://www.overleaf.com/read/crwvqmcbntmc#e38196](https://www.overleaf.com/read/crwvqmcbntmc#e38196)

## ✨ Features

- 🔒 RSA Digital Signature for Message Integrity
- 🛡️ RSA Encryption/Decryption for Confidentiality
- 🔁 Secure Publisher and Subscriber Nodes
- ❌ Attacker Simulation Node (to test tampering)
- 📊 Performance Benchmarking (encryption/decryption timing)
- ✅ Works with PX4 SITL and ROS 2 Offboard Communication

---

## 🧱 Dependencies

- ROS 2 (tested on **Humble**, Ubuntu 22.04)
- PX4 Autopilot (with `px4_ros_com` for ROS 2 communication)
- OpenSSL (for RSA encryption)
- Ubuntu 22.04

---

## 🛠 Installation Instructions

### 1. Install ROS 2 Humble

Follow the official ROS 2 installation guide for Ubuntu 22.04:  
🔗 https://docs.ros.org/en/humble/Installation.html

```bash
sudo apt update
sudo apt install curl gnupg2 lsb-release
source /opt/ros/humble/setup.bash
```

### 2. Install PX4 Autopilot (for drone simulation + offboard)

Follow the official PX4 setup for Ubuntu:
🔗 https://docs.px4.io/main/en/dev_setup/dev_env_linux_ubuntu.html

Also install and configure the ROS 2 interface for PX4 (px4_ros_com):
🔗 https://docs.px4.io/main/en/ros/ros2_comm.html

### 3. Clone the Repository

```bash
git clone https://github.com/Flame25/ROS2_Secure-Communication.git
cd ROS2_Secure-Communication
```

### 4. Build the Workspace

First, build the custom message package:

```bash
colcon build --packages-select custom_msgs
```

Then build the entire workspace:

```bash
colcon build
```

Don't forget to source it:

```bash
source install/setup.bash
```

### 6. Run The Key Generator: 

```bash
./generate_keys.sh
```
### 5. Run The Simulator

### 6. Running the Nodes
```bash
ros2 run custom_nodes control_node
```

```bash
ros2 run custom_nodes offboard_node
```

```bash
ros2 run custom_nodes setpoint_node
```

# 📊 Benchmarking Mode

You can measure encryption and signature performance with internal timers. Use this to check performance cost during real-time PX4 use.


# 🤖 PX4 Integration Notes

This secure ROS 2 communication system has been tested and works in a PX4 offboard control setup. You can integrate it with your PX4 setup as follows:

    Use this node alongside or within your offboard control node

    Encrypt/send trajectory setpoints or control messages

    Ensure PX4's px4_ros_com and microRTPS bridge (if applicable) are running

Check PX4 documentation for offboard control:
🔗 https://docs.px4.io/main/en/ros/ros2_comm.html
🔗 https://docs.px4.io/main/en/flight_modes/offboard.html

# ⚠️ Disclaimer

This project is a research-grade proof of concept. It demonstrates message-level security using RSA but:

* Doesn’t support large payloads or advanced key management
* Is not optimized for real-time control over lossy networks
* Should not be used in safety-critical production systems (yet!)
