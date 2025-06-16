# ROS 2 Secure Communication (Publisher-Subscriber)

This repository contains a simple demonstration of secure communication in a ROS 2 system using RSA encryption and digital signatures. Each message is signed and encrypted to ensure integrity, authenticity, and confidentiality.

## Features

- 🔒 RSA Digital Signature
- 🛡️ RSA Encryption/Decryption
- 🔁 Secure Publisher and Subscriber Nodes
- ❌ Attacker Simulation Node
- 📊 Performance Benchmarking (encryption/decryption timing)

## Dependencies

- ROS 2 (tested on Humble, Ubuntu 22.04)
- Ubuntu 22.04

1. **Install ROS 2 Humble**

   Follow the official installation guide for your operating system:
   https://docs.ros.org/en/humble/Installation.html

   Also, don't forget to source your ROS installation or add it your shell
   ```
   source /opt/ros/humble/setup.bash
   ```

3. **Clone the repository**
   ```bash
   git https://github.com/Flame25/ROS2_Secure-Communication.git
   cd ROS2_Secure-Communication
   ```
4. **Build the workspace**
5. 
   We need to build the custom msgs first

   ```
   colcon build --packages-select custom_msgs
   ```

   Then, build all

   ```
   colcon build
   ```

6. **Run the Nodes**

   Publisher Node:
   ```
   ros2 run secure_node publisher_node
   ```

   Subscriber Node:
   
    ```
    ros2 run secure_node subscriber_node
    ```
7. Generate Key Pairs

   I've set the key at ```src/secure_node/keys```. If you want to generate new key run the command below

   ```
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   ```

   For public key

   ```
   openssl rsa -pubout -in private_key.pem -out public_key.pem
   ```

   or

   Just run the ```./generate_keys.sh```
   
