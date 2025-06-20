/**
 *
 * @file control_node.cpp
 * @brief Secure ROS 2 node for checking and publishing it to FC (Flight
 * Controller).
 *
 * This is the subscriber node which responsible for:
 * - Verifying the signature,
 * - Decrypting the AES key using its private RSA key,
 * - Decrypting the data,
 * - Publishing the setpoint to PX4 if the signature is valid.
 *
 * This ensures that only authorized nodes data being read for the
 * commands, providing confidentiality and integrity in a secure drone
 * communication system.
 *
 **/

#include <ament_index_cpp/get_package_share_directory.hpp>
#include <custom_msgs/msg/detail/signed_data__struct.hpp>
#include <custom_msgs/msg/signed_data.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <px4_msgs/msg/detail/trajectory_setpoint__struct.hpp>
#include <px4_msgs/msg/trajectory_setpoint.hpp>
#include <rclcpp/rclcpp.hpp>
#include <sstream>
#include <string>

class SetPointSubscriber : public rclcpp::Node {
public:
  SetPointSubscriber() : Node("secure_subscriber") {
    subscription_ = this->create_subscription<custom_msgs::msg::SignedData>(
        "secure_trajectory", 10,
        std::bind(&SetPointSubscriber::verify_callback, this,
                  std::placeholders::_1));
    trajectory_publisher =
        this->create_publisher<px4_msgs::msg::TrajectorySetpoint>(
            "/fmu/in/trajectory_setpoint", 10);

    std::string share_dir =
        ament_index_cpp::get_package_share_directory("custom_nodes");
    load_public_key(share_dir + "/keys/setpoint_node/public.pem");
    load_private_key(share_dir + "/keys/control_node/private.pem");
  }

private:
  rclcpp::Subscription<custom_msgs::msg::SignedData>::SharedPtr subscription_;

  rclcpp::Publisher<px4_msgs::msg::TrajectorySetpoint>::SharedPtr
      trajectory_publisher;
  RSA *public_key_;
  RSA *private_key;

  std::string rsa_decrypt_key(const std::string &encrypted_key,
                              RSA *rsa_privkey) {
    std::string decrypted;
    decrypted.resize(RSA_size(rsa_privkey));

    int len = RSA_private_decrypt(
        encrypted_key.size(),
        reinterpret_cast<const unsigned char *>(encrypted_key.data()),
        reinterpret_cast<unsigned char *>(&decrypted[0]), rsa_privkey,
        RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      throw std::runtime_error("RSA decryption failed");
    }

    decrypted.resize(len);
    return decrypted;
  }

  std::string aes_decrypt(const std::string &ciphertext,
                          const std::string &aes_key, const std::string &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string plaintext;
    plaintext.resize(ciphertext.size());

    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char *>(aes_key.data()),
                       reinterpret_cast<const unsigned char *>(iv.data()));

    EVP_DecryptUpdate(
        ctx, reinterpret_cast<unsigned char *>(&plaintext[0]), &len,
        reinterpret_cast<const unsigned char *>(ciphertext.data()),
        ciphertext.size());
    plaintext_len = len;

    EVP_DecryptFinal_ex(
        ctx, reinterpret_cast<unsigned char *>(&plaintext[0]) + len, &len);
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
  }

  void load_private_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");

    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Failed to open public key file: %s",
                   path.c_str());
      private_key = nullptr;
      return;
    }

    private_key = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!public_key_) {
      RCLCPP_ERROR(this->get_logger(), "Failed to load public key from: %s",
                   path.c_str());
    }
  }

  void load_public_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Failed to open public key file: %s",
                   path.c_str());
      public_key_ = nullptr;
      return;
    }

    public_key_ = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!public_key_) {
      RCLCPP_ERROR(this->get_logger(), "Failed to load public key from: %s",
                   path.c_str());
    }
  }

  std::string decrypt_message(const std::string &encrypted_msg) {
    if (!private_key) {
      RCLCPP_ERROR(this->get_logger(), "Private key not loaded");
      return "";
    }

    int key_size = RSA_size(private_key);
    std::vector<unsigned char> decrypted(key_size);

    int len = RSA_private_decrypt(
        encrypted_msg.size(),
        reinterpret_cast<const unsigned char *>(encrypted_msg.c_str()),
        decrypted.data(), private_key, RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      RCLCPP_ERROR(this->get_logger(), "Decryption failed ");
      return "";
    }

    return std::string(reinterpret_cast<char *>(decrypted.data()), len);
  }
  std::string base64_encode(const std::string &in) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, in.c_str(), in.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
  }

  std::string base64_decode(const std::string &in) {
    BIO *bio, *b64;
    char *buffer = new char[in.size()];
    memset(buffer, 0, in.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in.data(), in.size());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_size = BIO_read(bio, buffer, in.size());
    BIO_free_all(bio);

    std::string decoded(buffer, decoded_size);
    delete[] buffer;
    return decoded;
  }

  void verify_callback(const custom_msgs::msg::SignedData::SharedPtr msg) {
    if (!public_key_ || !private_key) {
      RCLCPP_ERROR(this->get_logger(), "Public or private key not loaded.");
      return;
    }

    auto start = std::chrono::high_resolution_clock::now();

    try {
      std::string encrypted_data = base64_decode(msg->data);
      std::string signature = base64_decode(msg->signature);
      std::string encrypted_key = base64_decode(msg->encrypted_key);
      std::string iv = base64_decode(msg->iv);

      std::string aes_key = rsa_decrypt_key(encrypted_key, private_key);
      if (aes_key.empty()) {
        RCLCPP_ERROR(this->get_logger(), "Failed to decrypt AES key.");
        return;
      }

      std::string decrypted_data = aes_decrypt(encrypted_data, aes_key, iv);
      if (decrypted_data.empty()) {
        RCLCPP_ERROR(this->get_logger(), "Decryption failed.");
        return;
      }

      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256(reinterpret_cast<const unsigned char *>(decrypted_data.c_str()),
             decrypted_data.size(), hash);

      int result =
          RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                     reinterpret_cast<const unsigned char *>(signature.c_str()),
                     signature.size(), public_key_);

      auto end = std::chrono::high_resolution_clock::now();
      long elapsed_us =
          std::chrono::duration_cast<std::chrono::microseconds>(end - start)
              .count();

      RCLCPP_INFO(this->get_logger(), "Decryption/verification time: %ld µs",
                  elapsed_us);

      std::ofstream log_file("/home/gadzz/workspace/dec_verify_time.csv",
                             std::ios::app);
      if (log_file.is_open()) {
        log_file << elapsed_us << std::endl;
        log_file.close();
      } else {
        RCLCPP_ERROR(this->get_logger(), "Failed to open CSV log file.");
      }

      // Step 6: If valid, parse JSON and send to FC
      if (result == 1) {
        RCLCPP_INFO_STREAM(this->get_logger(),
                           "✅ Valid signature! Decrypted data:\n"
                               << decrypted_data);

        nlohmann::json j = nlohmann::json::parse(decrypted_data);

        px4_msgs::msg::TrajectorySetpoint sp;
        sp.timestamp = this->get_clock()->now().nanoseconds();

        if (j.contains("position") && j["position"].is_array() &&
            j["position"].size() == 3) {
          sp.position = {static_cast<float>(j["position"][0]),
                         static_cast<float>(j["position"][1]),
                         static_cast<float>(j["position"][2])};
        } else {
          RCLCPP_ERROR(this->get_logger(),
                       "⚠️ Missing or invalid position in JSON.");
          return;
        }

        if (j.contains("yaw")) {
          sp.yaw = static_cast<float>(j["yaw"]);
        }

        trajectory_publisher->publish(sp);

        RCLCPP_INFO(this->get_logger(), "📡 Pose published to FC.");
      } else {
        RCLCPP_WARN(this->get_logger(), "❌ Invalid signature!");
      }
    } catch (const std::exception &e) {
      RCLCPP_ERROR_STREAM(this->get_logger(),
                          "Exception during verification: " << e.what());
    } catch (...) {
      RCLCPP_ERROR(this->get_logger(),
                   "Unknown error occurred during verification.");
    }
  }
};

int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<SetPointSubscriber>());
  rclcpp::shutdown();
  return 0;
}
