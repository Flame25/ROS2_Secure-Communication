/**
 * @file setpoint_node.cpp
 * @brief Secure ROS 2 node for encrypted and signed trajectory publishing.
 *
 * This node prepares a secure message containing trajectory setpoint
 * information for a PX4-based drone. It performs the following tasks:
 *
 * 1. Takes raw trajectory data formatted in JSON.
 * 2. Encrypts the data using AES (symmetric encryption).
 * 3. Encrypts the AES key using RSA with the subscriber's public key.
 * 4. Signs the original message with the publisher's private key.
 * 5. Base64-encodes the encrypted message, key, IV, and signature.
 * 6. Publishes the encoded payload to a topic.
 *
 *
 */

#include <ament_index_cpp/get_package_share_directory.hpp>
#include <custom_msgs/msg/detail/signed_data__struct.hpp>
#include <custom_msgs/msg/signed_data.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <rclcpp/rclcpp.hpp>
#include <sstream>
#include <string>

class SetPointPublisher : public rclcpp::Node {
public:
  SetPointPublisher() : Node("setpoint_publisher") {
    publisher = this->create_publisher<custom_msgs::msg::SignedData>(
        "/secure_trajectory", 10);
    timer = this->create_wall_timer(
        std::chrono::seconds(1),
        std::bind(&SetPointPublisher::publish_signed_message, this));

    load_private_key(share_dir + "/keys/setpoint_node/private.pem");
    load_subscriber_public_key(share_dir + "/keys/control_node/public.pem");
  }

private:
  rclcpp::Publisher<custom_msgs::msg::SignedData>::SharedPtr publisher;
  rclcpp::TimerBase::SharedPtr timer;
  RSA *private_key;
  RSA *subscriber_pubkey;
  std::string share_dir =
      ament_index_cpp::get_package_share_directory("custom_nodes");

  std::string rsa_encrypt_key(const std::string &aes_key, RSA *rsa_pubkey) {
    std::string encrypted;
    encrypted.resize(RSA_size(rsa_pubkey));

    int len = RSA_public_encrypt(
        aes_key.size(), reinterpret_cast<const unsigned char *>(aes_key.data()),
        reinterpret_cast<unsigned char *>(&encrypted[0]), rsa_pubkey,
        RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      throw std::runtime_error("RSA encryption failed");
    }

    encrypted.resize(len);
    return encrypted;
  }

  std::string aes_encrypt(const std::string &plaintext,
                          std::string &aes_key_out, std::string &iv_out) {
    unsigned char key[32]; // AES-256
    unsigned char iv[16];  // AES block size

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    aes_key_out = std::string(reinterpret_cast<char *>(key), sizeof(key));
    iv_out = std::string(reinterpret_cast<char *>(iv), sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);

    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(
        ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len,
        reinterpret_cast<const unsigned char *>(plaintext.c_str()),
        plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(
        ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]) + len, &len);
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
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

  void load_subscriber_public_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(),
                   "Failed to open subscriber public key file: %s",
                   path.c_str());
      subscriber_pubkey = nullptr;
      return;
    }

    subscriber_pubkey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!subscriber_pubkey) {
      RCLCPP_ERROR(this->get_logger(),
                   "Failed to read RSA public key from file: %s", path.c_str());
    } else {
      RCLCPP_INFO(this->get_logger(),
                  "Successfully loaded subscriber public key.");
    }
  }

  std::string encrypt_message(const std::string &plaintext) {
    if (!subscriber_pubkey) {
      RCLCPP_ERROR(this->get_logger(), "Subscriber public key not loaded");
      return "";
    }

    int key_size = RSA_size(subscriber_pubkey);
    unsigned char *encrypted = new unsigned char[key_size];

    int len = RSA_public_encrypt(
        plaintext.size(),
        reinterpret_cast<const unsigned char *>(plaintext.c_str()), encrypted,
        subscriber_pubkey, RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      RCLCPP_ERROR(this->get_logger(), "Encryption failed");
      delete[] encrypted;
      return "";
    }

    std::string encrypted_str(reinterpret_cast<char *>(encrypted), len);
    delete[] encrypted;
    return encrypted_str;
  }
  void load_private_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Failed to open private key file: %s",
                   path.c_str());
      return;
    }

    private_key = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!private_key) {
      RCLCPP_ERROR(this->get_logger(), "Failed to read private key from: %s",
                   path.c_str());
    }
  }

  std::string sign_message(const std::string &message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(message.c_str()),
           message.size(), hash);

    unsigned char *signature = new unsigned char[RSA_size(private_key)];
    unsigned int sig_len;

    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len,
             private_key);

    std::string sig_str(reinterpret_cast<char *>(signature), sig_len);
    delete[] signature;
    return sig_str;
  }
  void publish_signed_message() {
    nlohmann::json j;
    j["position"] = {0.0, 0.0, -5.0};
    j["yaw"] = 1.57;

    std::string raw_data = j.dump(); // Ready to encrypt + sign

    auto start = std::chrono::high_resolution_clock::now();
    std::string aes_key, iv;
    std::string encrypted_data = aes_encrypt(raw_data, aes_key, iv);
    std::string encrypted_key = rsa_encrypt_key(aes_key, subscriber_pubkey);

    std::string encoded_data = base64_encode(encrypted_data);
    std::string encoded_signature = base64_encode(sign_message(raw_data));
    std::string encoded_key = base64_encode(encrypted_key);
    std::string encoded_iv = base64_encode(iv);

    // Send all in custom message
    custom_msgs::msg::SignedData msg;
    msg.data = encoded_data;
    msg.signature = encoded_signature;
    msg.encrypted_key = encoded_key;
    msg.iv = encoded_iv;

    auto end = std::chrono::high_resolution_clock::now();
    long elapsed_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start)
            .count();

    RCLCPP_INFO(this->get_logger(), "Signing/encryption time: %ld µs",
                elapsed_us);

    // Log to CSV for time measurements
    std::ofstream log_file;
    log_file.open("/home/gadzz/workspace/sign_enc_time.csv", std::ios::app);
    if (log_file.is_open()) {
      log_file << elapsed_us << std::endl;
      log_file.close();
    } else {
      RCLCPP_ERROR(this->get_logger(),
                   "Failed to open sign_enc_time.csv for writing.");
    }

    publisher->publish(msg);
  }
};

int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<SetPointPublisher>());
  rclcpp::shutdown();
  return 0;
}
