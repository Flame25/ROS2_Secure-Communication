/**
 * @file attacker_node.cpp
 * @brief Attacker ROS 2 node simulating forged secure messages.
 */

#include <ament_index_cpp/get_package_share_directory.hpp>
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
#include <rclcpp/rclcpp.hpp>
#include <string>

class AttackerNode : public rclcpp::Node {
public:
  AttackerNode() : Node("attacker_node") {
    publisher = this->create_publisher<custom_msgs::msg::SignedData>(
        "secure_trajectory", 10);
    timer = this->create_wall_timer(
        std::chrono::seconds(1),
        std::bind(&AttackerNode::publish_forged_message, this));

    load_fake_private_key(share_dir + "/keys/attacker_node/private.pem");
    load_fake_public_key(share_dir + "/keys/control_node/public.pem");
  }

private:
  rclcpp::Publisher<custom_msgs::msg::SignedData>::SharedPtr publisher;
  rclcpp::TimerBase::SharedPtr timer;
  RSA *fake_private_key = nullptr;
  RSA *fake_public_key = nullptr;
  std::string share_dir =
      ament_index_cpp::get_package_share_directory("custom_nodes");

  void load_fake_private_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Cannot open fake private key file");
      return;
    }
    fake_private_key = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
  }

  void load_fake_public_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Cannot open fake public key file");
      return;
    }
    fake_public_key = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
  }

  std::string aes_encrypt(const std::string &plaintext,
                          std::string &aes_key_out, std::string &iv_out) {
    unsigned char key[32];
    unsigned char iv[16];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    aes_key_out.assign(reinterpret_cast<char *>(key), sizeof(key));
    iv_out.assign(reinterpret_cast<char *>(iv), sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(
        ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len,
        reinterpret_cast<const unsigned char *>(plaintext.c_str()),
        plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(
        ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]) + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
  }

  std::string rsa_encrypt_key(const std::string &key) {
    std::string encrypted;
    encrypted.resize(RSA_size(fake_public_key));
    int len = RSA_public_encrypt(
        key.size(), reinterpret_cast<const unsigned char *>(key.data()),
        reinterpret_cast<unsigned char *>(&encrypted[0]), fake_public_key,
        RSA_PKCS1_OAEP_PADDING);
    if (len == -1)
      throw std::runtime_error("Fake RSA encryption failed");
    encrypted.resize(len);
    return encrypted;
  }

  std::string sign_message(const std::string &message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(message.c_str()),
           message.size(), hash);

    unsigned char *signature = new unsigned char[RSA_size(fake_private_key)];
    unsigned int sig_len;

    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len,
             fake_private_key);

    std::string sig(reinterpret_cast<char *>(signature), sig_len);
    delete[] signature;
    return sig;
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

  void publish_forged_message() {
    nlohmann::json j;
    j["position"] = {-999.0, -999.0, -999.0}; // Malicious setpoint
    j["yaw"] = 3.14;

    std::string raw_data = j.dump();
    std::string aes_key, iv;
    std::string encrypted_data = aes_encrypt(raw_data, aes_key, iv);
    std::string encrypted_key = rsa_encrypt_key(aes_key);
    std::string signature = sign_message(raw_data);

    custom_msgs::msg::SignedData msg;
    msg.data = base64_encode(encrypted_data);
    msg.signature = base64_encode(signature);
    msg.encrypted_key = base64_encode(encrypted_key);
    msg.iv = base64_encode(iv);

    RCLCPP_WARN(this->get_logger(), "[!] Publishing FORGED message.");
    publisher->publish(msg);
  }
};

int main(int argc, char **argv) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<AttackerNode>());
  rclcpp::shutdown();
  return 0;
}
