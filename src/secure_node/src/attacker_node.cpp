#include <ament_index_cpp/get_package_share_directory.hpp>
#include <custom_msgs/msg/signed_data.hpp>
#include <fstream>
#include <memory>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <rclcpp/rclcpp.hpp>

class AttackerNode : public rclcpp::Node {
public:
  AttackerNode() : Node("attacker_node") {
    publisher = this->create_publisher<custom_msgs::msg::SignedData>(
        "secure_topic", 10);

    std::string share_dir =
        ament_index_cpp::get_package_share_directory("secure_node");
    load_attacker_private_key(share_dir + "/keys/attacker_node/private.pem");
    load_subscriber_public_key(share_dir + "/keys/subscriber_node/public.pem");

    timer = this->create_wall_timer(
        std::chrono::seconds(2),
        std::bind(&AttackerNode::publish_signed_message, this));
  }

  ~AttackerNode() {
    if (attacker_key_)
      RSA_free(attacker_key_);
    if (subscriber_pubkey_)
      RSA_free(subscriber_pubkey_);
  }

private:
  rclcpp::Publisher<custom_msgs::msg::SignedData>::SharedPtr publisher;
  rclcpp::TimerBase::SharedPtr timer;
  RSA *attacker_key_ = nullptr;
  RSA *subscriber_pubkey_ = nullptr;

  void load_attacker_private_key(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) {
      RCLCPP_ERROR(this->get_logger(), "Failed to open attacker's private key");
      return;
    }
    attacker_key_ = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!attacker_key_) {
      RCLCPP_ERROR(this->get_logger(), "Failed to load attacker's private key");
    }
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
      RCLCPP_ERROR(this->get_logger(), "Failed to open subscriber public key");
      return;
    }
    subscriber_pubkey_ = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!subscriber_pubkey_) {
      RCLCPP_ERROR(this->get_logger(), "Failed to load subscriber public key");
    }
  }

  std::string sign_message(const std::string &msg) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(msg.c_str()), msg.size(),
           hash);

    int key_size = RSA_size(attacker_key_);
    unsigned char *signature = new unsigned char[key_size];

    unsigned int sig_len;
    int result = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature,
                          &sig_len, attacker_key_);

    if (result != 1) {
      RCLCPP_ERROR(this->get_logger(), "Attacker signature failed");
      delete[] signature;
      return "";
    }

    std::string sig_str(reinterpret_cast<char *>(signature), sig_len);
    delete[] signature;
    return sig_str;
  }

  std::string encrypt_message(const std::string &msg) {
    int key_size = RSA_size(subscriber_pubkey_);
    unsigned char *encrypted = new unsigned char[key_size];

    int len = RSA_public_encrypt(
        msg.size(), reinterpret_cast<const unsigned char *>(msg.c_str()),
        encrypted, subscriber_pubkey_, RSA_PKCS1_OAEP_PADDING);

    if (len == -1) {
      RCLCPP_ERROR(this->get_logger(), "Encryption failed");
      delete[] encrypted;
      return "";
    }

    std::string encrypted_str(reinterpret_cast<char *>(encrypted), len);
    delete[] encrypted;
    return encrypted_str;
  }

  void publish_signed_message() {
    std::string raw_data = "⚠️ This is a fake message.";

    std::string signature = sign_message(raw_data);
    std::string encrypted_data = encrypt_message(raw_data);

    // 🔐 Base64 encode both the encrypted message and the signature
    std::string encoded_data = base64_encode(encrypted_data);
    std::string encoded_signature = base64_encode(signature);

    custom_msgs::msg::SignedData msg;
    msg.data = encoded_data;           // encoded encrypted message
    msg.signature = encoded_signature; // encoded signature

    publisher->publish(msg);
  }
};

int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<AttackerNode>());
  rclcpp::shutdown();
  return 0;
}
