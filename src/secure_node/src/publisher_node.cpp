#include <ament_index_cpp/get_package_share_directory.hpp>
#include <custom_msgs/msg/detail/signed_data__struct.hpp>
#include <custom_msgs/msg/signed_data.hpp>
#include <fstream>
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

class SecurePublisher : public rclcpp::Node {
public:
  SecurePublisher() : Node("secure_publisher") {
    publisher = this->create_publisher<custom_msgs::msg::SignedData>(
        "secure_topic", 10);
    timer = this->create_wall_timer(
        std::chrono::seconds(5),
        std::bind(&SecurePublisher::publish_signed_message, this));

    load_private_key(share_dir + "/keys/publisher_node/private.pem");
    load_subscriber_public_key(share_dir + "/keys/subscriber_node/public.pem");
  }

private:
  rclcpp::Publisher<custom_msgs::msg::SignedData>::SharedPtr publisher;
  rclcpp::TimerBase::SharedPtr timer;
  RSA *private_key;
  RSA *subscriber_pubkey;
  std::string share_dir =
      ament_index_cpp::get_package_share_directory("secure_node");

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

    subscriber_pubkey =
        PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr); // ← THIS
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
    std::string raw_data =
        " Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas "
        "hendrerit interdum sem ac molestie. Aliquam volutpat semper congue. "
        "Nunc et ante sed eros viverra aliquet sed nec ex. Nam dapibus aliquet "
        "libero. Duis posuere sodales nunc sed suscipit. Praesent in elit non "
        "felis ultricies dictum. Nunc et viverra odio. Morbi a felis in elit "
        "dapibus tempor nec vitae ipsum. Sed pretium augue at massa facilisis "
        "ultricies. Morbi hendrerit accumsan blandit. Nunc tincidunt in lectus "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer enim "
        "odio, maximus nec placerat at, ultricies sed dolor. Donec quis "
        "euismod odio, vel hendrerit risus. Donec mi libero, posuere pulvinar "
        "tempus in, volutpat in dolor. Vestibulum ante ipsum primis in "
        "faucibus orci luctus et ultrices posuere cubilia curae; Aenean "
        "posuere, felis vel tempus placerat, quam turpis egestas dolor, vel "
        "accumsan ipsum risus in purus. Quisque pellentesque suscipit leo, ac "
        "convallis odio ornare eu. Vestibulum ante ipsum primis in faucibus "
        "orci luctus et ultrices posuere cubilia curae; Sed pharetra lacinia "
        "lobortis. Duis mattis erat sed diam ultrices suscipit. Sed efficitur "
        "laoreet magna, id molestie ex accumsan id. Integer euismod imperdiet "
        "tellus quis rhoncus. Maecenas leo mi, consectetur faucibus porttitor "
        "eu, feugiat in arcu. Nunc blandit, purus eu facilisis aliquam, elit "
        "sapien molestie nibh, blandit laoreet tellus tortor ac nisi. Nulla in "
        "dolor aliquam, semper risus vel, feugiat metus. Donec ultricies porta "
        "felis, eget mollis tellus fringilla quis. Sed vitae dolor et velit "
        "cursus viverra vitae quis purus. Donec dignissim arcu id augue "
        "malesuada, et interdum ex ornare. Donec id neque urna. Vivamus "
        "pretium lacus et ante auctor, vitae commodo mi condimentum. Integer "
        "elementum lectus sed condimentum consectetur. Proin in congue purus. "
        "Fusce pretium iaculis nisi eget sodales. Proin orci metus, tincidunt "
        "quis justo vel, pretium iaculis mauris. Pellentesque efficitur "
        "pharetra viverra. Suspendisse semper mauris nec tellus vulputate, id "
        "tincidunt lorem pretium. Donec non sem sed felis cursus viverra. Sed "
        "venenatis scelerisque massa. Quisque lacinia porttitor dolor varius "
        "rutrum. Aliquam et commodo nisl. Ut arcu justo, suscipit et blandit "
        "nec, molestie eget est. Vestibulum convallis varius dapibus. Quisque "
        "nunc est, aliquam in volutpat quis, mollis eget nisi. Duis bibendum "
        "nisl in libero dapibus fermentum. Duis bibendum vitae purus in "
        "semper. Maecenas posuere odio tempus elit cursus, dignissim bibendum "
        "justo lacinia. Curabitur tempus massa eget consequat auctor. Mauris "
        "aliquam dui risus. Sed eget porttitor erat. Duis vulputate nulla nec "
        "arcu euismod pretium. Pellentesque id eros quis lectus facilisis "
        "accumsan sed ac urna. Interdum et malesuada fames ac ante ipsum "
        "primis in faucibus. Fusce mattis facilisis consequat. Praesent "
        "bibendum sem at mi hendrerit convallis at dictum metus. Etiam "
        "tincidunt purus vehicula dolor luctus lacinia. Nunc sagittis eget "
        "purus vitae consectetur. Nullam commodo tempus velit. Duis ornare "
        "purus ut ornare vestibulum. In volutpat facilisis libero vitae "
        "tincidunt. Aliquam et vestibulum ligula, vel lacinia odio. Aenean "
        "pharetra in tortor non maximus. Praesent malesuada, arcu sodales "
        "placerat tempor, tellus lorem scelerisque tellus, vehicula rhoncus "
        "nibh massa fringilla urna. Nullam eget ultricies metus, eleifend "
        "gravida diam. Mauris purus mauris, pulvinar sit amet purus eu, "
        "vestibulum gravida lorem. Donec luctus, orci accumsan maximus dictum, "
        "elit felis consequat nunc, non cursus ligula justo id orci. Nunc vel "
        "dignissim libero, eget faucibus ipsum. Nunc venenatis pulvinar "
        "luctus. Morbi luctus elit in felis aliquet dignissim. Suspendisse "
        "consectetur mollis ex, et ullamcorper turpis molestie eu. In ultrices "
        "congue lorem, vitae bibendum elit feugiat non. Class aptent taciti "
        "sociosqu ad litora torquent per conubia nostra, per inceptos "
        "himenaeos. ";

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
    msg.encrypted_key = encoded_key; // You must add this field to your message
    msg.iv = encoded_iv;             // You must add this field to your message

    auto end = std::chrono::high_resolution_clock::now();
    long elapsed_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start)
            .count();

    RCLCPP_INFO(this->get_logger(), "Signing/encryption time: %ld µs",
                elapsed_us);

    // 🟢 Log to CSV
    std::ofstream log_file;
    log_file.open(std::string(getenv("HOME")) + "/sign_enc_time.csv",
                  std::ios::app);
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

// 🟢 main() at the bottom of the same file
int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<SecurePublisher>());
  rclcpp::shutdown();
  return 0;
}
