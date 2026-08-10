#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <numeric>
#include <random>
#include <cstdint>
#include <filesystem>
#include <cmath>
#include <limits>

// OpenCV for image and video processing
#include <opencv2/opencv.hpp>
#include <opencv2/videoio.hpp>

// OpenSSL for AES encryption/decryption
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// ========== HELPER & UTILITY FUNCTIONS ==========

// Helper function to handle OpenSSL errors
void handleOpenSSLErrors() {
    throw std::runtime_error("OpenSSL Error: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
}

// Check if file has a video extension
bool isVideoFile(const std::string& path) {
    std::string ext = path.substr(path.find_last_of(".") + 1);
    return ext == "avi" || ext == "mp4" || ext == "mov"; // Input can be common formats
}

// Check if file has an image extension
bool isImageFile(const std::string& path) {
    std::string ext = path.substr(path.find_last_of(".") + 1);
    return ext == "png" || ext == "bmp";
}

// ========== ENCRYPTION / DECRYPTION LOGIC ==========

std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::string& password) {
    unsigned char key[32], iv[16];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), nullptr, 0, 10000, EVP_sha256(), 32, key)) handleOpenSSLErrors();
    if (!RAND_bytes(iv, sizeof(iv))) handleOpenSSLErrors();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleOpenSSLErrors();

    std::vector<unsigned char> ciphertext;
    int len;
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) handleOpenSSLErrors();
    
    ciphertext.resize(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) handleOpenSSLErrors();
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleOpenSSLErrors();
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> result(sizeof(iv));
    std::copy(std::begin(iv), std::end(iv), std::begin(result));
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipher_data, const std::string& password) {
    if (cipher_data.size() < 17) throw std::runtime_error("Invalid cipher data size for decryption.");
    
    unsigned char key[32];
    unsigned char iv[16];
    std::copy(cipher_data.begin(), cipher_data.begin() + 16, iv);

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), nullptr, 0, 10000, EVP_sha256(), 32, key)) handleOpenSSLErrors();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleOpenSSLErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) handleOpenSSLErrors();

    std::vector<unsigned char> plaintext(cipher_data.size());
    int len;
    int plaintext_len;
    const unsigned char* ciphertext = cipher_data.data() + 16;
    int ciphertext_len = cipher_data.size() - 16;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len)) handleOpenSSLErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) handleOpenSSLErrors();
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}


// ========== STEGANOGRAPHY CORE LOGIC ==========

uint64_t hashPasswordToSeed(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);
    uint64_t seed = 0;
    for (int i = 0; i < 8; ++i) {
        seed = (seed << 8) | static_cast<uint64_t>(hash[i]);
    }
    return seed;
}

uint64_t deriveFrameSeed(uint64_t base_seed, uint64_t frame_index) {
    return base_seed ^ (0x9e3779b97f4a7c15ULL * (frame_index + 1));
}

std::vector<int> makeShuffledPositions(int rows, int cols, uint64_t seed) {
    const int total_positions = rows * cols * 3;
    std::vector<int> positions(total_positions);
    std::iota(positions.begin(), positions.end(), 0);
    std::mt19937_64 rng(seed);
    std::shuffle(positions.begin(), positions.end(), rng);
    return positions;
}

static inline void setBitAtPosition(cv::Mat& frame, int pos, bool bit) {
    const int channel = pos % 3;
    const int pixel_index = pos / 3;
    const int i = pixel_index / frame.cols;
    const int j = pixel_index % frame.cols;
    cv::Vec3b& pixel = frame.at<cv::Vec3b>(i, j);
    pixel[channel] = (pixel[channel] & 0xFE) | static_cast<unsigned char>(bit);
}

static inline bool getBitAtPosition(const cv::Mat& frame, int pos) {
    const int channel = pos % 3;
    const int pixel_index = pos / 3;
    const int i = pixel_index / frame.cols;
    const int j = pixel_index % frame.cols;
    const cv::Vec3b& pixel = frame.at<cv::Vec3b>(i, j);
    return (pixel[channel] & 1) != 0;
}

// Embeds bits into a single image frame
void embedBitsInFrame(cv::Mat& frame, const std::vector<bool>& bits, long& bit_index, const std::vector<int>& positions) {
    for (size_t idx = 0; idx < positions.size() && bit_index < static_cast<long>(bits.size()); ++idx) {
        setBitAtPosition(frame, positions[idx], bits[bit_index]);
        bit_index++;
    }
}

// Extracts bits from a single image frame
void extractBitsFromFrame(const cv::Mat& frame, std::vector<bool>& extracted_bits, long& bits_to_extract, const std::vector<int>& positions) {
    for (size_t idx = 0; idx < positions.size() && bits_to_extract > 0; ++idx) {
        extracted_bits.push_back(getBitAtPosition(frame, positions[idx]));
        bits_to_extract--;
    }
}


// ========== MAIN HANDLERS FOR IMAGE & VIDEO ==========

// Hides data in a static image
void handleHideImage(const std::string& cover_path, const std::vector<unsigned char>& data, const std::string& output_path, const std::string& password) {
    cv::Mat image = cv::imread(cover_path, cv::IMREAD_COLOR);
    if (image.empty()) throw std::runtime_error("Could not open cover image: " + cover_path);

    long image_capacity = image.rows * image.cols * 3;
    if ((data.size() * 8 + 32) > image_capacity) throw std::runtime_error("Cover image is not large enough.");

    std::vector<bool> bits_to_hide;
    uint32_t data_size = data.size();
    for (int i = 0; i < 32; ++i) bits_to_hide.push_back((data_size >> i) & 1);
    for (unsigned char byte : data) {
        for (int i = 0; i < 8; ++i) bits_to_hide.push_back((byte >> i) & 1);
    }

    uint64_t base_seed = hashPasswordToSeed(password);
    std::vector<int> positions = makeShuffledPositions(image.rows, image.cols, base_seed);
    long bit_index = 0;
    embedBitsInFrame(image, bits_to_hide, bit_index, positions);

    if (!cv::imwrite(output_path, image)) throw std::runtime_error("Failed to save output image.");
    std::cout << "Successfully hid data in " << output_path << std::endl;
}

// Extracts data from a static image
std::vector<unsigned char> handleExtractImage(const std::string& stego_path, const std::string& password) {
    cv::Mat image = cv::imread(stego_path, cv::IMREAD_COLOR);
    if (image.empty()) throw std::runtime_error("Could not open stego image: " + stego_path);
    
    uint64_t base_seed = hashPasswordToSeed(password);
    std::vector<int> positions = makeShuffledPositions(image.rows, image.cols, base_seed);

    if (positions.size() < 32) throw std::runtime_error("Image too small to contain size header.");

    uint32_t data_size = 0;
    for (int i = 0; i < 32; ++i) {
        if (getBitAtPosition(image, positions[i])) data_size |= (1u << i);
    }

    size_t total_bits = 32 + static_cast<size_t>(data_size) * 8;
    if (total_bits > positions.size()) throw std::runtime_error("Declared data size exceeds image capacity.");

    std::vector<bool> data_bits;
    data_bits.reserve(static_cast<size_t>(data_size) * 8);
    for (size_t idx = 32; idx < total_bits; ++idx) {
        data_bits.push_back(getBitAtPosition(image, positions[idx]));
    }

    std::vector<unsigned char> extracted_data(data_size);
    for (size_t i = 0; i < data_bits.size(); ++i) {
        if (data_bits[i]) {
            extracted_data[i/8] |= (1 << (i % 8));
        }
    }
    return extracted_data;
}

// Hides data in a video file
void handleHideVideo(const std::string& cover_path, const std::vector<unsigned char>& data, const std::string& output_path, const std::string& password) {
    cv::VideoCapture cap(cover_path);
    if (!cap.isOpened()) throw std::runtime_error("Could not open cover video.");

    int frame_width = cap.get(cv::CAP_PROP_FRAME_WIDTH);
    int frame_height = cap.get(cv::CAP_PROP_FRAME_HEIGHT);
    double fps = cap.get(cv::CAP_PROP_FPS);
    long total_frames = cap.get(cv::CAP_PROP_FRAME_COUNT);
    
    long total_capacity_bits = total_frames * frame_width * frame_height * 3;
    if (data.size() * 8 + 32 > total_capacity_bits) throw std::runtime_error("Cover video is not long/large enough.");

    std::string video_only_path = output_path + ".video_only.avi";
    cv::VideoWriter video_out(video_only_path, cv::VideoWriter::fourcc('F', 'F', 'V', '1'), fps, cv::Size(frame_width, frame_height));
    if (!video_out.isOpened()) throw std::runtime_error("Could not create output video file. Check codec support.");

    std::vector<bool> bits_to_hide;
    uint32_t data_size = data.size();
    for (int i = 0; i < 32; ++i) bits_to_hide.push_back((data_size >> i) & 1);
    for (unsigned char byte : data) {
        for (int i = 0; i < 8; ++i) bits_to_hide.push_back((byte >> i) & 1);
    }

    uint64_t base_seed = hashPasswordToSeed(password);
    cv::Mat frame;
    long bit_index = 0;
    long frame_index = 0;
    while (cap.read(frame)) {
        if (bit_index < static_cast<long>(bits_to_hide.size())) {
            uint64_t seed = deriveFrameSeed(base_seed, static_cast<uint64_t>(frame_index));
            std::vector<int> positions = makeShuffledPositions(frame.rows, frame.cols, seed);
            embedBitsInFrame(frame, bits_to_hide, bit_index, positions);
        }
        video_out.write(frame);
        frame_index++;
    }

    cap.release();
    video_out.release();

    std::string ffmpeg_cmd = "ffmpeg -y -i \"" + video_only_path + "\" -i \"" + cover_path + "\" -map 0:v:0 -map 1:a? -c:v copy -c:a pcm_s16le \"" + output_path + "\"";
    int mux_result = std::system(ffmpeg_cmd.c_str());
    if (mux_result == 0) {
        std::error_code ec;
        std::filesystem::remove(video_only_path, ec);
        std::cout << "Successfully hid data with audio preserved in " << output_path << std::endl;
    } else {
        std::error_code ec;
        std::filesystem::remove(output_path, ec);
        std::filesystem::rename(video_only_path, output_path, ec);
        if (ec) {
            throw std::runtime_error("Failed to finalize output video. Ensure write permissions and codec support.");
        }
        std::cerr << "Warning: could not mux audio (ffmpeg missing or failed). Output saved without audio to " << output_path << std::endl;
    }
}

// Extracts data from a video file
std::vector<unsigned char> handleExtractVideo(const std::string& stego_path, const std::string& password) {
    cv::VideoCapture cap(stego_path);
    if (!cap.isOpened()) throw std::runtime_error("Could not open stego video.");
    
    cv::Mat frame;
    std::vector<bool> extracted_bits;
    long bits_to_extract;
    uint64_t base_seed = hashPasswordToSeed(password);
    long frame_index = 0;

    // First, extract the 32-bit size header
    bits_to_extract = 32;
    while (cap.read(frame) && bits_to_extract > 0) {
        uint64_t seed = deriveFrameSeed(base_seed, static_cast<uint64_t>(frame_index));
        std::vector<int> positions = makeShuffledPositions(frame.rows, frame.cols, seed);
        extractBitsFromFrame(frame, extracted_bits, bits_to_extract, positions);
        frame_index++;
    }
    if (extracted_bits.size() < 32) throw std::runtime_error("Could not extract data size from video.");

    uint32_t data_size = 0;
    for(int i = 0; i < 32; ++i) {
        if (extracted_bits[i]) data_size |= (1 << i);
    }
    extracted_bits.clear();

    // Now, extract the data itself
    cap.set(cv::CAP_PROP_POS_FRAMES, 0); // Rewind video
    long total_bits_to_get = 32 + data_size * 8;
    bits_to_extract = total_bits_to_get;
    frame_index = 0;
    
    while(cap.read(frame) && bits_to_extract > 0) {
        uint64_t seed = deriveFrameSeed(base_seed, static_cast<uint64_t>(frame_index));
        std::vector<int> positions = makeShuffledPositions(frame.rows, frame.cols, seed);
        extractBitsFromFrame(frame, extracted_bits, bits_to_extract, positions);
        frame_index++;
    }
    cap.release();
    
    if (extracted_bits.size() < total_bits_to_get) throw std::runtime_error("Video ended before all data could be extracted.");
    
    std::vector<unsigned char> extracted_data(data_size);
    for(size_t i = 32; i < total_bits_to_get; ++i) {
        if (extracted_bits[i]) {
            extracted_data[(i - 32) / 8] |= (1 << ((i - 32) % 8));
        }
    }
    return extracted_data;
}


// ========== MAIN FUNCTION & ARGUMENT PARSING ==========

void printUsage() {
    std::cerr << "A tool for AES-256 encrypted steganography in images and videos.\n\n"
              << "Usage:\n"
              << "  To hide:   ./steganography hide <cover_media> <secret_file> <output_media> <password>\n"
              << "  To extract:./steganography extract <stego_media> <output_file> <password>\n\n"
              << "  Metrics (images only):\n"
              << "    ./steganography metrics <cover_image> <stego_image> <password> <output_prefix>\n\n"
              << "Supported Media:\n"
              << "  Cover Images (input): .png, .bmp\n"
              << "  Output Images (stego): .png (recommended), .bmp\n"
              << "  Cover Videos (input): .avi, .mp4, etc.\n"
              << "  Output Videos (stego): .avi (MUST use a lossless format)\n";
}

double computePSNR(const cv::Mat& original, const cv::Mat& stego) {
    cv::Mat diff;
    cv::absdiff(original, stego, diff);
    diff.convertTo(diff, CV_32F);
    diff = diff.mul(diff);
    cv::Scalar s = cv::sum(diff);
    double sse = s[0] + s[1] + s[2];
    double mse = sse / (static_cast<double>(original.total()) * original.channels());
    if (mse <= std::numeric_limits<double>::epsilon()) {
        return std::numeric_limits<double>::infinity();
    }
    return 10.0 * std::log10((255.0 * 255.0) / mse);
}

double computeSSE(const cv::Mat& original, const cv::Mat& stego) {
    cv::Mat diff;
    cv::absdiff(original, stego, diff);
    diff.convertTo(diff, CV_32F);
    diff = diff.mul(diff);
    cv::Scalar s = cv::sum(diff);
    return s[0] + s[1] + s[2];
}

double computeSSIM(const cv::Mat& original, const cv::Mat& stego) {
    const double C1 = (0.01 * 255) * (0.01 * 255);
    const double C2 = (0.03 * 255) * (0.03 * 255);

    cv::Mat I1, I2;
    original.convertTo(I1, CV_32F);
    stego.convertTo(I2, CV_32F);

    cv::Mat I1_2 = I1.mul(I1);
    cv::Mat I2_2 = I2.mul(I2);
    cv::Mat I1_I2 = I1.mul(I2);

    cv::Mat mu1, mu2;
    cv::GaussianBlur(I1, mu1, cv::Size(11, 11), 1.5);
    cv::GaussianBlur(I2, mu2, cv::Size(11, 11), 1.5);

    cv::Mat mu1_2 = mu1.mul(mu1);
    cv::Mat mu2_2 = mu2.mul(mu2);
    cv::Mat mu1_mu2 = mu1.mul(mu2);

    cv::Mat sigma1_2, sigma2_2, sigma12;
    cv::GaussianBlur(I1_2, sigma1_2, cv::Size(11, 11), 1.5);
    sigma1_2 -= mu1_2;
    cv::GaussianBlur(I2_2, sigma2_2, cv::Size(11, 11), 1.5);
    sigma2_2 -= mu2_2;
    cv::GaussianBlur(I1_I2, sigma12, cv::Size(11, 11), 1.5);
    sigma12 -= mu1_mu2;

    cv::Mat t1 = 2 * mu1_mu2 + C1;
    cv::Mat t2 = 2 * sigma12 + C2;
    cv::Mat t3 = mu1_2 + mu2_2 + C1;
    cv::Mat t4 = sigma1_2 + sigma2_2 + C2;

    cv::Mat ssim_map;
    cv::divide(t1.mul(t2), t3.mul(t4), ssim_map);
    cv::Scalar mean_ssim = cv::mean(ssim_map);
    return (mean_ssim[0] + mean_ssim[1] + mean_ssim[2]) / 3.0;
}

double computeEntropy(const cv::Mat& image) {
    cv::Mat gray;
    if (image.channels() == 3) {
        cv::cvtColor(image, gray, cv::COLOR_BGR2GRAY);
    } else {
        gray = image.clone();
    }

    std::vector<int> hist(256, 0);
    for (int i = 0; i < gray.rows; ++i) {
        const unsigned char* row = gray.ptr<unsigned char>(i);
        for (int j = 0; j < gray.cols; ++j) {
            hist[row[j]]++;
        }
    }

    double total = static_cast<double>(gray.total());
    double entropy = 0.0;
    for (int count : hist) {
        if (count == 0) continue;
        double p = count / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::vector<int> computeHistogram(const cv::Mat& image) {
    cv::Mat gray;
    if (image.channels() == 3) {
        cv::cvtColor(image, gray, cv::COLOR_BGR2GRAY);
    } else {
        gray = image.clone();
    }

    std::vector<int> hist(256, 0);
    for (int i = 0; i < gray.rows; ++i) {
        const unsigned char* row = gray.ptr<unsigned char>(i);
        for (int j = 0; j < gray.cols; ++j) {
            hist[row[j]]++;
        }
    }
    return hist;
}

void writeHistogramCsv(const std::vector<int>& hist, const std::string& path) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Could not write histogram CSV: " + path);
    out << "intensity,count\n";
    for (int i = 0; i < 256; ++i) {
        out << i << "," << hist[i] << "\n";
    }
}

void writeHistogramCsvLL(const std::vector<long long>& hist, const std::string& path) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Could not write histogram CSV: " + path);
    out << "intensity,count\n";
    for (int i = 0; i < 256; ++i) {
        out << i << "," << hist[i] << "\n";
    }
}

void ensureOutputPrefixDir(const std::string& output_prefix) {
    std::filesystem::path out_path(output_prefix);
    std::filesystem::path parent = out_path.parent_path();
    if (parent.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        throw std::runtime_error("Could not create output directory: " + parent.string());
    }
}

uint32_t getPayloadSizeFromImage(const cv::Mat& image, const std::string& password) {
    uint64_t base_seed = hashPasswordToSeed(password);
    std::vector<int> positions = makeShuffledPositions(image.rows, image.cols, base_seed);
    if (positions.size() < 32) throw std::runtime_error("Image too small to contain size header.");
    uint32_t data_size = 0;
    for (int i = 0; i < 32; ++i) {
        if (getBitAtPosition(image, positions[i])) data_size |= (1u << i);
    }
    return data_size;
}

uint32_t getPayloadSizeFromVideo(const std::string& stego_path, const std::string& password) {
    cv::VideoCapture cap(stego_path);
    if (!cap.isOpened()) throw std::runtime_error("Could not open stego video.");

    uint64_t base_seed = hashPasswordToSeed(password);
    cv::Mat frame;
    std::vector<bool> extracted_bits;
    long bits_to_extract = 32;
    long frame_index = 0;

    while (cap.read(frame) && bits_to_extract > 0) {
        uint64_t seed = deriveFrameSeed(base_seed, static_cast<uint64_t>(frame_index));
        std::vector<int> positions = makeShuffledPositions(frame.rows, frame.cols, seed);
        extractBitsFromFrame(frame, extracted_bits, bits_to_extract, positions);
        frame_index++;
    }
    cap.release();

    if (extracted_bits.size() < 32) throw std::runtime_error("Could not extract data size from video.");
    uint32_t data_size = 0;
    for (int i = 0; i < 32; ++i) {
        if (extracted_bits[i]) data_size |= (1u << i);
    }
    return data_size;
}

void accumulateHistogram(const cv::Mat& frame, std::vector<long long>& hist) {
    cv::Mat gray;
    if (frame.channels() == 3) {
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
    } else {
        gray = frame;
    }
    for (int i = 0; i < gray.rows; ++i) {
        const unsigned char* row = gray.ptr<unsigned char>(i);
        for (int j = 0; j < gray.cols; ++j) {
            hist[row[j]]++;
        }
    }
}

void handleMetricsImage(const std::string& cover_path, const std::string& stego_path, const std::string& password, const std::string& output_prefix) {
    cv::Mat cover = cv::imread(cover_path, cv::IMREAD_COLOR);
    if (cover.empty()) throw std::runtime_error("Could not open cover image: " + cover_path);
    cv::Mat stego = cv::imread(stego_path, cv::IMREAD_COLOR);
    if (stego.empty()) throw std::runtime_error("Could not open stego image: " + stego_path);

    ensureOutputPrefixDir(output_prefix);

    if (cover.rows != stego.rows || cover.cols != stego.cols || cover.type() != stego.type()) {
        throw std::runtime_error("Cover and stego images must have the same size and type.");
    }

    double psnr = computePSNR(cover, stego);
    double ssim = computeSSIM(cover, stego);
    double entropy_cover = computeEntropy(cover);
    double entropy_stego = computeEntropy(stego);

    uint32_t payload_size = getPayloadSizeFromImage(stego, password);
    double total_pixels = static_cast<double>(cover.rows) * cover.cols;
    double payload_bits = static_cast<double>(payload_size) * 8.0;
    double capacity_bpp = payload_bits / total_pixels;
    double capacity_bpp_with_header = (payload_bits + 32.0) / total_pixels;

    std::vector<int> cover_hist = computeHistogram(cover);
    std::vector<int> stego_hist = computeHistogram(stego);
    writeHistogramCsv(cover_hist, output_prefix + "_hist_cover.csv");
    writeHistogramCsv(stego_hist, output_prefix + "_hist_stego.csv");

    cv::Mat diff, diff_gray, diff_vis;
    cv::absdiff(cover, stego, diff);
    cv::cvtColor(diff, diff_gray, cv::COLOR_BGR2GRAY);
    diff_gray.convertTo(diff_vis, CV_8U, 255.0);
    if (!cv::imwrite(output_prefix + "_diff.png", diff_vis)) {
        throw std::runtime_error("Failed to write difference map image.");
    }

    std::ofstream summary(output_prefix + "_metrics.txt");
    if (!summary) throw std::runtime_error("Could not write metrics summary.");

    auto writeLine = [&](const std::string& key, const std::string& value) {
        std::cout << key << ": " << value << std::endl;
        summary << key << ": " << value << "\n";
    };

    writeLine("PSNR (dB)", std::isinf(psnr) ? "inf" : std::to_string(psnr));
    writeLine("SSIM", std::to_string(ssim));
    writeLine("Entropy (cover)", std::to_string(entropy_cover));
    writeLine("Entropy (stego)", std::to_string(entropy_stego));
    writeLine("Payload size (bytes)", std::to_string(payload_size));
    writeLine("Capacity (payload bits / pixel)", std::to_string(capacity_bpp));
    writeLine("Capacity (payload+header bits / pixel)", std::to_string(capacity_bpp_with_header));
    writeLine("Histogram (cover)", output_prefix + "_hist_cover.csv");
    writeLine("Histogram (stego)", output_prefix + "_hist_stego.csv");
    writeLine("Difference map", output_prefix + "_diff.png");
}

void handleMetricsVideo(const std::string& cover_path, const std::string& stego_path, const std::string& password, const std::string& output_prefix) {
    cv::VideoCapture cover_cap(cover_path);
    if (!cover_cap.isOpened()) throw std::runtime_error("Could not open cover video.");
    cv::VideoCapture stego_cap(stego_path);
    if (!stego_cap.isOpened()) throw std::runtime_error("Could not open stego video.");

    ensureOutputPrefixDir(output_prefix);

    cv::Mat cover_frame;
    cv::Mat stego_frame;
    double sse_total = 0.0;
    double ssim_sum = 0.0;
    double entropy_cover_sum = 0.0;
    double entropy_stego_sum = 0.0;
    long long frame_count = 0;
    int frame_rows = 0;
    int frame_cols = 0;
    int frame_channels = 0;

    std::vector<long long> cover_hist(256, 0);
    std::vector<long long> stego_hist(256, 0);
    bool wrote_diff = false;

    while (cover_cap.read(cover_frame) && stego_cap.read(stego_frame)) {
        if (cover_frame.rows != stego_frame.rows || cover_frame.cols != stego_frame.cols || cover_frame.type() != stego_frame.type()) {
            throw std::runtime_error("Cover and stego videos must have matching frame sizes and types.");
        }

        if (frame_count == 0) {
            frame_rows = cover_frame.rows;
            frame_cols = cover_frame.cols;
            frame_channels = cover_frame.channels();
        }

        sse_total += computeSSE(cover_frame, stego_frame);
        ssim_sum += computeSSIM(cover_frame, stego_frame);
        entropy_cover_sum += computeEntropy(cover_frame);
        entropy_stego_sum += computeEntropy(stego_frame);
        accumulateHistogram(cover_frame, cover_hist);
        accumulateHistogram(stego_frame, stego_hist);

        if (!wrote_diff) {
            cv::Mat diff, diff_gray, diff_vis;
            cv::absdiff(cover_frame, stego_frame, diff);
            cv::cvtColor(diff, diff_gray, cv::COLOR_BGR2GRAY);
            diff_gray.convertTo(diff_vis, CV_8U, 255.0);
            if (!cv::imwrite(output_prefix + "_diff_frame0.png", diff_vis)) {
                throw std::runtime_error("Failed to write difference map image.");
            }
            wrote_diff = true;
        }

        frame_count++;
    }

    if (frame_count == 0) throw std::runtime_error("No frames read from cover/stego videos.");

    uint32_t payload_size = getPayloadSizeFromVideo(stego_path, password);
    double total_pixels = static_cast<double>(frame_rows) * frame_cols * static_cast<double>(frame_count);
    double payload_bits = static_cast<double>(payload_size) * 8.0;
    double capacity_bpp = payload_bits / total_pixels;
    double capacity_bpp_with_header = (payload_bits + 32.0) / total_pixels;

    double total_samples = total_pixels * static_cast<double>(frame_channels);
    double mse = sse_total / total_samples;
    double avg_psnr = mse <= std::numeric_limits<double>::epsilon()
        ? std::numeric_limits<double>::infinity()
        : 10.0 * std::log10((255.0 * 255.0) / mse);
    double avg_ssim = ssim_sum / static_cast<double>(frame_count);
    double avg_entropy_cover = entropy_cover_sum / static_cast<double>(frame_count);
    double avg_entropy_stego = entropy_stego_sum / static_cast<double>(frame_count);

    writeHistogramCsvLL(cover_hist, output_prefix + "_hist_cover.csv");
    writeHistogramCsvLL(stego_hist, output_prefix + "_hist_stego.csv");

    std::ofstream summary(output_prefix + "_metrics.txt");
    if (!summary) throw std::runtime_error("Could not write metrics summary.");

    auto writeLine = [&](const std::string& key, const std::string& value) {
        std::cout << key << ": " << value << std::endl;
        summary << key << ": " << value << "\n";
    };

    writeLine("Frames processed", std::to_string(frame_count));
    writeLine("Average PSNR (dB)", std::isinf(avg_psnr) ? "inf" : std::to_string(avg_psnr));
    writeLine("Average SSIM", std::to_string(avg_ssim));
    writeLine("Average Entropy (cover)", std::to_string(avg_entropy_cover));
    writeLine("Average Entropy (stego)", std::to_string(avg_entropy_stego));
    writeLine("Payload size (bytes)", std::to_string(payload_size));
    writeLine("Capacity (payload bits / pixel)", std::to_string(capacity_bpp));
    writeLine("Capacity (payload+header bits / pixel)", std::to_string(capacity_bpp_with_header));
    writeLine("Histogram (cover)", output_prefix + "_hist_cover.csv");
    writeLine("Histogram (stego)", output_prefix + "_hist_stego.csv");
    writeLine("Difference map (first frame)", output_prefix + "_diff_frame0.png");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];

    try {
        if (mode == "hide" && argc == 6) {
            std::string cover_path = argv[2];
            std::string secret_path = argv[3];
            std::string output_path = argv[4];
            std::string password = argv[5];

            std::ifstream secret_file(secret_path, std::ios::binary);
            if (!secret_file) throw std::runtime_error("Could not open secret file: " + secret_path);
            std::vector<unsigned char> secret_data((std::istreambuf_iterator<char>(secret_file)), std::istreambuf_iterator<char>());

            std::cout << "Encrypting data..." << std::endl;
            std::vector<unsigned char> encrypted_data = encrypt(secret_data, password);

            if (isImageFile(cover_path)) {
                handleHideImage(cover_path, encrypted_data, output_path, password);
            } else if (isVideoFile(cover_path)) {
                handleHideVideo(cover_path, encrypted_data, output_path, password);
            } else {
                throw std::runtime_error("Unsupported cover file format. Use PNG/BMP for images or AVI/MP4 for videos.");
            }

        } else if (mode == "extract" && argc == 5) {
            std::string stego_path = argv[2];
            std::string output_path = argv[3];
            std::string password = argv[4];
            
            std::vector<unsigned char> encrypted_data;
            if (isImageFile(stego_path)) {
                encrypted_data = handleExtractImage(stego_path, password);
            } else if (isVideoFile(stego_path)) {
                encrypted_data = handleExtractVideo(stego_path, password);
            } else {
                throw std::runtime_error("Unsupported stego file format. Use PNG/BMP or AVI.");
            }

            std::cout << "Decrypting data..." << std::endl;
            std::vector<unsigned char> decrypted_data = decrypt(encrypted_data, password);
            
            std::ofstream output_file(output_path, std::ios::binary);
            if (!output_file) throw std::runtime_error("Could not open output file for writing: " + output_path);
            output_file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());

            std::cout << "Successfully extracted secret data to " << output_path << std::endl;

        } else if (mode == "metrics" && argc == 6) {
            std::string cover_path = argv[2];
            std::string stego_path = argv[3];
            std::string password = argv[4];
            std::string output_prefix = argv[5];

            bool cover_is_image = isImageFile(cover_path);
            bool stego_is_image = isImageFile(stego_path);
            bool cover_is_video = isVideoFile(cover_path);
            bool stego_is_video = isVideoFile(stego_path);

            if (cover_is_image && stego_is_image) {
                handleMetricsImage(cover_path, stego_path, password, output_prefix);
            } else if (cover_is_video && stego_is_video) {
                handleMetricsVideo(cover_path, stego_path, password, output_prefix);
            } else {
                throw std::runtime_error("Metrics mode requires both inputs to be images or both to be videos.");
            }

        } else {
            printUsage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
