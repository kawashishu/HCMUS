#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <algorithm>

// Namespace cho tiện
namespace fs = std::filesystem;

// Cấu trúc để lưu chữ ký bắt đầu và kết thúc
struct Signature {
    std::vector<unsigned char> start;
    std::vector<unsigned char> end;
};

/**
 * Hàm tìm vị trí pattern trong data, bắt đầu từ start_pos.
 * Trả về std::string::npos nếu không tìm thấy.
 */
size_t find_signature(const std::vector<unsigned char>& data,
                      const std::vector<unsigned char>& pattern,
                      size_t start_pos = 0)
{
    if (pattern.empty() || start_pos >= data.size()) {
        return std::string::npos;
    }
    auto it = std::search(data.begin() + start_pos, data.end(),
                          pattern.begin(), pattern.end());
    if (it != data.end()) {
        return std::distance(data.begin(), it);
    }
    return std::string::npos;
}

/**
 * Hàm tìm chữ ký bắt đầu (của tất cả định dạng) và lấy ra
 * vị trí sớm nhất (nếu có).
 *
 * - Trả về (foundExt, foundPos).
 *   + foundExt: phần mở rộng (ext) tìm được. Rỗng nếu không tìm thấy.
 *   + foundPos: vị trí tìm thấy start signature. npos nếu không tìm thấy.
 */
std::pair<std::string, size_t> search_next_signature(
    const std::vector<unsigned char>& buffer,
    const std::unordered_map<std::string, Signature>& signatures,
    size_t offset)
{
    std::string foundExt;
    size_t foundPos = std::string::npos;

    // Dò tất cả các định dạng (jpg, png), lấy vị trí sớm nhất
    for (const auto& [ext, sig] : signatures) {
        size_t pos = find_signature(buffer, sig.start, offset);
        if (pos != std::string::npos) {
            // Lần đầu tìm hoặc là vị trí này sớm hơn vị trí cũ
            if (foundPos == std::string::npos || pos < foundPos) {
                foundPos = pos;
                foundExt = ext;
            }
        }
    }

    return std::make_pair(foundExt, foundPos);
}

int main()
{
    std::string volume_file = "Image00.Vol";
    std::string output_directory = "recovered_images";

    // Định nghĩa chữ ký cho JPG và PNG
    std::unordered_map<std::string, Signature> signatures;
    signatures["jpg"] = {
        {0xFF, 0xD8, 0xFF},      // Start JPG
        {0xFF, 0xD9}             // End JPG
    };
    signatures["png"] = {
        {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, // Start PNG
        {0x49, 0x45, 0x4E, 0x44, 
         static_cast<unsigned char>(0xAE), 
         0x42, 
         0x60, 
         static_cast<unsigned char>(0x82)} // End PNG
    };

    // Tạo thư mục đầu ra nếu chưa tồn tại
    if (!fs::exists(output_directory)) {
        if (!fs::create_directory(output_directory)) {
            std::cerr << "Không thể tạo thư mục đầu ra: " << output_directory << std::endl;
            return 1;
        }
    }

    // Đọc toàn bộ dữ liệu từ file volume
    std::ifstream infile(volume_file, std::ios::binary | std::ios::ate);
    if (!infile) {
        std::cerr << "Không thể mở file: " << volume_file << std::endl;
        return 1;
    }

    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!infile.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Không thể đọc dữ liệu từ file: " << volume_file << std::endl;
        return 1;
    }
    infile.close();


    // Biến đếm số lượng file tìm được cho mỗi loại
    std::unordered_map<std::string, int> file_count;
    for (const auto& [ext, _] : signatures) {
        file_count[ext] = 0;
    }

    size_t offset = 0;
    // Bắt đầu quét đến khi không còn tìm thấy signature nào nữa
    while (true) {
        auto [foundExt, foundStart] = search_next_signature(buffer, signatures, offset);
        if (foundStart == std::string::npos) {
            // Không tìm thấy start signature tiếp theo, thoát
            break;
        }

        // Tìm end signature tương ứng với định dạng vừa tìm thấy
        const auto& sig = signatures[foundExt];
        size_t endPos = find_signature(buffer, sig.end, foundStart + sig.start.size());
        if (endPos == std::string::npos) {
            // Không tìm thấy end, có thể file bị hỏng hoặc chỉ có partial
            // -> Hoặc ta bỏ qua, hoặc cắt luôn đến cuối file.
            // Ở đây ta bỏ qua cho đơn giản.
            offset = foundStart + 1;  // Tiếp tục thử tìm start khác
            continue;
        }

        // Tính end thực sự (bao gồm cả kích thước end signature)
        endPos += sig.end.size();

        // Trích xuất dữ liệu ảnh
        std::vector<unsigned char> image_data(
            buffer.begin() + foundStart,
            buffer.begin() + endPos
        );

        // Tăng biến đếm và tạo tên file
        file_count[foundExt]++;
        std::string image_filename =
            "image_" + std::to_string(file_count[foundExt]) + "." + foundExt;
        fs::path image_path = fs::path(output_directory) / image_filename;

        // Ghi file ảnh ra ổ cứng
        std::ofstream outfile(image_path, std::ios::binary);
        if (!outfile) {
            std::cerr << "Không thể tạo file ảnh: "
                      << image_path.string() << std::endl;
            return 1;
        }
        outfile.write(reinterpret_cast<const char*>(image_data.data()),
                      static_cast<std::streamsize>(image_data.size()));
        outfile.close();

        std::cout << "[+] Phục hồi: " << image_filename
                  << " (offset " << foundStart
                  << " -> " << endPos << ")\n";

        // Sau khi tách xong, thay vì nhảy đến endPos,
        // ta chỉ nhảy offset thêm 1 byte để không bỏ lỡ
        // các signature khác có thể nằm “gối” vùng này
        offset = foundStart + 1;
    }

    // In kết quả
    std::cout << "Hoàn tất phục hồi.\n";
    for (const auto& [ext, count] : file_count) {
        std::cout << "Tổng số file " << ext << " phục hồi: " << count << std::endl;
    }

    return 0;
}
