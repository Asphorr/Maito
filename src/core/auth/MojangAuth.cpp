#include "MojangAuth.h"
#include <curl/curl.h>
#include <json/json.h>
#include <stdexcept>
#include <iostream>
#include <thread>
#include <chrono>

class MojangAuth::Impl {
public:
    Impl() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~Impl() {
        curl_global_cleanup();
    }

    CURL* getCurl() {
        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
        return curl;
    }
};

MojangAuth::MojangAuth() : pImpl(std::make_unique<Impl>()) {}

MojangAuth::~MojangAuth() = default;

MojangAuth::MojangAuth(MojangAuth&&) noexcept = default;
MojangAuth& MojangAuth::operator=(MojangAuth&&) noexcept = default;

std::unique_ptr<AuthenticationResult> MojangAuth::authenticate(const std::string& username, const std::string& password) {
    CURL* curl = pImpl->getCurl();
    
    std::string payload = buildAuthPayload(username, password);
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/authenticate");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) {
        size_t newLength = size * nmemb;
        s->append((char*)contents, newLength);
        return newLength;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("CURL request failed: ") + curl_easy_strerror(res));
    }

    return parseAuthResponse(response);
}

void MojangAuth::authenticateAsync(const std::string& username, const std::string& password,
                                   std::function<void(std::unique_ptr<AuthenticationResult>)> callback) {
    std::thread([this, username, password, callback]() {
        try {
            auto result = authenticate(username, password);
            callback(std::move(result));
        } catch (const std::exception& e) {
            std::cerr << "Authentication failed: " << e.what() << std::endl;
            callback(nullptr);
        }
    }).detach();
}

bool MojangAuth::validateSession(const Session& session) {
    CURL* curl = pImpl->getCurl();
    
    Json::Value payload;
    payload["accessToken"] = session.getAccessToken();

    std::string jsonPayload = Json::FastWriter().write(payload);
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/validate");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) {
        size_t newLength = size * nmemb;
        s->append((char*)contents, newLength);
        return newLength;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return res == CURLE_OK && response.empty();
}

bool MojangAuth::refreshSession(Session& session) {
    CURL* curl = pImpl->getCurl();
    
    Json::Value payload;
    payload["accessToken"] = session.getAccessToken();
    payload["clientToken"] = session.getClientToken();

    std::string jsonPayload = Json::FastWriter().write(payload);
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/refresh");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) {
        size_t newLength = size * nmemb;
        s->append((char*)contents, newLength);
        return newLength;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return false;
    }

    try {
        auto refreshResult = parseAuthResponse(response);
        session.refresh(*refreshResult);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Session refresh failed: " << e.what() << std::endl;
        return false;
    }
}

void MojangAuth::invalidateSession(Session& session) {
    CURL* curl = pImpl->getCurl();
    
    Json::Value payload;
    payload["accessToken"] = session.getAccessToken();
    payload["clientToken"] = session.getClientToken();

    std::string jsonPayload = Json::FastWriter().write(payload);

    curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/invalidate");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        session = Session("", "", "", "");
    }
}

std::string MojangAuth::buildAuthPayload(const std::string& username, const std::string& password) {
    Json::Value payload;
    payload["agent"]["name"] = "Minecraft";
    payload["agent"]["version"] = 1;
    payload["username"] = username;
    payload["password"] = password;

    return Json::FastWriter().write(payload);
}

std::unique_ptr<AuthenticationResult> MojangAuth::parseAuthResponse(const std::string& response) {
    Json::Value root;
    Json::Reader reader;

    if (!reader.parse(response, root)) {
        throw std::runtime_error("Failed to parse authentication response");
    }

    if (root.isMember("error")) {
        throw std::runtime_error(root["errorMessage"].asString());
    }

    return std::make_unique<AuthenticationResult>(
        root["accessToken"].asString(),
        root["clientToken"].asString(),
        root["selectedProfile"]["name"].asString(),
        root["selectedProfile"]["id"].asString()
    );
}

AuthenticationResult::AuthenticationResult(std::string accessToken, std::string clientToken,
                                           std::string username, std::string uuid)
    : accessToken(std::move(accessToken)), clientToken(std::move(clientToken)),
      username(std::move(username)), uuid(std::move(uuid)) {}

Session::Session(std::string accessToken, std::string clientToken,
                 std::string username, std::string uuid)
    : accessToken(std::move(accessToken)), clientToken(std::move(clientToken)),
      username(std::move(username)), uuid(std::move(uuid)),
      expirationTime(std::chrono::system_clock::now() + std::chrono::hours(24)) {}

bool Session::isExpired() const {
    return std::chrono::system_clock::now() > expirationTime;
}

void Session::refresh(const AuthenticationResult& result) {
    accessToken = result.getAccessToken();
    clientToken = result.getClientToken();
    username = result.getUsername();
    uuid = result.getUUID();
    expirationTime = std::chrono::system_clock::now() + std::chrono::hours(24);
}

// Utility functions

std::string generateClientToken() {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int tokenLength = 32;
    std::string token;
    token.reserve(tokenLength);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    for (int i = 0; i < tokenLength; ++i) {
        token += charset[dis(gen)];
    }

    return token;
}

std::string base64Encode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    unsigned int in_len = input.size();
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.c_str());

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while(i++ < 3)
            encoded += '=';
    }

    return encoded;
}

// Error handling class
class AuthenticationError : public std::runtime_error {
public:
    AuthenticationError(const std::string& message) : std::runtime_error(message) {}
};

// Enhanced error handling in MojangAuth::authenticate
std::unique_ptr<AuthenticationResult> MojangAuth::authenticate(const std::string& username, const std::string& password) {
    CURL* curl = pImpl->getCurl();
    
    std::string payload = buildAuthPayload(username, password);
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, "https://authserver.mojang.com/authenticate");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* contents, size_t size, size_t nmemb, std::string* s) {
        size_t newLength = size * nmemb;
        s->append((char*)contents, newLength);
        return newLength;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw AuthenticationError(std::string("CURL request failed: ") + curl_easy_strerror(res));
    }

    if (http_code != 200) {
        Json::Value root;
        Json::Reader reader;
        if (reader.parse(response, root) && root.isMember("errorMessage")) {
            throw AuthenticationError("Authentication failed: " + root["errorMessage"].asString());
        } else {
            throw AuthenticationError("Authentication failed with HTTP code: " + std::to_string(http_code));
        }
    }

    return parseAuthResponse(response);
}

// Add this to the MojangAuth class
void MojangAuth::setProxy(const std::string& proxyUrl) {
    CURL* curl = pImpl->getCurl();
    curl_easy_setopt(curl, CURLOPT_PROXY, proxyUrl.c_str());
}

// Add this to improve security
void MojangAuth::setSSLVerification(bool verify) {
    CURL* curl = pImpl->getCurl();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
}
