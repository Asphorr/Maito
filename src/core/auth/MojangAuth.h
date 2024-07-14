#pragma once

#include <string>
#include <memory>
#include <functional>
#include <chrono>
#include <stdexcept>

class AuthenticationResult;
class Session;

class AuthenticationError : public std::runtime_error {
public:
    AuthenticationError(const std::string& message) : std::runtime_error(message) {}
};

class MojangAuth {
public:
    MojangAuth();
    ~MojangAuth();

    // Prevent copying
    MojangAuth(const MojangAuth&) = delete;
    MojangAuth& operator=(const MojangAuth&) = delete;

    // Allow moving
    MojangAuth(MojangAuth&&) noexcept;
    MojangAuth& operator=(MojangAuth&&) noexcept;

    // Main authentication method
    std::unique_ptr<AuthenticationResult> authenticate(const std::string& username, const std::string& password);

    // Session management
    bool validateSession(const Session& session);
    bool refreshSession(Session& session);
    void invalidateSession(Session& session);

    // Asynchronous authentication
    void authenticateAsync(const std::string& username, const std::string& password,
                           std::function<void(std::unique_ptr<AuthenticationResult>)> callback);

    // Configuration methods
    void setProxy(const std::string& proxyUrl);
    void setSSLVerification(bool verify);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    std::string buildAuthPayload(const std::string& username, const std::string& password);
    std::unique_ptr<AuthenticationResult> parseAuthResponse(const std::string& response);
};

class AuthenticationResult {
public:
    AuthenticationResult(std::string accessToken, std::string clientToken,
                         std::string username, std::string uuid);

    const std::string& getAccessToken() const { return accessToken; }
    const std::string& getClientToken() const { return clientToken; }
    const std::string& getUsername() const { return username; }
    const std::string& getUUID() const { return uuid; }

private:
    std::string accessToken;
    std::string clientToken;
    std::string username;
    std::string uuid;
};

class Session {
public:
    Session(std::string accessToken, std::string clientToken,
            std::string username, std::string uuid);

    bool isExpired() const;
    void refresh(const AuthenticationResult& result);

    const std::string& getAccessToken() const { return accessToken; }
    const std::string& getClientToken() const { return clientToken; }
    const std::string& getUsername() const { return username; }
    const std::string& getUUID() const { return uuid; }

private:
    std::string accessToken;
    std::string clientToken;
    std::string username;
    std::string uuid;
    std::chrono::system_clock::time_point expirationTime;
};

// Utility functions
std::string generateClientToken();
std::string base64Encode(const std::string& input);
