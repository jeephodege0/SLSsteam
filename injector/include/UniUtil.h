#pragma once

#include <Windows.h>
#include <string>
#include <stdexcept> // For std::runtime_error

/**
 * \brief Converts a wide string (UTF-16 on Windows) to a UTF-8 encoded narrow string.
 * \param wstr The wide string to convert.
 * \return The UTF-8 encoded narrow string.
 * \throws std::runtime_error on failure.
 */
inline std::string ConvertWideToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();

    int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), NULL, 0, NULL, NULL);
    if (count == 0)
    {
        throw std::runtime_error("Failed to calculate buffer size for wide to UTF-8 conversion.");
    }

    std::string str(count, 0);
    int result = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), &str[0], count, NULL, NULL);
    if (result == 0)
    {
        throw std::runtime_error("Failed to convert wide string to UTF-8.");
    }
    
    return str;
}

/**
 * \brief Converts a UTF-8 encoded narrow string to a wide string (UTF-16 on Windows).
 * \param utf8 The UTF-8 encoded narrow string.
 * \return The converted wide string.
 * \throws std::runtime_error on failure.
 */
inline std::wstring ConvertUtf8ToWide(const std::string& utf8)
{
	if (utf8.empty())
	{
		return std::wstring();
	}

	const auto wideCharCount = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
	if (wideCharCount == 0)
	{
		throw std::runtime_error("Failed to calculate buffer size for UTF-8 to wide conversion.");
	}

	std::wstring wstr;
	wstr.resize(wideCharCount);

	int result = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), &wstr[0], wideCharCount);
	if (result == 0)
	{
		throw std::runtime_error("Failed to convert UTF-8 string to wide.");
	}
	
	return wstr;
}