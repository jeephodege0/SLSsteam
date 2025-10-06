#pragma once

#include <string>
#include <locale>
#include <algorithm>
#include <iterator>


template <typename S_type>
S_type toLower(const S_type& in)
{
	S_type out;
	out.reserve(in.size()); // Pre-allocate memory to avoid reallocations
	const auto& loc = std::locale(); // Create locale object once for efficiency
	std::transform(in.begin(), in.end(), std::back_inserter(out), [&loc](typename S_type::value_type ch)
	{
		return std::tolower(ch, loc);
	});
	return out;
}