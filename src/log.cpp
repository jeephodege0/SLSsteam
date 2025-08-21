#include "log.hpp"
#include "config.hpp"

#include <cstdlib>
#include <memory>

CLog::CLog(const char* path) : path(path)
{
	ofstream = std::ofstream(path, std::ios::out);
	if (!ofstream.is_open())
	{
		throw std::runtime_error("Unable to open logfile!");
	}
}

CLog::~CLog()
{
	if (ofstream.is_open())
	{
		ofstream.close();
	}

	for(auto& msg : msgCache)
	{
		free(msg);
	}
}

//Dirty workaround for not being able to access g_config from __log
bool CLog::shouldNotify()
{
	return g_config.notifications;
}

CLog* CLog::createDefaultLog()
{
	const char* home = getenv("HOME");
	if (home)
	{
		std::stringstream ss;
		ss << home << "/.SLSsteam.log";

		return new CLog(ss.str().c_str());
	}

	return nullptr;
}

std::unique_ptr<CLog> g_pLog;
