#pragma once


#include <thread>
#include <atomic>
#include <memory>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <mutex>
#include <condition_variable>


template <typename T>
class limitQ
{
public:
	limitQ()  { ; }
	~limitQ() { ; }
	void push(const T & val)
	{
		std::lock_guard<std::mutex> lck (lock);
		m_queue.push(val);
	}
	bool pop(T & value)
	{
		std::lock_guard<std::mutex> lck (lock);
		bool rtn = false;
		if( !m_queue.empty() )
		{
			value = std::move( m_queue.front());
			m_queue.pop();
			rtn = true;
		}

		return rtn;
	}

	size_t size() const
	{
		std::lock_guard<std::mutex> lck (lock);
		return m_queue.size();
	}

	void clear() {
		std::lock_guard<std::mutex> lck (lock);
		m_queue = std::queue<T>();
	}

private:
	std::queue<T> m_queue;
	mutable std::mutex lock;

	limitQ(const limitQ & );
	limitQ & operator=(const limitQ & );
};

class apn_message {
public:

	apn_message() { ; }
	apn_message(const std::string & caller, const std::string & token, const std::string & display_name ) :
		m_caller(caller), m_token(token), m_display_name(display_name)

	{ ; }

	apn_message(const apn_message & message) {
		this->m_caller = message.m_caller;
		this->m_token = message.m_token;
		this->m_display_name = message.m_display_name;
	}

	const apn_message & operator=(const apn_message & message) {
		this->m_caller = message.m_caller;
		this->m_token = message.m_token;
		this->m_display_name = message.m_display_name;
		return * this;
	}

	std::string m_caller;
	std::string m_token;
	std::string m_display_name;
};

class apn_service {
public:
	apn_service(const std::string & push_serv_ip, const  std::string &  push_serv_port, const std::string & path_to_cred_dir );
	~apn_service();
	bool sendPush(const  apn_message & message);
	void stop();
	bool start();

private:
	const std::string m_push_serv_ip;
	const std::string m_push_serv_port;
	const std::string m_path_to_cred_dir;
	std::mutex m_mtx;

	class Detail;
	std::unique_ptr<Detail> m_impl;
};


