#include "apn_service.h"
#include <iostream>
#include <mutex>
#include <curl/curl.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>


const static std::string private_key = "private_key.pem";
const static std::string certificate = "certificate.pem";
const static std::string JsonData = "{\"aps\":{\"alert\":\"Call\",\"sound\":\"default\"},\"dname\": \"%s\", \"caller\": \"%s\"}";
const static unsigned htttp2_timeout_ms = 20000;



//#define LOG_TO_STDOUT
#ifdef LOG_TO_STDOUT
#else
#include <switch.h>
#endif

static void log_impl( const char * format, ...){
#ifdef LOG_TO_STDOUT
	char buffer[4096]= { 0 };
	va_list args;
	va_start (args, format);
	vsnprintf (buffer,sizeof(buffer),format, args);
	fprintf(stderr, "=>  %s", buffer);
	va_end (args);
#else

	char buffer[4096]= { 0 };
	va_list args;
	va_start (args, format);
	vsnprintf (buffer,sizeof(buffer),format, args);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,  "fs=> %s", buffer);
	va_end (args);

#endif

}

class apn_service::Detail{
public:

	static
	void dump(const char *text, int num, unsigned char *ptr, size_t size,
			  char nohex)
	{
		size_t i;
		size_t c;
		unsigned int width=0x10;

		if(nohex)
			/* without the hex output, we can fit more on screen */
			width = 0x40;

		fprintf(stderr, "%d %s, %ld bytes (0x%lx)\n",
				num, text, (long)size, (long)size);

		for(i=0; i<size; i+= width) {

			fprintf(stderr, "%4.4lx: ", (long)i);

			if(!nohex) {
				/* hex not disabled, show it */
				for(c = 0; c < width; c++)
					if(i+c < size)
						fprintf(stderr, "%02x ", ptr[i+c]);
					else
						fputs("   ", stderr);
			}

			for(c = 0; (c < width) && (i+c < size); c++) {
				/* check for 0D0A; if found, skip past and start a new line of output */
				if(nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
					i+=(c+2-width);
					break;
				}
				fprintf(stderr, "%c",
						(ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
				/* check again for 0D0A, to avoid an extra \n if it's at width */
				if(nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
					i+=(c+3-width);
					break;
				}
			}
			fputc('\n', stderr); /* newline */
		}
	}



	static
	int trace(CURL *handle, curl_infotype type,
			  char *data, size_t size,
			  void *userp)
	{
		char timebuf[20];
		const char *text;
		//  int num = hnd2num(handle);
		static time_t epoch_offset;
		static int    known_offset;
		struct timeval tv;
		time_t secs;
		struct tm *now;

		(void)handle; /* prevent compiler warning */
		(void)userp;

		gettimeofday(&tv, NULL);
		if(!known_offset) {
			epoch_offset = time(NULL) - tv.tv_sec;
			known_offset = 1;
		}
		secs = epoch_offset + tv.tv_sec;
		now = localtime(&secs);  /* not thread safe but we don't care */
		snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
				 now->tm_hour, now->tm_min, now->tm_sec, (long)tv.tv_usec);

		switch(type) {
		case CURLINFO_TEXT:
			fprintf(stderr, "%s [%d] Info: %s", timebuf, 0, data);
		default: /* in case a new one is introduced to shock us */
			return 0;

		case CURLINFO_HEADER_OUT:
			text = "=> Send header";
			break;
		case CURLINFO_DATA_OUT:
			text = "=> Send data";
			break;
		case CURLINFO_SSL_DATA_OUT:
			text = "=> Send SSL data";
			break;
		case CURLINFO_HEADER_IN:
			text = "<= Recv header";
			break;
		case CURLINFO_DATA_IN:
			text = "<= Recv data";
			break;
		case CURLINFO_SSL_DATA_IN:
			text = "<= Recv SSL data";
			break;
		}

		dump(text, 0, (unsigned char *)data, size, 1);
		return 0;
	}


	Detail(const std::string & cred_path, const std::string & push_serv_ip, const std::string & push_serv_port) :
		chunk(NULL),
		curl(curl_easy_init()),
		m_pkey_path(cred_path + "/" + private_key),
		m_cert_path(cred_path + "/" + certificate),
		m_device_url_templ("https://" + push_serv_ip + ":" + push_serv_port + "/3/device/")

	{
		assert(curl != NULL);

		log_impl( "apn_service::Detail pkey: %s, cert: %s , url_templ: %s\n",
				  m_pkey_path.c_str(),
				  m_cert_path.c_str(),
				  m_device_url_templ.c_str()
				  );

		chunk = curl_slist_append(chunk, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, htttp2_timeout_ms);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

		curl_easy_setopt(curl,CURLOPT_SSLCERT,m_cert_path.c_str());
		curl_easy_setopt(curl,CURLOPT_SSLCERTTYPE,"PEM");
		curl_easy_setopt(curl,CURLOPT_SSLKEY,m_pkey_path.c_str());
		curl_easy_setopt(curl,CURLOPT_SSLKEYTYPE,"PEM");

		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		//		 curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, trace);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

	}

	void init() {
		curl_global_init(CURL_GLOBAL_DEFAULT);
	}

	void deinit() {
		curl_global_cleanup();
	}

	int sendPush(const  apn_message & message) {

		const std::string sendUrl(m_device_url_templ + message.m_token);

		char c_json_payload[256] = { 0 };
		snprintf(c_json_payload, sizeof(c_json_payload), JsonData.c_str(),   message.m_display_name.c_str(), message.m_caller.c_str());
		std::cerr << "c_json_payload " << std::string(c_json_payload) << std::endl;
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, c_json_payload);

		curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());

		CURLcode res = curl_easy_perform(curl);
		curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);


		std::string str_status;
		if(res != CURLE_OK){
			str_status= "CURLE_FAIL";
		}
		else {
			if(http_code == 200 ) {
				str_status = "CURLE_OK";
			} else {
				str_status= "CURLE_FAIL";
			}
		}


		log_impl("apn_service::Detail::sendPush  [%s]  %s, %d  %s\n",
				 str_status.c_str(),
				 sendUrl.c_str(),
				 (int)http_code,
				 curl_easy_strerror(res)
				 );

		return http_code;
	}

	long http_code = 0;
	struct curl_slist *chunk;;
	CURL* curl;
	const std::string m_device_url_templ;
	const std::string m_pkey_path;
	const std::string m_cert_path;
};

apn_service::apn_service(
		const std::string & push_serv_ip,
		const  std::string &  push_serv_port,
		const std::string & path_to_cred_dir) :
	m_push_serv_ip(push_serv_ip ),
	m_push_serv_port(push_serv_port),
	m_path_to_cred_dir(path_to_cred_dir)

{
	this->m_impl.reset(new apn_service::Detail(m_path_to_cred_dir, m_push_serv_ip, m_push_serv_port));
}

bool
apn_service::start() {
	bool ret(true);

	log_impl( "apn_service::start  %s, %s \n",
			  m_push_serv_ip.c_str(),
			  m_push_serv_port.c_str()
			  );

	std::lock_guard<std::mutex> lock(m_mtx);
	m_impl->init();

	return ret;
}

apn_service::~apn_service() {
	//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,  "apn_service::~apn_service\n");
	printf("apn_service::~apn_service\n");
	std::lock_guard<std::mutex> lock(m_mtx);
	m_impl->deinit();
}

bool apn_service::sendPush(const  apn_message & message) {
	std::lock_guard<std::mutex> lock(m_mtx);
	int http_code = m_impl->sendPush(message);
	if(http_code != 200){
		return false;
	}
	return true;
}

void apn_service::stop() {

}

