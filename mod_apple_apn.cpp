/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * mod_apple_apn.cpp -- send ios push tocken on call
 * example <action application="sendIosPush" data="${destination_number},${caller_id_number},${caller_id_name}"/>
 */

#include <stdexcept>
#include <thread>
#include <stdio.h>

#include <switch.h>
#include <atomic>
#include <memory>
#include <sstream>
#include "db_helper.hpp"
#include "apn_service.h"
#include "pugixml.hpp"

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_apple_apn_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_apple_apn_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_apple_apn_load);


SWITCH_MODULE_DEFINITION(mod_apple_apn, mod_apple_apn_load, mod_apple_apn_shutdown, mod_apple_apn_runtime);

static int on_fetch_token_callback(void *pArg, int argc, char **argv, char **columnNames);
static struct{
	char *cert_path;
	char * dbname;
	char *aps_ip;
	char *aps_port;

	std::mutex db_mutex;
	std::atomic<bool> looping;

	std::shared_ptr<apn_service>  g_apn_service;
	limitQ<apn_message> g_TokenQ;
} globals;


static switch_xml_config_item_t instructions[] = {
	/* parameter name        type                 reloadable   pointer                         default value     options structure */
	SWITCH_CONFIG_ITEM_STRING_STRDUP("cert_path", CONFIG_RELOAD, &globals.cert_path, NULL, NULL, "APS server connect creditionals path"),
	SWITCH_CONFIG_ITEM_STRING_STRDUP("db_name", CONFIG_RELOAD, &globals.dbname, NULL, NULL, "Token db path"),
	SWITCH_CONFIG_ITEM_STRING_STRDUP("aps_host", CONFIG_RELOAD, &globals.aps_ip, NULL, NULL, "APS server ip"),
	SWITCH_CONFIG_ITEM_STRING_STRDUP("aps_port", CONFIG_RELOAD, &globals.aps_port, NULL, NULL, "APS server port"),
	SWITCH_CONFIG_ITEM_END()
};

const static std::string req_abonents_store_ios_token = "req_abonents_store_ios_token";
const static std::string ios_token_attr = "ios_token";
const static unsigned wait_ios_awakening = 10;

static inline void print_thread_id(){
	std::thread::id this_id = std::this_thread::get_id();
	std::stringstream ss;
	ss << this_id;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, ">>>>> print_thread_id %s\n", ss.str().c_str());
}

static bool checking_abonent_online(const std::string & abonent) {
	switch_status_t status;
	switch_stream_handle_t stream = { 0 };
	bool ret(false);

	SWITCH_STANDARD_STREAM(stream);

	if ((status = switch_api_execute("sofia_contact", abonent.c_str(), NULL, &stream)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "sofia_contact '%s' failed. status: %d \n", abonent.c_str(), status );
		switch_safe_free(stream.data);
		return false;
	}

	//	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "stream.data %s \n", (char*)stream.data);
	if(stream.data != NULL && std::string((char*)stream.data).find("user_not_registered") == std::string::npos)  {
		// result sofia_contact abonent != user_not_registered
		ret = true;
	}
	switch_safe_free(stream.data);
	return ret;
}

static void dialplan_sleep(switch_core_session_t * session, int sec) {
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "dialplan_sleep %d sec\n", sec);
	switch_ivr_sleep(session, sec * 1000, SWITCH_TRUE, NULL);
}

static void split_line(std::vector<std::string> & tokens, const std::string & line, char delimeter) {
	std::istringstream ss(line);
	std::string token;
	while(std::getline(ss, token, delimeter)) {
		tokens.push_back(token);
	}
}


enum send_ios_push_args{
	destination_number = 0, caller_id_number, caller_id_name
};

SWITCH_STANDARD_APP(send_ios_push)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "send_ios_push start%s\n", (char*)data);
	print_thread_id();

	if(zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>>>>>> send_ios_push data is NULL\n");
		return;
	}

	std::vector<std::string>  args;
	std::string arg_line((char*)data);
	split_line(args,arg_line,',');

	if(args.size() != 3) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>>>>>> send_ios_push count args != 3 (destination_number,caller_id_number,caller_id_name)\n");
		return;
	}


	std::string callee_abonent(args[destination_number]);
	std::string token_value;
	std::string token_value_sql = get_token_template + callee_abonent;
	limit_execute_sql_callback((char*)globals.dbname,
							   &globals.db_mutex,
							   const_cast<char*>(token_value_sql.data()),
							   on_fetch_token_callback, &token_value);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "token_value  %s\n", token_value.c_str());

	if(!token_value.empty()) {
		dialplan_sleep(session, 2);
		if(checking_abonent_online(callee_abonent)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>> mod_apple_apn_mod_apple_apn_runtime user %s ALREDY AVALIBLE FOR CALL\n", callee_abonent.c_str());
		} else {

			apn_message message(args[caller_id_number], token_value, args[caller_id_name]);
			globals.g_TokenQ.push(message);
			unsigned count = wait_ios_awakening;

			while(count -- && !checking_abonent_online(callee_abonent)) {
				dialplan_sleep(session, 2);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "checking_abonent_online  count %d\n", count);
			}
			if(!count) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>> mod_apple_apn_mod_apple_apn_runtime user %s NOW AVALIBLE FOR CALL\n", callee_abonent.c_str());
			}
		}
	}
}


SWITCH_STANDARD_CHAT_APP(store_token_function)
{
	//	action application="storeIosToken" data=""/>

	switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
	const char *from_user = switch_event_get_header(message, "from_user");
	const char *body = switch_event_get_body(message);

	if(zstr(from_user)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>>>>>> store_token_function from_user is NULL\n");
		return SWITCH_STATUS_FALSE;
	}

	if(zstr(body)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>>>>>> store_token_function body is NULL\n");
		return SWITCH_STATUS_FALSE;
	}

	pugi::xml_document doc;
	pugi::xml_parse_result result = doc.load_string(body);
	if(!result) {
		return SWITCH_STATUS_FALSE;
	}


	pugi::xml_node panels = doc.child(req_abonents_store_ios_token.c_str());
	if(panels.empty()) {
		return SWITCH_STATUS_FALSE;
	}

	std::string ios_token;
	for (pugi::xml_node panel = panels.first_child(); panel; panel = panel.next_sibling()){
		for (pugi::xml_attribute attr = panel.first_attribute(); attr; attr = attr.next_attribute()) {
			//    		 sc_log::err("attr.name()", std::string(attr.name()), "attr.value()", attr.value());
			if(std::string(attr.name()) == ios_token_attr) {
				ios_token = std::string(attr.value());
			}
		}
	}

	if(ios_token.empty()) {
		return SWITCH_STATUS_FALSE;
	}

	char sql[4096] = { 0 };
	snprintf(sql, sizeof(sql), delete_token_template.c_str(), ios_token.c_str());
	limit_execute_sql((char*)globals.dbname, (char*)sql, &globals.db_mutex);

	memset(sql, 0, sizeof(sql));
	snprintf(sql, sizeof(sql), insert_token.c_str(), from_user, ios_token.c_str());
	switch_status = limit_execute_sql((char*)globals.dbname, (char*)sql, &globals.db_mutex);
	if(switch_status == SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}


/* Macro expands to: switch_status_t mod_skel_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool) */
SWITCH_MODULE_LOAD_FUNCTION(mod_apple_apn_load)
{

	switch_application_interface_t *app_interface;
	switch_chat_application_interface_t *chat_app_interface;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>> mod_apple_apn_load\n");
	print_thread_id();
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	if (switch_xml_config_parse_module_settings("securevoip.conf", SWITCH_FALSE, instructions) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, ">>>>> mod_apple_apn_load error load securevoip.conf \n");
		return SWITCH_STATUS_FALSE;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>> mod_apple_apn_load globals.cert_path %s\n", (char*)globals.cert_path);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, ">>>>> mod_apple_apn_load global.dbname %s\n", (char*)globals.dbname);


	SWITCH_ADD_APP(app_interface, "sendIosPush", "send IOS push", "Send IOS Push", send_ios_push, "<push token>", SAF_SUPPORT_NOMEDIA | SAF_ZOMBIE_EXEC);
	SWITCH_ADD_CHAT_APP(chat_app_interface, "storeIosToken", "Store Ios Token", "", store_token_function, "", SCAF_NONE);

	globals.looping = true;
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_skel_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_apple_apn_shutdown)
{
	globals.looping = false;
	switch_xml_config_cleanup(instructions);
	return SWITCH_STATUS_SUCCESS;
}



SWITCH_MODULE_RUNTIME_FUNCTION(mod_apple_apn_runtime)
{

	switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
	std::shared_ptr<apn_service> m_apn_service;
	const std::string apn_ip(globals.aps_ip);
	const std::string apn_port(globals.aps_port);
	const std::string apn_cert_path(globals.cert_path);

	m_apn_service.reset(new apn_service(apn_ip, apn_port,apn_cert_path));

	switch_status = limit_execute_sql((char*)globals.dbname, (char*)create_table_tokens_sql.data(), NULL);
	if(switch_status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, ">>>>> mod_apple_apn_load  \n");
		return SWITCH_STATUS_FALSE;
	}

	bool ret = m_apn_service->start();
	if(!ret){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, ">>>>> mod_apple_apn_load g_apn_service start \n");
		return SWITCH_STATUS_FALSE;
	}

	print_thread_id();
	apn_message message;

	while(globals.looping)
	{
		if(	globals.g_TokenQ.pop(message)) {
			m_apn_service->sendPush(message);
		} else {
			usleep(500);
		}

		switch_cond_next();
	}
	return SWITCH_STATUS_TERM;
}


static int on_fetch_token_callback(void *pArg, int argc, char **argv, char **columnNames) {

	std::string * token_value = reinterpret_cast<std::string*>(pArg);
	for  ( int x = 0; x < argc; x++) {
		if (columnNames[x] && argv[x]) {
			*token_value = std::string(argv[x]);
			//			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, ">>>>> on_fetch_token_callback  %s\n", argv[x]);
		}
	}
	return 0;
}


