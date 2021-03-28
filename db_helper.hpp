#pragma once
#include <switch.h>
#include <string>
#include <mutex>


static const std::string tokens_tbl_name = "tokens_tbl";
static const std::string login_colume_name = "login";
static const std::string token_colume_name = "token";

static const std::string create_table_tokens_sql = "CREATE TABLE IF NOT EXISTS " + tokens_tbl_name
		+ " ( "  + login_colume_name + " text UNIQUE NOT NULL ," + token_colume_name +  " text UNIQUE NOT NULL);";

static const std::string get_token_template = "select token from tokens_tbl where login = ";
static const std::string delete_token_template = "delete from " + tokens_tbl_name + " where token = '%s';";
static const std::string insert_token = "INSERT INTO " + tokens_tbl_name + " ( " + login_colume_name + " , " + token_colume_name + ") VALUES (\'%s\', \'%s\');";


inline
static switch_status_t limit_execute_sql(const char *dbname , char *sql, std::mutex *mutex)
{
	switch_core_db_t *db;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (mutex) {
		mutex->lock();
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "limit_execute_sql exex  %s\n", sql);

	if (!(db = switch_core_db_open_file(dbname))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening DB %s\n", dbname);
		status = SWITCH_STATUS_FALSE;
		goto end;
	}

	status = switch_core_db_persistant_execute(db, sql, 25);
	switch_core_db_close(db);

end:
	if (mutex) {
		mutex->unlock();
	}
	return status;
}

inline
static switch_bool_t limit_execute_sql_callback(const char *dbname,
												std::mutex  *mutex,
												char *sql,
												switch_core_db_callback_func_t callback,
												void *pdata)
{
	switch_bool_t ret = SWITCH_FALSE;
	switch_core_db_t *db;
	char *errmsg = NULL;

	if (mutex) {
		mutex->lock();
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "limit_execute_sql_callback exex  %s\n", sql);


	if (!(db = switch_core_db_open_file(dbname))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening DB %s\n", dbname);
		goto end;
	}


	switch_core_db_exec(db, sql, callback, pdata, &errmsg);

	if (errmsg) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SQL ERR: [%s] %s\n", sql, errmsg);
		free(errmsg);
	}

	if (db) {
		switch_core_db_close(db);
	}
end:

	if (mutex) {
		mutex->unlock();
	}



	return ret;

}
