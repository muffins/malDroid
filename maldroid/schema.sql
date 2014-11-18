drop table if exists reports;
drop table if exists users;
create table reports (
  id integer primary key autoincrement,
  digest text not null,
  comname text,
  tstamp integer not null,
  report text not null
);
create table users (
  id integer primary key autoincrement,
  username text not null,
  password text not null,
  timestamp integer not null
);
