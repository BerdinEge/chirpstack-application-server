CREATE TABLE IF NOT EXISTS device_down (
    id uuid primary key,
    sent_at timestamp with time zone not null,
    dev_eui bytea not null,
    device_name varchar(100) not null,
    application_id bigint not null,
    application_name varchar(100) not null,
    frequency bigint not null,
    dr smallint not null,
    adr boolean not null,
    f_cnt bigint not null,
    f_port smallint not null,
    data bytea not null,
    tx_info jsonb not null,
    object jsonb not null,
    tags hstore not null,
    confirmed_downlink boolean not null,
    dev_addr bytea not null
);