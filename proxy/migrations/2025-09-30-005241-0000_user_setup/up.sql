CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    user_principal BYTEA NOT NULL
);

CREATE INDEX user_user_principal_idx ON users (user_principal);

CREATE TABLE server_setup (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    show_hit_miss BOOLEAN NOT NULL,
    add_forwarded_from_header BOOLEAN NOT NULL,
    connect_timeout INT NOT NULL,
    read_timeout INT NOT NULL,
    total_timeout INT NOT NULL
);

CREATE INDEX server_setup_user_id_idx ON server_setup (user_id);

CREATE TABLE add_request_header (
    id SERIAL PRIMARY KEY,
    server_setup_id INT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL
);

CREATE INDEX add_request_header_server_setup_id_idx ON add_request_header (server_setup_id);

CREATE TABLE remove_request_header (
    id SERIAL PRIMARY KEY,
    server_setup_id INT NOT NULL,
    header_name TEXT NOT NULL
);
    
CREATE INDEX remove_request_header_server_setup_id_idx ON remove_request_header (server_setup_id);

CREATE TABLE add_response_header (
    id SERIAL PRIMARY KEY,
    server_setup_id INT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL
);

CREATE INDEX add_response_header_server_setup_id_idx ON add_response_header (server_setup_id);

CREATE TABLE remove_response_header (
    id SERIAL PRIMARY KEY,
    server_setup_id INT NOT NULL,
    header_name TEXT NOT NULL
);
    
CREATE INDEX remove_response_header_server_setup_id_idx ON remove_response_header (server_setup_id);

