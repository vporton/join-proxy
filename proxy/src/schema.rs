// @generated automatically by Diesel CLI.

diesel::table! {
    add_request_headers (id) {
        id -> Int4,
        server_setup_id -> Int8,
        header_name -> Text,
        header_value -> Text,
    }
}

diesel::table! {
    add_response_headers (id) {
        id -> Int4,
        server_setup_id -> Int8,
        header_name -> Text,
        header_value -> Text,
    }
}

diesel::table! {
    remove_request_headers (id) {
        id -> Int4,
        server_setup_id -> Int8,
        header_name -> Text,
    }
}

diesel::table! {
    remove_response_headers (id) {
        id -> Int4,
        server_setup_id -> Int8,
        header_name -> Text,
    }
}

diesel::table! {
    request (id) {
        id -> Int8,
        request_hash -> Bytea,
        certificate_hash -> Bytea,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Int8,
        token_hash -> Bytea,
        owner_principal -> Text,
        client_id -> Text,
        scope -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    server_setups (id) {
        id -> Int8,
        guid -> Bytea,
        user_id -> Int4,
        show_hit_miss -> Bool,
        add_forwarded_from_header -> Bool,
        connect_timeout -> Int4,
        read_timeout -> Int4,
        total_timeout -> Int4,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        user_principal -> Bytea,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    add_request_headers,
    add_response_headers,
    remove_request_headers,
    remove_response_headers,
    request,
    refresh_tokens,
    server_setups,
    users,
);
