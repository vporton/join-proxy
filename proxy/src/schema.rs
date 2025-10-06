// @generated automatically by Diesel CLI.

diesel::table! {
    add_request_header (id) {
        id -> Int4,
        server_setup_id -> Int4,
        header_name -> Text,
        header_value -> Text,
    }
}

diesel::table! {
    remove_request_header (id) {
        id -> Int4,
        server_setup_id -> Int4,
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
    server_setup (id) {
        id -> Int4,
        user_id -> Int4,
        server_prefix -> Text,
        show_hit_miss -> Bool,
        add_forwarded_from_header -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        user_principal -> Bytea,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    add_request_header,
    remove_request_header,
    request,
    server_setup,
    users,
);
