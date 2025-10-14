use diesel::{QueryableByName, Selectable};
use crate::schema::{server_setups, users};

#[derive(Selectable, QueryableByName)]
pub struct User {
    // id: i64,
    id: i32,
    user_principal: String, // TODO: BYTEA
}

#[derive(Selectable, QueryableByName)]
pub struct ServerSetup {
    // id: i64,
    // guid: String, // TODO: BYTEA
    user_id: i32,
    show_hit_miss: bool,
    add_forwarded_from_header: bool,
    connect_timeout: i32,
    read_timeout: i32,
    total_timeout: i32,
}
