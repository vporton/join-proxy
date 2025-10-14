use diesel::Selectable;

#[derive(Selectable)]
pub struct ServerSetup {
    user_id: String,
    show_hit_miss: bool,
    add_forwarded_from_header: bool,
    connect_timeout: u64,
    read_timeout: u64,
    total_timeout: u64,
}
