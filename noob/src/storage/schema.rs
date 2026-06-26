//! auth tables

use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Schema};

use super::{client_enrollment_store, identity_store, opaque_setup_store, opaque_user_store};

// create if missing
pub async fn ensure_node_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);

    let stmts: [TableCreateStatement; 4] = [
        schema.create_table_from_entity(identity_store::Entity),
        schema.create_table_from_entity(opaque_setup_store::Entity),
        schema.create_table_from_entity(opaque_user_store::Entity),
        schema.create_table_from_entity(client_enrollment_store::Entity),
    ];

    for mut stmt in stmts {
        stmt.if_not_exists();
        db.execute(backend.build(&stmt)).await?;
    }
    Ok(())
}
