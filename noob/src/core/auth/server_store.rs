//! opaque persistence

use anyhow::{Context, Result};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveModelTrait, ActiveValue, DatabaseConnection, EntityTrait};

use crate::core::crypto::opaque::OpaqueServer;
use crate::storage::{opaque_setup_store, opaque_user_store};

// load or generate on first run
pub async fn load_opaque_server(db: &DatabaseConnection) -> Result<OpaqueServer> {
    if let Some(row) = opaque_setup_store::Entity::find_by_id(opaque_setup_store::ROW_ID)
        .one(db)
        .await
        .context("load opaque server setup")?
    {
        return OpaqueServer::from_setup_bytes(&row.server_setup);
    }

    let server = OpaqueServer::new();
    opaque_setup_store::ActiveModel {
        id: ActiveValue::Set(opaque_setup_store::ROW_ID),
        server_setup: ActiveValue::Set(server.serialize_setup()),
    }
    .insert(db)
    .await
    .context("persist opaque server setup")?;
    Ok(server)
}

// per login lookup
pub async fn fetch_user(
    db: &DatabaseConnection,
    username: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let row = opaque_user_store::Entity::find_by_id(username.to_owned())
        .one(db)
        .await
        .context("fetch opaque user")?;
    Ok(row.map(|r| (r.registration_record, r.at_rest_blob)))
}

// upsert on register
pub async fn persist_registration(
    db: &DatabaseConnection,
    username: &str,
    registration_record: &[u8],
    at_rest_blob: &[u8],
) -> Result<()> {
    let model = opaque_user_store::ActiveModel {
        username: ActiveValue::Set(username.to_owned()),
        registration_record: ActiveValue::Set(registration_record.to_vec()),
        at_rest_blob: ActiveValue::Set(at_rest_blob.to_vec()),
    };
    opaque_user_store::Entity::insert(model)
        .on_conflict(
            OnConflict::column(opaque_user_store::Column::Username)
                .update_columns([
                    opaque_user_store::Column::RegistrationRecord,
                    opaque_user_store::Column::AtRestBlob,
                ])
                .to_owned(),
        )
        .exec(db)
        .await
        .context("persist opaque user registration")?;
    Ok(())
}
