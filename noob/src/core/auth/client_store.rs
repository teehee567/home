//! client enrollment persistence

use anyhow::{Context, Result};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue, DatabaseConnection, EntityTrait};

use super::types::ClientEnrollment;
use crate::storage::client_enrollment_store;

// none means not registered yet
pub async fn load_enrollment(db: &DatabaseConnection) -> Result<Option<ClientEnrollment>> {
    let Some(row) = client_enrollment_store::Entity::find_by_id(client_enrollment_store::ROW_ID)
        .one(db)
        .await
        .context("load client enrollment")?
    else {
        return Ok(None);
    };

    let server_noise_pubkey: [u8; 32] = row
        .server_noise_pubkey
        .as_slice()
        .try_into()
        .context("stored server noise pubkey wrong size")?;
    let tls_cert_fingerprint: [u8; 32] = row
        .tls_cert_fingerprint
        .as_slice()
        .try_into()
        .context("stored tls fingerprint wrong size")?;

    Ok(Some(ClientEnrollment {
        server_noise_pubkey,
        server_ml_kem_pubkey: row.server_ml_kem_pubkey,
        tls_cert_fingerprint,
    }))
}

// save after register
pub async fn persist_enrollment(
    db: &DatabaseConnection,
    enrollment: &ClientEnrollment,
) -> Result<()> {
    let model = client_enrollment_store::ActiveModel {
        id: ActiveValue::Set(client_enrollment_store::ROW_ID),
        server_noise_pubkey: ActiveValue::Set(enrollment.server_noise_pubkey.to_vec()),
        server_ml_kem_pubkey: ActiveValue::Set(enrollment.server_ml_kem_pubkey.clone()),
        tls_cert_fingerprint: ActiveValue::Set(enrollment.tls_cert_fingerprint.to_vec()),
    };
    client_enrollment_store::Entity::insert(model)
        .on_conflict(
            OnConflict::column(client_enrollment_store::Column::Id)
                .update_columns([
                    client_enrollment_store::Column::ServerNoisePubkey,
                    client_enrollment_store::Column::ServerMlKemPubkey,
                    client_enrollment_store::Column::TlsCertFingerprint,
                ])
                .to_owned(),
        )
        .exec(db)
        .await
        .context("persist client enrollment")?;
    Ok(())
}
