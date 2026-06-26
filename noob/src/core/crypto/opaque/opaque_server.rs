use anyhow::{Context, Result};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, rand::rngs::OsRng,
};
use secrecy::SecretBox;
use zeroize::Zeroize;

use super::OpaqueCipherSuite;

pub struct ServerLoginState(ServerLogin<OpaqueCipherSuite>);

// immutable setup only, records live in db
pub struct OpaqueServer {
    server_setup: ServerSetup<OpaqueCipherSuite>,
}

impl OpaqueServer {
    // random setup on first run
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self { server_setup: ServerSetup::<OpaqueCipherSuite>::new(&mut rng) }
    }

    pub fn from_setup_bytes(bytes: &[u8]) -> Result<Self> {
        let server_setup = ServerSetup::<OpaqueCipherSuite>::deserialize(bytes)
            .context("deserialize opaque server setup")?;
        Ok(Self { server_setup })
    }

    pub fn serialize_setup(&self) -> Vec<u8> {
        self.server_setup.serialize().to_vec()
    }

    pub fn registration_start(&self, username: &str, request_bytes: &[u8]) -> Result<Vec<u8>> {
        let request = RegistrationRequest::deserialize(request_bytes)?;
        let start = ServerRegistration::<OpaqueCipherSuite>::start(
            &self.server_setup,
            request,
            username.as_bytes(),
        )?;
        Ok(start.message.serialize().to_vec())
    }

    // returns record for caller to persist
    pub fn process_registration_upload(&self, upload_bytes: &[u8]) -> Result<Vec<u8>> {
        let upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(upload_bytes)?;
        let record = ServerRegistration::finish(upload);
        Ok(record.serialize().to_vec())
    }

    // record supplied by caller
    pub fn login_start(
        &self,
        username: &str,
        ke1_bytes: &[u8],
        registration_record_bytes: &[u8],
    ) -> Result<(Vec<u8>, ServerLoginState)> {
        let record =
            ServerRegistration::<OpaqueCipherSuite>::deserialize(registration_record_bytes)
                .context("deserialize stored registration record")?;
        let request = CredentialRequest::deserialize(ke1_bytes)?;

        let mut rng = OsRng;
        let start = ServerLogin::start(
            &mut rng,
            &self.server_setup,
            Some(record),
            request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )?;

        let ke2 = start.message.serialize().to_vec();
        Ok((ke2, ServerLoginState(start.state)))
    }

    pub fn login_finish(state: ServerLoginState, ke3_bytes: &[u8]) -> Result<SecretBox<[u8; 64]>> {
        let fin = CredentialFinalization::deserialize(ke3_bytes)?;
        let result = state
            .0
            .finish(fin, ServerLoginParameters::default())?;

        let mut sk: [u8; 64] = result.session_key.as_slice().try_into()?;
        let secret = SecretBox::new(Box::new(sk));
        sk.zeroize();
        Ok(secret)
    }
}
