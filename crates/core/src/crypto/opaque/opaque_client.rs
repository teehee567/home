use anyhow::Result;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    rand::rngs::OsRng,
};
use secrecy::SecretBox;
use zeroize::Zeroize;

use super::OpaqueCipherSuite;

pub struct LoginResult {
    pub session_key: SecretBox<[u8; 64]>,
    pub export_key: SecretBox<[u8; 64]>,
}

pub struct ClientRegistrationState(ClientRegistration<OpaqueCipherSuite>);

pub struct ClientLoginState(ClientLogin<OpaqueCipherSuite>);

pub struct OpaqueClient;

impl OpaqueClient {
    pub fn registration_start(password: &[u8]) -> Result<(Vec<u8>, ClientRegistrationState)> {
        let mut rng = OsRng;
        let start = ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, password)?;
        let msg = start.message.serialize().to_vec();
        Ok((msg, ClientRegistrationState(start.state)))
    }

    pub fn registration_finish(
        state: ClientRegistrationState,
        password: &[u8],
        response_bytes: &[u8],
    ) -> Result<(Vec<u8>, SecretBox<[u8; 64]>)> {
        let mut rng = OsRng;
        let response = RegistrationResponse::deserialize(response_bytes)?;
        let finish = state.0.finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )?;
        let msg = finish.message.serialize().to_vec();
        let mut ek: [u8; 64] = finish.export_key.as_slice().try_into()?;
        let secret = SecretBox::new(Box::new(ek));
        ek.zeroize();
        Ok((msg, secret))
    }

    pub fn login_start(password: &[u8]) -> Result<(Vec<u8>, ClientLoginState)> {
        let mut rng = OsRng;
        let start = ClientLogin::<OpaqueCipherSuite>::start(&mut rng, password)?;
        let msg = start.message.serialize().to_vec();
        Ok((msg, ClientLoginState(start.state)))
    }

    pub fn login_finish(
        state: ClientLoginState,
        password: &[u8],
        ke2_bytes: &[u8],
    ) -> Result<(Vec<u8>, LoginResult)> {
        let mut rng = OsRng;
        let response = CredentialResponse::deserialize(ke2_bytes)?;
        let finish = state
            .0
            .finish(
                &mut rng,
                password,
                response,
                ClientLoginFinishParameters::default(),
            )?;
        let ke3 = finish.message.serialize().to_vec();
        let mut sk: [u8; 64] = finish.session_key.as_slice().try_into()?;
        let mut ek: [u8; 64] = finish.export_key.as_slice().try_into()?;
        let result = LoginResult {
            session_key: SecretBox::new(Box::new(sk)),
            export_key: SecretBox::new(Box::new(ek)),
        };
        sk.zeroize();
        ek.zeroize();
        Ok((ke3, result))
    }
}