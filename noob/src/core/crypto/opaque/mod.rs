mod opaque_server;
mod opaque_client;

use opaque_ke::{CipherSuite, Ristretto255, TripleDh, argon2::Argon2};
pub use opaque_server::*;
pub use opaque_client::*;
use sha2::Sha512;

struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}


#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn register_then_login() {
        let password = b"128-byte-passwordlasdjf;asjfasjdf;askdfj;asdjf;klajsdfl;kjas;ldfja;sjf;lasjdf;klajsdf;lkjas;fja;dfjasjdf;aksjdfa;skdjfa;as;dkjll";
        let username = "king noob";

        let (reg_request, client_reg_state) =
            OpaqueClient::registration_start(password).unwrap();

        let mut server = OpaqueServer::new();
        let reg_response = server.registration_start(username, &reg_request).unwrap();

        let (reg_upload, _) =
            OpaqueClient::registration_finish(client_reg_state, password, &reg_response).unwrap();

        server.registration_finish(username, &reg_upload).unwrap();

        let (ke1, client_login_state) = OpaqueClient::login_start(password).unwrap();

        let (ke2, server_login_state) = server.login_start(username, &ke1).unwrap();

        let (ke3, client_result) =
            OpaqueClient::login_finish(client_login_state, password, &ke2).unwrap();

        let server_session_key =
            OpaqueServer::login_finish(server_login_state, &ke3).unwrap();

        assert_eq!(
            client_result.session_key.expose_secret(),
            server_session_key.expose_secret(),
            "session keys must match"
        );
    }
}
