use actix::{Actor, Addr, Context, Handler};
use actix_web::{web, HttpRequest};
use oxide_auth::{
    /*code_grant::client_credentials::ClientCredentials,*/ endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, QueryParameter, Solicitation}, frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic, Vacant}, primitives::prelude::{AuthMap, Client, ClientMap, RandomGenerator, Scope, TokenMap}
};
use oxide_auth_actix::{
    Authorize, OAuthMessage, OAuthOperation, OAuthRequest, OAuthResponse, Refresh, Token, WebError
};
use oxide_auth_actix::ClientCredentials;

// Follows https://github.com/197g/oxide-auth/blob/master/oxide-auth-actix/examples/actix-example/src/main.rs

pub struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
}

// TODO: What is it?
enum Extras {
    AuthGet,
    AuthPost(String),
    ClientCredentials,
    Nothing,
}

/// Handles OAuth2 /authorize requests
pub async fn authorize(
    (r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    // FIXME: Some authentication should be performed here in production cases
    state
        .send(Authorize(req).wrap(Extras::AuthPost(r.query_string().to_owned())))
        .await?
}

pub async fn token((req, state): (OAuthRequest, web::Data<Addr<State>>)) -> Result<OAuthResponse, WebError> {
    let grant_type = req.body().and_then(|body| body.unique_value("grant_type"));
    // Different grant types determine which flow to perform.
    match grant_type.as_deref() {
        Some("client_credentials") => {
            state
                .send(ClientCredentials(req).wrap(Extras::ClientCredentials))
                .await?
        }
        // Each flow will validate the grant_type again, so we can let one case handle
        // any incorrect or unsupported options.
        _ => state.send(Token(req).wrap(Extras::Nothing)).await?,
    }
}

pub async fn refresh(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    state.send(Refresh(req).wrap(Extras::Nothing)).await?
}

impl State {
    pub fn preconfigured() -> Self {
        let api_server_url = "https://localhost:3000"; // FIXME: totally wrong URL
        // let api_server_url = config.bind_api.host.clone() + ":" + config.bind_api.port.to_string().as_str(); // TODO: duplicate code

        State {
            endpoint: Generic {
                // A registrar with one pre-registered client
                registrar: vec![Client::confidential( // FIXME: a dynamic DB client instead of this clear-text password one
                    "JoinProxyApi",
                    format!("{}/redirect", api_server_url)
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                    "default".parse().unwrap(),
                    "SecretSecret".as_bytes(),
                )]
                .into_iter()
                .collect(),
                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(32)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this example is somewhat paranoid.
                //
                // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
                // be read and parsed by anyone, but not maliciously created. However, they can not be
                // revoked and thus don't offer even longer lived refresh tokens.
                issuer: TokenMap::new(RandomGenerator::new(32)),

                solicitor: Vacant,

                // A single scope that will guard resources for this endpoint
                scopes: vec!["default-scope".parse().unwrap()],

                response: OAuthResponse::ok,
            },
        }
    }

    pub fn with_solicitor<'a, S>(
        &'a mut self, solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for State
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::AuthGet => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: Solicitation| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok()
                            .content_type("text/html")
                            .unwrap()
                            .body(&consent_page_html("/authorize".into(), pre_grant)),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::ClientCredentials => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                    // For the client credentials flow, the solicitor is consulted
                    // to ensure that the resulting access token is issued to the
                    // correct owner. This may be the client itself, if clients
                    // and resource owners are from the same set of entities, but
                    // may be distinct if that is not the case.
                    OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(&mut self.endpoint),
        }
    }
}

pub fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
    macro_rules! template {
        () => {
"<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
</form>
</html>"
        };
    }

    let grant = solicitation.pre_grant();
    let state = solicitation.state();

    let mut extra = vec![
        ("response_type", "code"),
        ("client_id", grant.client_id.as_str()),
        ("redirect_uri", grant.redirect_uri.as_str()),
    ];

    if let Some(state) = state {
        extra.push(("state", state));
    }
    
    format!(template!(), 
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        serde_urlencoded::to_string(extra).unwrap(),
        &route,
    )
}