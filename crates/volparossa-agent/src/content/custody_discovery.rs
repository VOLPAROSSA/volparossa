//! Public candidate hints through the retained protected route, never object-key DHT queries.

use std::{collections::BTreeMap, time::Duration};

use tokio::{net::UnixStream, time::timeout};
use volparossa_local_control::{
    ContentCustodyDiscoverRequest, ContentCustodyDiscovered, ContentCustodyProvider,
};
use volparossa_policy::TransportProtocol;

use super::{ContentError, ContentRuntime, cancellation::until_requester_closed, custody, now};
use crate::{control::ControlContext, unix_millis};

impl ContentRuntime {
    pub(crate) async fn custody_discover(
        &self,
        request: &ContentCustodyDiscoverRequest,
        context: &ControlContext,
        local: &mut UnixStream,
    ) -> Result<ContentCustodyDiscovered, ContentError> {
        if !(1..=16).contains(&request.max_providers) {
            return Err(ContentError::Invalid);
        }
        let (_, manifest) = custody::public_manifest(&request.manifest, &request.publisher_key)?;
        if !self.object_policy.allows_now(&manifest) {
            return Err(ContentError::Policy);
        }
        let mut changed = super::background_custody::owner_idle(&self.foreground)?;
        let spare = self.background_custody.acquire(&context.config)?;
        let _worker = self.worker_budget.try_acquire().ok_or(ContentError::Busy)?;
        let operation = until_requester_closed(local, async {
            spare.admit(0).await;
            let policy = custody::checked_policy(context, None).await?;
            Box::pin(context.routes.connect_tcp(
                &context.config,
                &context.discovery,
                &context.helper,
            ))
            .await
            .map_err(|_| ContentError::Unavailable)?;
            let control = context
                .routes
                .content_discovery_control()
                .await
                .ok_or(ContentError::Unavailable)?;
            let providers = context
                .discovery
                .discover_content_providers(control, request.max_providers as usize)
                .await
                .map_err(|_| ContentError::Unavailable)?;
            let mut unique = BTreeMap::new();
            for provider in providers {
                let offer = &provider.offer;
                if offer.provider_key() != &self.signer.verifying_key().to_bytes()
                    && offer.validity().expires > now()
                    && policy
                        .authorize_domain(
                            unix_millis(),
                            offer.endpoint().hostname(),
                            TransportProtocol::Tcp,
                            offer.endpoint().port(),
                        )
                        .is_ok()
                    && context
                        .routes
                        .content_provider_is_distinct(&provider.peer_id)
                        .await
                {
                    unique.insert(
                        *offer.provider_key(),
                        ContentCustodyProvider {
                            provider_key: offer.provider_key().to_vec(),
                            offer_expires_unix_seconds: offer.validity().expires,
                        },
                    );
                }
            }
            custody::checked_policy(context, Some(&policy)).await?;
            super::check_publication_time(&manifest)?;
            if context.routes.content_discovery_control().await != Some(control) {
                return Err(ContentError::Policy);
            }
            Ok(ContentCustodyDiscovered {
                providers: unique
                    .into_values()
                    .filter(|offer| offer.offer_expires_unix_seconds > now())
                    .collect(),
                control_relay_peer_id: control.to_string(),
            })
        });
        tokio::select! {
            biased;
            _ = changed.changed() => Err(ContentError::Busy),
            () = self.object_policy.wait_until_withheld(&manifest) => Err(ContentError::Policy),
            result = timeout(Duration::from_secs(150), operation) => result.map_err(|_| ContentError::Unavailable)?,
        }
    }
}
