use std::collections::{BTreeMap, HashSet};

use anyhow::{anyhow, Result};
use async_signature::AsyncSigner;
use coset::iana::Algorithm;
use coset::{CoseSign1, Label};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use signature::{SignatureEncoding, Signer};

use crate::cose::sign1::PreparedCoseSign1;
use crate::cose::{MaybeTagged, SignatureAlgorithm};
use crate::digest_executor::{
    digest_length, DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor,
};
use crate::{
    definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL},
    definitions::{
        helpers::{NonEmptyMap, NonEmptyVec, Tag24},
        issuer_signed::{IssuerNamespaces, IssuerSignedItemBytes},
        DeviceKeyInfo, DigestAlgorithm, DigestId, DigestIds, IssuerSignedItem, Mso, ValidityInfo,
    },
};

pub type Namespaces = BTreeMap<String, BTreeMap<String, ciborium::Value>>;

/// A signed mdoc.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Mdoc {
    pub doc_type: String,
    pub mso: Mso,
    pub namespaces: IssuerNamespaces,
    pub issuer_auth: MaybeTagged<CoseSign1>,
}

/// An incomplete mdoc, requiring a remotely signed signature to be completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedMdoc {
    doc_type: String,
    mso: Mso,
    namespaces: IssuerNamespaces,
    prepared_sig: PreparedCoseSign1,
}

#[derive(Debug, Clone, Default)]
pub struct Builder {
    doc_type: Option<String>,
    namespaces: Option<Namespaces>,
    validity_info: Option<ValidityInfo>,
    digest_algorithm: Option<DigestAlgorithm>,
    device_key_info: Option<DeviceKeyInfo>,
    enable_decoy_digests: Option<bool>,
}

impl Mdoc {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Prepare mdoc for remote signing.
    pub fn prepare(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        signature_algorithm: Algorithm,
        enable_decoy_digests: bool,
    ) -> Result<PreparedMdoc> {
        Self::prepare_with_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signature_algorithm,
            enable_decoy_digests,
            &SerialDigestExecutor,
        )
    }

    /// Prepare an mdoc for remote signing using a caller-selected digest executor.
    ///
    /// The executor receives encoded issuer-signed items, which can contain
    /// sensitive credential claims. It must therefore run within the same
    /// trusted boundary as the issuer. Signing keys and signer handles are not
    /// passed to the executor.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_digest_executor<E>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        signature_algorithm: Algorithm,
        enable_decoy_digests: bool,
        digest_executor: &E,
    ) -> Result<PreparedMdoc>
    where
        E: DigestExecutor + ?Sized,
    {
        if let Some(authorizations) = &device_key_info.key_authorizations {
            authorizations.validate()?;
        }
        // Invalid shapes fail before RNG allocation. Error values match the
        // legacy path; failed calls do not promise preservation of RNG state.
        validate_namespace_shape(&namespaces)?;
        let mut rng = rand::thread_rng();
        Self::prepare_with_validated_inputs_rng_and_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signature_algorithm,
            enable_decoy_digests,
            &mut rng,
            digest_executor,
        )
    }

    // The public entry point validates authorizations and namespace shape
    // before constructing its RNG. Test callers use already-valid fixtures.
    #[allow(clippy::too_many_arguments)]
    fn prepare_with_validated_inputs_rng_and_digest_executor<R, E>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        signature_algorithm: Algorithm,
        enable_decoy_digests: bool,
        rng: &mut R,
        digest_executor: &E,
    ) -> Result<PreparedMdoc>
    where
        R: CryptoRng + Rng + ?Sized,
        E: DigestExecutor + ?Sized,
    {
        let issuer_namespaces = to_issuer_namespaces(namespaces, rng)?;
        let digest_plan = plan_digest_namespaces(
            &issuer_namespaces,
            digest_algorithm,
            enable_decoy_digests,
            rng,
        )?;
        let digest_results = digest_executor.execute(&digest_plan.jobs)?;
        let value_digests = assemble_digest_namespaces(&digest_plan, digest_results)?;

        Self::finish_preparation(
            doc_type,
            issuer_namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signature_algorithm,
            value_digests,
        )
    }

    fn finish_preparation(
        doc_type: String,
        issuer_namespaces: IssuerNamespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        signature_algorithm: Algorithm,
        value_digests: BTreeMap<String, DigestIds>,
    ) -> Result<PreparedMdoc> {
        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm,
            value_digests,
            device_key_info,
            doc_type: doc_type.clone(),
            validity_info,
        };

        let mso_bytes = crate::cbor::to_vec(&Tag24::new(&mso)?)?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(signature_algorithm)
            .build();
        let builder = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(mso_bytes);
        let prepared_sig = PreparedCoseSign1::new(builder, None, None, false)?;

        let preparation_mdoc = PreparedMdoc {
            doc_type,
            namespaces: issuer_namespaces,
            mso,
            prepared_sig,
        };

        Ok(preparation_mdoc)
    }

    /// Directly sign and issue an mdoc.
    #[allow(clippy::too_many_arguments)]
    pub fn issue<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        enable_decoy_digests: bool,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        let prepared_mdoc = Self::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signer.algorithm(),
            enable_decoy_digests,
        )?;

        let signature_payload = prepared_mdoc.signature_payload();
        let signature = signer
            .try_sign(signature_payload)
            .map_err(|e| anyhow!("error signing cosesign1: {}", e))?
            .to_vec();

        Ok(prepared_mdoc.complete(x5chain, signature))
    }

    /// Directly sign and issue an mdoc.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_async<S, Sig>(
        doc_type: String,
        namespaces: Namespaces,
        validity_info: ValidityInfo,
        digest_algorithm: DigestAlgorithm,
        device_key_info: DeviceKeyInfo,
        x5chain: X5Chain,
        enable_decoy_digests: bool,
        signer: S,
    ) -> Result<Mdoc>
    where
        S: AsyncSigner<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding + Send + 'static,
    {
        let prepared_mdoc = Self::prepare(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signer.algorithm(),
            enable_decoy_digests,
        )?;

        let signature_payload = prepared_mdoc.signature_payload();
        let signature = signer
            .sign_async(signature_payload)
            .await
            .map_err(|e| anyhow!("error signing cosesign1: {}", e))?
            .to_vec();

        Ok(prepared_mdoc.complete(x5chain, signature))
    }
}

impl PreparedMdoc {
    /// Retrieve the payload for a remote signature.
    pub fn signature_payload(&self) -> &[u8] {
        self.prepared_sig.signature_payload()
    }

    /// Supply the remotely signed signature and x5chain containing the issuing certificate
    /// to complete and issue the prepared mdoc.
    pub fn complete(self, x5chain: X5Chain, signature: Vec<u8>) -> Mdoc {
        let PreparedMdoc {
            doc_type,
            namespaces,
            mso,
            prepared_sig,
        } = self;

        let mut issuer_auth = prepared_sig.finalize(signature);
        issuer_auth
            .inner
            .unprotected
            .rest
            .push((Label::Int(X5CHAIN_COSE_HEADER_LABEL), x5chain.into_cbor()));
        Mdoc {
            doc_type,
            mso,
            namespaces,
            issuer_auth,
        }
    }
}

impl Builder {
    /// Set the document type.
    pub fn doc_type(mut self, doc_type: String) -> Self {
        self.doc_type = Some(doc_type);
        self
    }

    /// Set the data elements.
    pub fn namespaces(mut self, namespaces: Namespaces) -> Self {
        self.namespaces = Some(namespaces);
        self
    }

    /// Set the validity information
    pub fn validity_info(mut self, validity_info: ValidityInfo) -> Self {
        self.validity_info = Some(validity_info);
        self
    }

    /// Set the digest algorithm to be used for hashing the data elements.
    pub fn digest_algorithm(mut self, digest_algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = Some(digest_algorithm);
        self
    }

    /// Set the information about the device key that this mdoc will be issued to.
    pub fn device_key_info(mut self, device_key_info: DeviceKeyInfo) -> Self {
        self.device_key_info = Some(device_key_info);
        self
    }

    /// Enable the use of decoy digests.
    pub fn enable_decoy_digests(mut self, enable_decoy_digests: bool) -> Self {
        self.enable_decoy_digests = Some(enable_decoy_digests);
        self
    }

    /// Prepare the mdoc for remote signing.
    ///
    /// The signature algorithm which the mdoc will be signed with must be known ahead of time as
    /// it is a required field in the signature headers.
    pub fn prepare(self, signature_algorithm: Algorithm) -> Result<PreparedMdoc> {
        self.prepare_with_digest_executor(signature_algorithm, &SerialDigestExecutor)
    }

    /// Prepare an mdoc with a caller-selected digest executor.
    ///
    /// See [`Mdoc::prepare_with_digest_executor`] for the executor's security
    /// boundary and contract.
    pub fn prepare_with_digest_executor<E>(
        self,
        signature_algorithm: Algorithm,
        digest_executor: &E,
    ) -> Result<PreparedMdoc>
    where
        E: DigestExecutor + ?Sized,
    {
        let doc_type = self
            .doc_type
            .ok_or_else(|| anyhow!("missing parameter: 'doc_type'"))?;
        let namespaces = self
            .namespaces
            .ok_or_else(|| anyhow!("missing parameter: 'namespaces'"))?;
        let validity_info = self
            .validity_info
            .ok_or_else(|| anyhow!("missing parameter: 'validity_info'"))?;
        let digest_algorithm = self
            .digest_algorithm
            .ok_or_else(|| anyhow!("missing parameter: 'digest_algorithm'"))?;
        let device_key_info = self
            .device_key_info
            .ok_or_else(|| anyhow!("missing parameter: 'device_key_info'"))?;
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::prepare_with_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            signature_algorithm,
            enable_decoy_digests,
            digest_executor,
        )
    }

    /// Directly issue an mdoc.
    pub fn issue<S, Sig>(self, x5chain: X5Chain, signer: S) -> Result<Mdoc>
    where
        S: Signer<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding,
    {
        let doc_type = self
            .doc_type
            .ok_or_else(|| anyhow!("missing parameter: 'doc_type'"))?;
        let namespaces = self
            .namespaces
            .ok_or_else(|| anyhow!("missing parameter: 'namespaces'"))?;
        let validity_info = self
            .validity_info
            .ok_or_else(|| anyhow!("missing parameter: 'validity_info'"))?;
        let digest_algorithm = self
            .digest_algorithm
            .ok_or_else(|| anyhow!("missing parameter: 'digest_algorithm'"))?;
        let device_key_info = self
            .device_key_info
            .ok_or_else(|| anyhow!("missing parameter: 'device_key_info'"))?;
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::issue(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            enable_decoy_digests,
            signer,
        )
    }

    /// Directly issue an mdoc.
    pub async fn issue_async<S, Sig>(self, x5chain: X5Chain, signer: S) -> Result<Mdoc>
    where
        S: AsyncSigner<Sig> + SignatureAlgorithm,
        Sig: SignatureEncoding + Send + 'static,
    {
        let doc_type = self
            .doc_type
            .ok_or_else(|| anyhow!("missing parameter: 'doc_type'"))?;
        let namespaces = self
            .namespaces
            .ok_or_else(|| anyhow!("missing parameter: 'namespaces'"))?;
        let validity_info = self
            .validity_info
            .ok_or_else(|| anyhow!("missing parameter: 'validity_info'"))?;
        let digest_algorithm = self
            .digest_algorithm
            .ok_or_else(|| anyhow!("missing parameter: 'digest_algorithm'"))?;
        let device_key_info = self
            .device_key_info
            .ok_or_else(|| anyhow!("missing parameter: 'device_key_info'"))?;
        let enable_decoy_digests = self.enable_decoy_digests.unwrap_or(true);

        Mdoc::issue_async(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            x5chain,
            enable_decoy_digests,
            signer,
        )
        .await
    }
}

fn validate_namespace_shape(namespaces: &Namespaces) -> Result<()> {
    if namespaces.is_empty() {
        return Err(anyhow!("at least one namespace required"));
    }
    if namespaces.values().any(BTreeMap::is_empty) {
        return Err(anyhow!("at least one element required in each namespace"));
    }
    Ok(())
}

fn to_issuer_namespaces<R>(namespaces: Namespaces, rng: &mut R) -> Result<IssuerNamespaces>
where
    R: Rng + ?Sized,
{
    namespaces
        .into_iter()
        .map(|(name, elements)| {
            to_issuer_signed_items(elements, rng)
                .into_iter()
                .map(Tag24::new)
                .collect::<Result<Vec<Tag24<IssuerSignedItem>>, _>>()
                .map_err(|err| anyhow!("unable to encode IssuerSignedItem as cbor: {}", err))
                .and_then(|items| {
                    NonEmptyVec::try_from(items)
                        .map_err(|_| anyhow!("at least one element required in each namespace"))
                })
                .map(|elems| (name, elems))
        })
        .collect::<Result<BTreeMap<String, NonEmptyVec<Tag24<IssuerSignedItem>>>>>()
        .and_then(|namespaces| {
            NonEmptyMap::try_from(namespaces)
                .map_err(|_| anyhow!("at least one namespace required"))
        })
}

fn to_issuer_signed_items<R>(
    elements: BTreeMap<String, ciborium::Value>,
    rng: &mut R,
) -> Vec<IssuerSignedItem>
where
    R: Rng + ?Sized,
{
    let mut used_ids = HashSet::with_capacity(elements.len());
    let mut items = Vec::with_capacity(elements.len());
    for (key, value) in elements {
        let digest_id = generate_digest_id(&mut used_ids, rng);
        let random = Vec::from(rng.gen::<[u8; 16]>()).into();
        items.push(IssuerSignedItem {
            digest_id,
            random,
            element_identifier: key,
            element_value: value,
        });
    }
    items
}

const MDOC_CREDENTIAL_ID: u64 = 0;
const DECOY_BYTES_LENGTH: usize = 512;

#[derive(Clone, Eq, PartialEq)]
struct MdocDigestPlan {
    namespaces: Vec<PlannedMdocNamespace>,
    jobs: Vec<DigestJob>,
}

#[derive(Clone, Eq, PartialEq)]
struct PlannedMdocNamespace {
    name: String,
    digests: Vec<PlannedMdocDigest>,
}

#[derive(Clone, Eq, PartialEq)]
struct PlannedMdocDigest {
    credential_id: u64,
    job_id: u64,
    digest_id: DigestId,
}

fn plan_digest_namespaces<R>(
    namespaces: &IssuerNamespaces,
    digest_algorithm: DigestAlgorithm,
    enable_decoy_digests: bool,
    rng: &mut R,
) -> Result<MdocDigestPlan>
where
    R: Rng + ?Sized,
{
    let item_count = namespaces.values().map(|elements| elements.len()).sum();
    let mut plan = MdocDigestPlan {
        namespaces: Vec::with_capacity(namespaces.len()),
        jobs: Vec::with_capacity(item_count),
    };
    let mut next_job_id = 0;

    for (name, elements) in namespaces.iter() {
        plan.namespaces.push(PlannedMdocNamespace {
            name: name.clone(),
            digests: plan_digest_namespace(
                elements,
                digest_algorithm,
                enable_decoy_digests,
                rng,
                &mut next_job_id,
                &mut plan.jobs,
            )?,
        });
    }

    Ok(plan)
}

fn plan_digest_namespace<R>(
    elements: &[IssuerSignedItemBytes],
    digest_algorithm: DigestAlgorithm,
    enable_decoy_digests: bool,
    rng: &mut R,
    next_job_id: &mut u64,
    jobs: &mut Vec<DigestJob>,
) -> Result<Vec<PlannedMdocDigest>>
where
    R: Rng + ?Sized,
{
    let decoy_count = if enable_decoy_digests {
        rng.gen_range(5..10)
    } else {
        0
    };
    let mut used_ids = HashSet::with_capacity(elements.len() + decoy_count);
    used_ids.extend(elements.iter().map(|item| item.as_ref().digest_id));

    jobs.reserve(elements.len() + decoy_count);
    let mut planned_digests = Vec::with_capacity(elements.len() + decoy_count);

    for (ordinal, item) in elements.iter().enumerate() {
        push_planned_digest(
            item.as_ref().digest_id,
            ordinal,
            digest_algorithm,
            crate::cbor::to_vec(item)?,
            next_job_id,
            jobs,
            &mut planned_digests,
        )?;
    }

    // Generate random digests to avoid leaking the number of real items.
    for decoy_ordinal in 0..decoy_count {
        let digest_id = generate_digest_id(&mut used_ids, rng);
        let mut bytes = vec![0; DECOY_BYTES_LENGTH];
        rng.fill(bytes.as_mut_slice());
        push_planned_digest(
            digest_id,
            elements.len() + decoy_ordinal,
            digest_algorithm,
            bytes,
            next_job_id,
            jobs,
            &mut planned_digests,
        )?;
    }

    Ok(planned_digests)
}

#[allow(clippy::too_many_arguments)]
fn push_planned_digest(
    digest_id: DigestId,
    ordinal: usize,
    algorithm: DigestAlgorithm,
    input: Vec<u8>,
    next_job_id: &mut u64,
    jobs: &mut Vec<DigestJob>,
    planned_digests: &mut Vec<PlannedMdocDigest>,
) -> Result<()> {
    let job_id = *next_job_id;
    *next_job_id = next_job_id
        .checked_add(1)
        .ok_or_else(|| anyhow!("too many mdoc digest jobs"))?;

    jobs.push(DigestJob {
        credential_id: MDOC_CREDENTIAL_ID,
        job_id,
        ordinal,
        algorithm,
        input,
    });
    planned_digests.push(PlannedMdocDigest {
        credential_id: MDOC_CREDENTIAL_ID,
        job_id,
        digest_id,
    });
    Ok(())
}

fn assemble_digest_namespaces(
    plan: &MdocDigestPlan,
    results: Vec<DigestResult>,
) -> Result<BTreeMap<String, DigestIds>> {
    if results_follow_plan_order(plan, &results) {
        return assemble_ordered_digest_namespaces(plan, results);
    }

    assemble_reordered_digest_namespaces(plan, results)
}

fn results_follow_plan_order(plan: &MdocDigestPlan, results: &[DigestResult]) -> bool {
    results.len() == plan.jobs.len()
        && plan.jobs.iter().zip(results).all(|(job, result)| {
            (job.credential_id, job.job_id) == (result.credential_id, result.job_id)
                && job.ordinal == result.ordinal
        })
}

fn assemble_ordered_digest_namespaces(
    plan: &MdocDigestPlan,
    results: Vec<DigestResult>,
) -> Result<BTreeMap<String, DigestIds>> {
    let mut results = results.into_iter();
    let mut jobs = plan.jobs.iter();
    let mut namespaces = BTreeMap::new();
    let mut expected_job_id = 0u64;

    for namespace in &plan.namespaces {
        let mut digest_ids = BTreeMap::new();
        for planned_digest in &namespace.digests {
            let job = jobs
                .next()
                .ok_or_else(|| anyhow!("mdoc digest plan references an unknown job"))?;
            let result = results
                .next()
                .ok_or_else(|| anyhow!("digest executor omitted a planned result"))?;
            if (job.credential_id, job.job_id) != (MDOC_CREDENTIAL_ID, expected_job_id) {
                return Err(anyhow!("mdoc digest plan contains duplicate job identity"));
            }
            if (planned_digest.credential_id, planned_digest.job_id)
                != (job.credential_id, job.job_id)
            {
                return Err(anyhow!("mdoc digest plan references an unknown job"));
            }
            if (result.credential_id, result.job_id) != (job.credential_id, job.job_id) {
                return Err(anyhow!("digest executor changed result identity metadata"));
            }
            if result.ordinal != job.ordinal {
                return Err(anyhow!("digest executor changed result identity metadata"));
            }
            if result.digest.len() != digest_length(job.algorithm) {
                return Err(anyhow!("digest executor returned an invalid digest length"));
            }
            if digest_ids
                .insert(planned_digest.digest_id, result.digest.into())
                .is_some()
            {
                return Err(anyhow!(
                    "mdoc digest plan contains a duplicate digest ID within a namespace"
                ));
            }
            expected_job_id = expected_job_id
                .checked_add(1)
                .ok_or_else(|| anyhow!("too many mdoc digest jobs"))?;
        }
        if namespaces
            .insert(namespace.name.clone(), digest_ids)
            .is_some()
        {
            return Err(anyhow!("mdoc digest plan contains a duplicate namespace"));
        }
    }
    if jobs.next().is_some() {
        return Err(anyhow!("mdoc digest plan contains an unreferenced job"));
    }
    if results.next().is_some() {
        return Err(anyhow!("digest executor returned an unexpected result"));
    }

    Ok(namespaces)
}

fn assemble_reordered_digest_namespaces(
    plan: &MdocDigestPlan,
    results: Vec<DigestResult>,
) -> Result<BTreeMap<String, DigestIds>> {
    let mut results_by_identity = BTreeMap::new();
    let mut duplicate_result = false;
    for result in results {
        let identity = (result.credential_id, result.job_id);
        if results_by_identity.insert(identity, result).is_some() {
            duplicate_result = true;
        }
    }
    if duplicate_result {
        return Err(anyhow!(
            "digest executor returned duplicate result identity"
        ));
    }

    let mut digests_by_identity = BTreeMap::new();
    let mut expected_identities = HashSet::with_capacity(plan.jobs.len());
    for job in &plan.jobs {
        let identity = (job.credential_id, job.job_id);
        if !expected_identities.insert(identity) {
            return Err(anyhow!("mdoc digest plan contains duplicate job identity"));
        }

        let result = results_by_identity
            .remove(&identity)
            .ok_or_else(|| anyhow!("digest executor omitted a planned result"))?;
        if result.ordinal != job.ordinal {
            return Err(anyhow!("digest executor changed result identity metadata"));
        }
        if result.digest.len() != digest_length(job.algorithm) {
            return Err(anyhow!("digest executor returned an invalid digest length"));
        }
        digests_by_identity.insert(identity, result.digest);
    }
    if !results_by_identity.is_empty() {
        return Err(anyhow!("digest executor returned an unexpected result"));
    }

    let mut namespaces = BTreeMap::new();
    for namespace in &plan.namespaces {
        let mut digest_ids = BTreeMap::new();
        for planned_digest in &namespace.digests {
            let identity = (planned_digest.credential_id, planned_digest.job_id);
            let digest = digests_by_identity
                .remove(&identity)
                .ok_or_else(|| anyhow!("mdoc digest plan references an unknown job"))?;
            if digest_ids
                .insert(planned_digest.digest_id, digest.into())
                .is_some()
            {
                return Err(anyhow!(
                    "mdoc digest plan contains a duplicate digest ID within a namespace"
                ));
            }
        }
        if namespaces
            .insert(namespace.name.clone(), digest_ids)
            .is_some()
        {
            return Err(anyhow!("mdoc digest plan contains a duplicate namespace"));
        }
    }
    if !digests_by_identity.is_empty() {
        return Err(anyhow!("mdoc digest plan contains an unreferenced job"));
    }

    Ok(namespaces)
}

fn generate_digest_id<R>(used_ids: &mut HashSet<DigestId>, rng: &mut R) -> DigestId
where
    R: Rng + ?Sized,
{
    let mut digest_id;
    loop {
        digest_id = DigestId::new(rng.gen());
        if used_ids.insert(digest_id) {
            break;
        }
    }
    digest_id
}

#[cfg(test)]
pub mod test {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use p256::SecretKey;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use time::OffsetDateTime;

    use crate::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
    use crate::definitions::namespaces::{
        org_iso_18013_5_1::OrgIso1801351, org_iso_18013_5_1_aamva::OrgIso1801351Aamva,
    };
    use crate::definitions::traits::{FromJson, ToNamespaceMap};
    use crate::digest_executor::DigestExecutionError;

    use super::*;

    static ISSUER_CERT: &[u8] = include_bytes!("../../test/issuance/issuer-cert.pem");
    static ISSUER_KEY: &str = include_str!("../../test/issuance/issuer-key.pem");

    /// Explicit replay tape whose bulk fill consumes the same sequence as the
    /// legacy per-byte loop. Production RNGs need only preserve the same byte
    /// distribution; this test RNG establishes byte-for-byte differential runs.
    #[derive(Clone, Debug)]
    struct ReplayRng(StdRng);

    impl SeedableRng for ReplayRng {
        type Seed = <StdRng as SeedableRng>::Seed;

        fn from_seed(seed: Self::Seed) -> Self {
            Self(StdRng::from_seed(seed))
        }
    }

    impl RngCore for ReplayRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for byte in destination {
                *byte = self.next_u32() as u8;
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl rand::CryptoRng for ReplayRng {}

    #[derive(Debug)]
    struct U32SequenceRng {
        values: VecDeque<u32>,
    }

    impl U32SequenceRng {
        fn new(values: impl IntoIterator<Item = u32>) -> Self {
            Self {
                values: values.into_iter().collect(),
            }
        }
    }

    impl RngCore for U32SequenceRng {
        fn next_u32(&mut self) -> u32 {
            self.values
                .pop_front()
                .expect("the test sequence must contain enough values")
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) | (u64::from(self.next_u32()) << 32)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(4) {
                let bytes = self.next_u32().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    fn isomdl_data() -> serde_json::Value {
        serde_json::json!(
            {
              "family_name":"Smith",
              "given_name":"Alice",
              "birth_date":"1980-01-01",
              "issue_date":"2020-01-01",
              "expiry_date":"2030-01-01",
              "issuing_country":"US",
              "issuing_authority":"NY DMV",
              "document_number":"DL12345678",
              "portrait":include_str!("../../test/issuance/portrait.b64"),
              "driving_privileges":[
                {
                   "vehicle_category_code":"A",
                   "issue_date":"2020-01-01",
                   "expiry_date":"2030-01-01"
                },
                {
                   "vehicle_category_code":"B",
                   "issue_date":"2020-01-01",
                   "expiry_date":"2030-01-01"
                }
              ],
              "un_distinguishing_sign":"USA",
              "administrative_number":"ABC123",
              "sex":1,
              "height":170,
              "weight":70,
              "eye_colour":"hazel",
              "hair_colour":"red",
              "birth_place":"Canada",
              "resident_address":"138 Eagle Street",
              "portrait_capture_date":"2020-01-01T12:00:00Z",
              "age_in_years":43,
              "age_birth_year":1980,
              "age_over_18":true,
              "age_over_21":true,
              "issuing_jurisdiction":"US-NY",
              "nationality":"US",
              "resident_city":"Albany",
              "resident_state":"New York",
              "resident_postal_code":"12202-1719",
              "resident_country": "US"
            }
        )
    }

    fn aamva_isomdl_data() -> serde_json::Value {
        serde_json::json!(
            {
              "domestic_driving_privileges":[
                {
                  "domestic_vehicle_class":{
                    "domestic_vehicle_class_code":"A",
                    "domestic_vehicle_class_description":"unknown",
                    "issue_date":"2020-01-01",
                    "expiry_date":"2030-01-01"
                  }
                },
                {
                  "domestic_vehicle_class":{
                    "domestic_vehicle_class_code":"B",
                    "domestic_vehicle_class_description":"unknown",
                    "issue_date":"2020-01-01",
                    "expiry_date":"2030-01-01"
                  }
                }
              ],
              "name_suffix":"1ST",
              "organ_donor":1,
              "veteran":1,
              "family_name_truncation":"N",
              "given_name_truncation":"N",
              "aka_family_name.v2":"Smithy",
              "aka_given_name.v2":"Ally",
              "aka_suffix":"I",
              "weight_range":3,
              "race_ethnicity":"AI",
              "EDL_credential":1,
              "sex":1,
              "DHS_compliance":"F",
              "resident_county":"001",
              "hazmat_endorsement_expiration_date":"2024-01-30",
              "CDL_indicator":1,
              "DHS_compliance_text":"Compliant",
              "DHS_temporary_lawful_status":1,
            }
        )
    }

    #[test]
    fn issue_minimal_mdoc() -> anyhow::Result<()> {
        minimal_test_mdoc()?;
        Ok(())
    }

    fn minimal_test_mdoc_builder() -> Builder {
        let doc_type = String::from("org.iso.18013.5.1.mDL");
        let isomdl_namespace = String::from("org.iso.18013.5.1");
        let aamva_namespace = String::from("org.iso.18013.5.1.aamva");

        let isomdl_data = OrgIso1801351::from_json(&isomdl_data())
            .unwrap()
            .to_ns_map();
        let aamva_data = OrgIso1801351Aamva::from_json(&aamva_isomdl_data())
            .unwrap()
            .to_ns_map();

        let namespaces = [
            (isomdl_namespace, isomdl_data),
            (aamva_namespace, aamva_data),
        ]
        .into_iter()
        .collect();

        let validity_info = ValidityInfo {
            signed: OffsetDateTime::now_utc(),
            valid_from: OffsetDateTime::now_utc(),
            valid_until: OffsetDateTime::now_utc(),
            expected_update: None,
        };

        let digest_algorithm = DigestAlgorithm::SHA256;

        let der = include_str!("../../test/issuance/device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let key = p256::SecretKey::from_sec1_der(&der_bytes).unwrap();
        let pub_key = key.public_key();
        let ec = pub_key.to_encoded_point(false);
        let x = ec.x().unwrap().to_vec();
        let y = EC2Y::Value(ec.y().unwrap().to_vec());
        let device_key = CoseKey::EC2 {
            crv: EC2Curve::P256,
            x,
            y,
        };

        let device_key_info = DeviceKeyInfo {
            device_key,
            key_authorizations: None,
            key_info: None,
        };

        Mdoc::builder()
            .doc_type(doc_type)
            .namespaces(namespaces)
            .validity_info(validity_info)
            .digest_algorithm(digest_algorithm)
            .device_key_info(device_key_info)
    }

    #[test]
    fn empty_namespace_set_error_is_stable() {
        let error = minimal_test_mdoc_builder()
            .namespaces(BTreeMap::new())
            .prepare(Algorithm::ES256)
            .expect_err("an mdoc without namespaces must be rejected");

        assert_eq!(error.to_string(), "at least one namespace required");
    }

    #[test]
    fn empty_namespace_error_is_stable() {
        let namespaces = [("org.iso.18013.5.1".to_owned(), BTreeMap::new())]
            .into_iter()
            .collect();
        let error = minimal_test_mdoc_builder()
            .namespaces(namespaces)
            .prepare(Algorithm::ES256)
            .expect_err("an empty namespace must be rejected");

        assert_eq!(
            error.to_string(),
            "at least one element required in each namespace"
        );
    }

    pub fn minimal_test_mdoc() -> anyhow::Result<Mdoc> {
        let mdoc_builder = minimal_test_mdoc_builder();

        let x5chain = X5Chain::builder()
            .with_pem_certificate(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap();
        let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        Ok(mdoc_builder
            .issue::<SigningKey, Signature>(x5chain, signer)
            .expect("failed to issue mdoc"))
    }

    #[derive(Debug)]
    struct RotatingDigestExecutor {
        rotation: usize,
    }

    impl DigestExecutor for RotatingDigestExecutor {
        fn execute(
            &self,
            jobs: &[DigestJob],
        ) -> std::result::Result<Vec<DigestResult>, DigestExecutionError> {
            let mut results = SerialDigestExecutor.execute(jobs)?;
            if !results.is_empty() {
                let rotation = self.rotation % results.len();
                results.rotate_left(rotation);
            }
            Ok(results)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ResultSetFault {
        ExtraFirst,
        DuplicateFuture,
        MissingFirst,
        InvalidLengthAndDuplicate,
    }

    #[derive(Debug)]
    struct FaultyDigestExecutor(ResultSetFault);

    impl DigestExecutor for FaultyDigestExecutor {
        fn execute(
            &self,
            jobs: &[DigestJob],
        ) -> std::result::Result<Vec<DigestResult>, DigestExecutionError> {
            let mut results = SerialDigestExecutor.execute(jobs)?;
            match self.0 {
                ResultSetFault::ExtraFirst => {
                    let mut result = results
                        .last()
                        .cloned()
                        .expect("the mdoc fixture must produce digest jobs");
                    result.credential_id = u64::MAX;
                    result.job_id = u64::MAX;
                    result.ordinal = usize::MAX;
                    results.insert(0, result);
                }
                ResultSetFault::DuplicateFuture => {
                    results[0] = results[1].clone();
                }
                ResultSetFault::MissingFirst => {
                    results.remove(0);
                }
                ResultSetFault::InvalidLengthAndDuplicate => {
                    results[0].digest.pop();
                    results.push(results[1].clone());
                }
            }
            Ok(results)
        }
    }

    #[derive(Debug)]
    struct FailingDigestExecutor;

    impl DigestExecutor for FailingDigestExecutor {
        fn execute(
            &self,
            _jobs: &[DigestJob],
        ) -> std::result::Result<Vec<DigestResult>, DigestExecutionError> {
            Err(DigestExecutionError)
        }
    }

    #[derive(Debug)]
    struct PanicDigestExecutor;

    impl DigestExecutor for PanicDigestExecutor {
        fn execute(
            &self,
            _jobs: &[DigestJob],
        ) -> std::result::Result<Vec<DigestResult>, DigestExecutionError> {
            panic!("validation errors must prevent executor invocation")
        }
    }

    #[derive(Debug, Default)]
    struct CountingDigestExecutor {
        calls: AtomicUsize,
        jobs: AtomicUsize,
    }

    impl DigestExecutor for CountingDigestExecutor {
        fn execute(
            &self,
            jobs: &[DigestJob],
        ) -> std::result::Result<Vec<DigestResult>, DigestExecutionError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.jobs.fetch_add(jobs.len(), Ordering::Relaxed);
            SerialDigestExecutor.execute(jobs)
        }
    }

    fn small_namespaces() -> Namespaces {
        [
            (
                "org.example.first".to_owned(),
                [
                    ("family_name".to_owned(), "Doe".to_owned().into()),
                    ("given_name".to_owned(), "Jane".to_owned().into()),
                ]
                .into_iter()
                .collect(),
            ),
            (
                "org.example.second".to_owned(),
                [("status".to_owned(), true.into())].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect()
    }

    /// Reproduces the old item planning path with an injected random tape.
    fn legacy_to_issuer_namespaces<R>(
        namespaces: Namespaces,
        rng: &mut R,
    ) -> anyhow::Result<IssuerNamespaces>
    where
        R: Rng + ?Sized,
    {
        let mut issuer_namespaces = BTreeMap::new();
        for (name, elements) in namespaces {
            let mut used_ids = HashSet::new();
            let mut items = Vec::new();
            for (element_identifier, element_value) in elements {
                let digest_id = legacy_generate_digest_id(&mut used_ids, rng);
                let random = Vec::from(rng.gen::<[u8; 16]>()).into();
                items.push(Tag24::new(IssuerSignedItem {
                    digest_id,
                    random,
                    element_identifier,
                    element_value,
                })?);
            }
            let items = NonEmptyVec::try_from(items)
                .map_err(|_| anyhow!("at least one element required in each namespace"))?;
            issuer_namespaces.insert(name, items);
        }
        NonEmptyMap::try_from(issuer_namespaces)
            .map_err(|_| anyhow!("at least one namespace required"))
    }

    /// Reproduces the old serial digest path, including random call order.
    fn legacy_digest_namespaces<R>(
        namespaces: &IssuerNamespaces,
        digest_algorithm: DigestAlgorithm,
        enable_decoy_digests: bool,
        rng: &mut R,
    ) -> anyhow::Result<BTreeMap<String, DigestIds>>
    where
        R: Rng + ?Sized,
    {
        let mut value_digests = BTreeMap::new();
        for (name, elements) in namespaces.iter() {
            let mut used_ids: HashSet<_> = elements
                .iter()
                .map(|item| item.as_ref().digest_id)
                .collect();
            let decoy_count: usize = if enable_decoy_digests {
                rng.gen_range(5..10)
            } else {
                0
            };
            let mut digests = BTreeMap::new();
            for item in elements.iter() {
                let input = crate::cbor::to_vec(item)?;
                digests.insert(
                    item.as_ref().digest_id,
                    legacy_digest(digest_algorithm, &input).into(),
                );
            }
            for _ in 0..decoy_count {
                let digest_id = legacy_generate_digest_id(&mut used_ids, rng);
                let input: Vec<u8> = std::iter::repeat_with(|| rng.gen::<u8>())
                    .take(DECOY_BYTES_LENGTH)
                    .collect();
                digests.insert(digest_id, legacy_digest(digest_algorithm, &input).into());
            }
            value_digests.insert(name.clone(), digests);
        }
        Ok(value_digests)
    }

    fn legacy_generate_digest_id<R>(used_ids: &mut HashSet<DigestId>, rng: &mut R) -> DigestId
    where
        R: Rng + ?Sized,
    {
        loop {
            let digest_id = DigestId::new(rng.gen());
            if used_ids.insert(digest_id) {
                return digest_id;
            }
        }
    }

    fn legacy_digest(algorithm: DigestAlgorithm, input: &[u8]) -> Vec<u8> {
        match algorithm {
            DigestAlgorithm::SHA256 => Sha256::digest(input).to_vec(),
            DigestAlgorithm::SHA384 => Sha384::digest(input).to_vec(),
            DigestAlgorithm::SHA512 => Sha512::digest(input).to_vec(),
        }
    }

    #[test]
    fn complete_buffer_fill_preserves_the_explicit_replay_tape() {
        let seed = 0x4344_4c41;
        let mut legacy_rng = ReplayRng::seed_from_u64(seed);
        let legacy: Vec<u8> = std::iter::repeat_with(|| legacy_rng.gen::<u8>())
            .take(DECOY_BYTES_LENGTH)
            .collect();
        let legacy_tail = legacy_rng.gen::<u64>();

        let mut fill_rng = ReplayRng::seed_from_u64(seed);
        let mut filled = vec![0; DECOY_BYTES_LENGTH];
        fill_rng.fill(filled.as_mut_slice());
        let fill_tail = fill_rng.gen::<u64>();

        assert_eq!(legacy, filled);
        assert_eq!(legacy_tail, fill_tail);
    }

    #[test]
    fn digest_id_generation_retries_collisions_in_order() {
        let mut used_ids = [DigestId::new(7)].into_iter().collect();
        let mut rng = U32SequenceRng::new([7, 7, 42, 99]);

        let digest_id = generate_digest_id(&mut used_ids, &mut rng);

        assert_eq!(digest_id, DigestId::new(42));
        assert_eq!(rng.next_u32(), 99);
        assert_eq!(used_ids.len(), 2);
        assert!(used_ids.contains(&DigestId::new(7)));
        assert!(used_ids.contains(&DigestId::new(42)));
    }

    #[test]
    fn serial_executor_matches_legacy_planning_for_fixed_randomness() -> anyhow::Result<()> {
        let Builder {
            validity_info: Some(validity_info),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };

        for digest_algorithm in [
            DigestAlgorithm::SHA256,
            DigestAlgorithm::SHA384,
            DigestAlgorithm::SHA512,
        ] {
            for enable_decoy_digests in [false, true] {
                let seed = 0x4344_4c41;
                let mut legacy_rng = ReplayRng::seed_from_u64(seed);
                let legacy_namespaces =
                    legacy_to_issuer_namespaces(small_namespaces(), &mut legacy_rng)?;
                let expected = legacy_digest_namespaces(
                    &legacy_namespaces,
                    digest_algorithm,
                    enable_decoy_digests,
                    &mut legacy_rng,
                )?;

                let mut executor_rng = ReplayRng::seed_from_u64(seed);
                let executor_namespaces =
                    to_issuer_namespaces(small_namespaces(), &mut executor_rng)?;
                let plan = plan_digest_namespaces(
                    &executor_namespaces,
                    digest_algorithm,
                    enable_decoy_digests,
                    &mut executor_rng,
                )?;
                assert_eq!(legacy_rng.gen::<u64>(), executor_rng.gen::<u64>());
                let mut results = SerialDigestExecutor.execute(&plan.jobs)?;
                results.reverse();
                let actual = assemble_digest_namespaces(&plan, results)?;

                assert_eq!(
                    crate::cbor::to_vec(&legacy_namespaces)?,
                    crate::cbor::to_vec(&executor_namespaces)?
                );
                assert_eq!(expected, actual);

                let legacy_prepared = Mdoc::finish_preparation(
                    "org.example.credential".to_owned(),
                    legacy_namespaces,
                    validity_info.clone(),
                    digest_algorithm,
                    device_key_info.clone(),
                    Algorithm::ES256,
                    expected,
                )?;
                let executor_prepared = Mdoc::finish_preparation(
                    "org.example.credential".to_owned(),
                    executor_namespaces,
                    validity_info.clone(),
                    digest_algorithm,
                    device_key_info.clone(),
                    Algorithm::ES256,
                    actual,
                )?;

                assert_eq!(
                    legacy_prepared.signature_payload(),
                    executor_prepared.signature_payload()
                );
                assert_eq!(
                    crate::cbor::to_vec(&Tag24::new(&legacy_prepared.mso)?)?,
                    crate::cbor::to_vec(&Tag24::new(&executor_prepared.mso)?)?
                );
            }
        }
        Ok(())
    }

    #[test]
    fn digest_jobs_from_all_namespaces_execute_in_one_call() -> anyhow::Result<()> {
        let Builder {
            validity_info: Some(validity_info),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };
        let executor = CountingDigestExecutor::default();
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);

        Mdoc::prepare_with_validated_inputs_rng_and_digest_executor(
            "org.example.credential".to_owned(),
            small_namespaces(),
            validity_info,
            DigestAlgorithm::SHA256,
            device_key_info,
            Algorithm::ES256,
            false,
            &mut rng,
            &executor,
        )?;

        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert_eq!(executor.jobs.load(Ordering::Relaxed), 3);
        Ok(())
    }

    #[test]
    fn decoy_planning_preserves_count_size_and_namespace_boundaries() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);
        let issuer_namespaces = to_issuer_namespaces(small_namespaces(), &mut rng)?;
        let real_counts: BTreeMap<_, _> = issuer_namespaces
            .iter()
            .map(|(name, elements)| (name.clone(), elements.len()))
            .collect();
        let plan =
            plan_digest_namespaces(&issuer_namespaces, DigestAlgorithm::SHA256, true, &mut rng)?;
        let jobs_by_identity: BTreeMap<_, _> = plan
            .jobs
            .iter()
            .map(|job| ((job.credential_id, job.job_id), job))
            .collect();

        for namespace in &plan.namespaces {
            let real_count = real_counts[&namespace.name];
            let decoys = &namespace.digests[real_count..];
            assert!((5..=9).contains(&decoys.len()));
            for decoy in decoys {
                let job = jobs_by_identity[&(decoy.credential_id, decoy.job_id)];
                assert_eq!(job.input.len(), DECOY_BYTES_LENGTH);
                assert!(job.ordinal >= real_count);
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_randomness_produces_schedule_independent_signature_payload() -> anyhow::Result<()> {
        let Builder {
            doc_type: Some(doc_type),
            namespaces: Some(namespaces),
            validity_info: Some(validity_info),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };

        for digest_algorithm in [
            DigestAlgorithm::SHA256,
            DigestAlgorithm::SHA384,
            DigestAlgorithm::SHA512,
        ] {
            for enable_decoy_digests in [false, true] {
                let seed = 0x4344_4c41;
                let mut serial_rng = StdRng::seed_from_u64(seed);
                let serial = Mdoc::prepare_with_validated_inputs_rng_and_digest_executor(
                    doc_type.clone(),
                    namespaces.clone(),
                    validity_info.clone(),
                    digest_algorithm,
                    device_key_info.clone(),
                    Algorithm::ES256,
                    enable_decoy_digests,
                    &mut serial_rng,
                    &SerialDigestExecutor,
                )?;
                let serial_mso_bytes = crate::cbor::to_vec(&Tag24::new(&serial.mso)?)?;
                let serial_namespace_bytes = crate::cbor::to_vec(&serial.namespaces)?;

                for rotation in 0..8 {
                    let mut reordered_rng = StdRng::seed_from_u64(seed);
                    let reordered = Mdoc::prepare_with_validated_inputs_rng_and_digest_executor(
                        doc_type.clone(),
                        namespaces.clone(),
                        validity_info.clone(),
                        digest_algorithm,
                        device_key_info.clone(),
                        Algorithm::ES256,
                        enable_decoy_digests,
                        &mut reordered_rng,
                        &RotatingDigestExecutor { rotation },
                    )?;

                    assert_eq!(serial.signature_payload(), reordered.signature_payload());
                    assert_eq!(
                        serial_mso_bytes,
                        crate::cbor::to_vec(&Tag24::new(&reordered.mso)?)?
                    );
                    assert_eq!(
                        serial_namespace_bytes,
                        crate::cbor::to_vec(&reordered.namespaces)?
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn executor_failure_aborts_mdoc_preparation() {
        let Builder {
            doc_type: Some(doc_type),
            namespaces: Some(namespaces),
            validity_info: Some(validity_info),
            digest_algorithm: Some(digest_algorithm),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);

        let error = Mdoc::prepare_with_validated_inputs_rng_and_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            Algorithm::ES256,
            false,
            &mut rng,
            &FailingDigestExecutor,
        )
        .expect_err("executor failure must not produce a prepared credential");

        assert_eq!(error.to_string(), "digest execution failed");
    }

    #[test]
    fn public_executor_failure_aborts_mdoc_preparation() {
        let Builder {
            doc_type: Some(doc_type),
            namespaces: Some(namespaces),
            validity_info: Some(validity_info),
            digest_algorithm: Some(digest_algorithm),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };

        let error = Mdoc::prepare_with_digest_executor(
            doc_type,
            namespaces,
            validity_info,
            digest_algorithm,
            device_key_info,
            Algorithm::ES256,
            false,
            &FailingDigestExecutor,
        )
        .expect_err("executor failure must not produce a prepared credential");

        assert_eq!(error.to_string(), "digest execution failed");
    }

    #[test]
    fn public_assembly_preserves_result_error_precedence() {
        for (fault, expected_error) in [
            (
                ResultSetFault::ExtraFirst,
                "digest executor returned an unexpected result",
            ),
            (
                ResultSetFault::DuplicateFuture,
                "digest executor returned duplicate result identity",
            ),
            (
                ResultSetFault::MissingFirst,
                "digest executor omitted a planned result",
            ),
            (
                ResultSetFault::InvalidLengthAndDuplicate,
                "digest executor returned duplicate result identity",
            ),
        ] {
            let Builder {
                doc_type: Some(doc_type),
                namespaces: Some(namespaces),
                validity_info: Some(validity_info),
                digest_algorithm: Some(digest_algorithm),
                device_key_info: Some(device_key_info),
                ..
            } = minimal_test_mdoc_builder()
            else {
                unreachable!("the minimal mdoc builder has every required input")
            };

            let error = Mdoc::prepare_with_digest_executor(
                doc_type,
                namespaces,
                validity_info,
                digest_algorithm,
                device_key_info,
                Algorithm::ES256,
                false,
                &FaultyDigestExecutor(fault),
            )
            .expect_err("a malformed result set must fail closed");

            assert_eq!(error.to_string(), expected_error);
        }
    }

    #[test]
    fn public_validation_precedes_executor_execution() {
        let Builder {
            validity_info: Some(validity_info),
            digest_algorithm: Some(digest_algorithm),
            device_key_info: Some(device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };

        let empty_namespaces = Mdoc::prepare_with_digest_executor(
            "org.example.credential".to_owned(),
            BTreeMap::new(),
            validity_info.clone(),
            digest_algorithm,
            device_key_info.clone(),
            Algorithm::ES256,
            false,
            &PanicDigestExecutor,
        )
        .expect_err("empty namespaces must fail before execution");
        assert_eq!(
            empty_namespaces.to_string(),
            "at least one namespace required"
        );

        let empty_elements = Mdoc::prepare_with_digest_executor(
            "org.example.credential".to_owned(),
            [("org.example.empty".to_owned(), BTreeMap::new())]
                .into_iter()
                .collect(),
            validity_info,
            digest_algorithm,
            device_key_info,
            Algorithm::ES256,
            false,
            &PanicDigestExecutor,
        )
        .expect_err("empty namespace elements must fail before execution");
        assert_eq!(
            empty_elements.to_string(),
            "at least one element required in each namespace"
        );
    }

    #[test]
    fn key_authorization_errors_precede_shape_validation_and_execution() {
        let Builder {
            validity_info: Some(validity_info),
            digest_algorithm: Some(digest_algorithm),
            device_key_info: Some(mut device_key_info),
            ..
        } = minimal_test_mdoc_builder()
        else {
            unreachable!("the minimal mdoc builder has every required input")
        };
        let namespace = "org.example.first".to_owned();
        let authorized_elements = NonEmptyMap::try_from(
            [(
                namespace.clone(),
                NonEmptyVec::try_from(vec!["family_name".to_owned()]).unwrap(),
            )]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        )
        .unwrap();
        device_key_info.key_authorizations = Some(crate::definitions::KeyAuthorizations {
            namespaces: Some(NonEmptyVec::try_from(vec![namespace.clone()]).unwrap()),
            data_elements: Some(authorized_elements),
        });

        let error = Mdoc::prepare_with_digest_executor(
            "org.example.credential".to_owned(),
            BTreeMap::new(),
            validity_info,
            digest_algorithm,
            device_key_info,
            Algorithm::ES256,
            false,
            &PanicDigestExecutor,
        )
        .expect_err("invalid authorizations must fail before shape validation");

        assert_eq!(
            error.to_string(),
            "namespace 'org.example.first' cannot be present in both authorized_namespaces and authorized_data_elements"
        );
    }

    #[test]
    fn builder_uses_the_caller_selected_executor() -> anyhow::Result<()> {
        let builder = minimal_test_mdoc_builder().enable_decoy_digests(false);
        let expected_jobs: usize = builder
            .namespaces
            .as_ref()
            .expect("the minimal builder has namespaces")
            .values()
            .map(BTreeMap::len)
            .sum();
        let executor = CountingDigestExecutor::default();

        builder.prepare_with_digest_executor(Algorithm::ES256, &executor)?;

        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert_eq!(executor.jobs.load(Ordering::Relaxed), expected_jobs);
        Ok(())
    }

    #[test]
    fn assembly_rejects_invalid_executor_results() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);
        let issuer_namespaces = to_issuer_namespaces(small_namespaces(), &mut rng)?;
        let plan =
            plan_digest_namespaces(&issuer_namespaces, DigestAlgorithm::SHA256, false, &mut rng)?;

        let mut duplicate = SerialDigestExecutor.execute(&plan.jobs)?;
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            assemble_digest_namespaces(&plan, duplicate)
                .expect_err("duplicate results must be rejected")
                .to_string(),
            "digest executor returned duplicate result identity"
        );

        let mut missing = SerialDigestExecutor.execute(&plan.jobs)?;
        missing.pop();
        assert_eq!(
            assemble_digest_namespaces(&plan, missing)
                .expect_err("missing results must be rejected")
                .to_string(),
            "digest executor omitted a planned result"
        );

        let mut unexpected = SerialDigestExecutor.execute(&plan.jobs)?;
        let mut extra = unexpected[0].clone();
        extra.job_id = u64::MAX;
        unexpected.push(extra);
        assert_eq!(
            assemble_digest_namespaces(&plan, unexpected)
                .expect_err("unexpected results must be rejected")
                .to_string(),
            "digest executor returned an unexpected result"
        );

        let mut invalid_length = SerialDigestExecutor.execute(&plan.jobs)?;
        invalid_length[0].digest.pop();
        assert_eq!(
            assemble_digest_namespaces(&plan, invalid_length)
                .expect_err("invalid digest lengths must be rejected")
                .to_string(),
            "digest executor returned an invalid digest length"
        );

        let mut changed_ordinal = SerialDigestExecutor.execute(&plan.jobs)?;
        changed_ordinal[0].ordinal = usize::MAX;
        assert_eq!(
            assemble_digest_namespaces(&plan, changed_ordinal)
                .expect_err("changed ordinals must be rejected")
                .to_string(),
            "digest executor changed result identity metadata"
        );

        let mut changed_credential = SerialDigestExecutor.execute(&plan.jobs)?;
        changed_credential[0].credential_id = u64::MAX;
        assert_eq!(
            assemble_digest_namespaces(&plan, changed_credential)
                .expect_err("changed credential IDs must be rejected")
                .to_string(),
            "digest executor omitted a planned result"
        );

        let mut changed_job = SerialDigestExecutor.execute(&plan.jobs)?;
        changed_job[0].job_id = u64::MAX;
        assert_eq!(
            assemble_digest_namespaces(&plan, changed_job)
                .expect_err("changed job IDs must be rejected")
                .to_string(),
            "digest executor omitted a planned result"
        );

        Ok(())
    }

    #[test]
    fn assembly_rejects_invalid_digest_plans() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);
        let issuer_namespaces = to_issuer_namespaces(small_namespaces(), &mut rng)?;
        let plan =
            plan_digest_namespaces(&issuer_namespaces, DigestAlgorithm::SHA256, false, &mut rng)?;

        let mut duplicate_digest_id_plan = plan.clone();
        duplicate_digest_id_plan.namespaces[0].digests[1].digest_id =
            duplicate_digest_id_plan.namespaces[0].digests[0].digest_id;
        let valid_results = SerialDigestExecutor.execute(&duplicate_digest_id_plan.jobs)?;
        assert_eq!(
            assemble_digest_namespaces(&duplicate_digest_id_plan, valid_results)
                .expect_err("duplicate digest IDs within a namespace must be rejected")
                .to_string(),
            "mdoc digest plan contains a duplicate digest ID within a namespace"
        );

        let mut duplicate_job_identity_plan = plan.clone();
        duplicate_job_identity_plan.jobs[1].credential_id =
            duplicate_job_identity_plan.jobs[0].credential_id;
        duplicate_job_identity_plan.jobs[1].job_id = duplicate_job_identity_plan.jobs[0].job_id;
        let original_results = SerialDigestExecutor.execute(&plan.jobs)?;
        assert_eq!(
            assemble_digest_namespaces(&duplicate_job_identity_plan, original_results)
                .expect_err("duplicate planned job identities must be rejected")
                .to_string(),
            "mdoc digest plan contains duplicate job identity"
        );

        let mut unknown_job_plan = plan.clone();
        unknown_job_plan.namespaces[0].digests[0].job_id = u64::MAX;
        let valid_results = SerialDigestExecutor.execute(&unknown_job_plan.jobs)?;
        assert_eq!(
            assemble_digest_namespaces(&unknown_job_plan, valid_results)
                .expect_err("unknown planned job references must be rejected")
                .to_string(),
            "mdoc digest plan references an unknown job"
        );

        let mut unreferenced_job_plan = plan.clone();
        unreferenced_job_plan.jobs.push(DigestJob {
            credential_id: MDOC_CREDENTIAL_ID,
            job_id: u64::MAX,
            ordinal: usize::MAX,
            algorithm: DigestAlgorithm::SHA256,
            input: b"unreferenced".to_vec(),
        });
        let valid_results = SerialDigestExecutor.execute(&unreferenced_job_plan.jobs)?;
        assert_eq!(
            assemble_digest_namespaces(&unreferenced_job_plan, valid_results)
                .expect_err("unreferenced jobs must be rejected")
                .to_string(),
            "mdoc digest plan contains an unreferenced job"
        );

        let mut duplicate_namespace_plan = plan.clone();
        duplicate_namespace_plan
            .namespaces
            .push(PlannedMdocNamespace {
                name: duplicate_namespace_plan.namespaces[0].name.clone(),
                digests: Vec::new(),
            });
        let valid_results = SerialDigestExecutor.execute(&duplicate_namespace_plan.jobs)?;
        assert_eq!(
            assemble_digest_namespaces(&duplicate_namespace_plan, valid_results)
                .expect_err("duplicate namespaces must be rejected")
                .to_string(),
            "mdoc digest plan contains a duplicate namespace"
        );

        let mut cross_namespace_duplicate_id_plan = plan;
        cross_namespace_duplicate_id_plan.namespaces[1].digests[0].digest_id =
            cross_namespace_duplicate_id_plan.namespaces[0].digests[0].digest_id;
        let valid_results =
            SerialDigestExecutor.execute(&cross_namespace_duplicate_id_plan.jobs)?;
        assert!(
            assemble_digest_namespaces(&cross_namespace_duplicate_id_plan, valid_results).is_ok(),
            "digest IDs are scoped to their namespaces"
        );

        Ok(())
    }

    #[test]
    fn assembly_error_precedence_is_result_order_independent() -> anyhow::Result<()> {
        let mut rng = StdRng::seed_from_u64(0x4344_4c41);
        let issuer_namespaces = to_issuer_namespaces(small_namespaces(), &mut rng)?;
        let plan =
            plan_digest_namespaces(&issuer_namespaces, DigestAlgorithm::SHA256, false, &mut rng)?;

        for reverse_results in [false, true] {
            let mut duplicate_and_unexpected = SerialDigestExecutor.execute(&plan.jobs)?;
            duplicate_and_unexpected.push(duplicate_and_unexpected[0].clone());
            let mut extra = duplicate_and_unexpected[1].clone();
            extra.job_id = u64::MAX;
            duplicate_and_unexpected.push(extra);
            if reverse_results {
                duplicate_and_unexpected.reverse();
            }
            assert_eq!(
                assemble_digest_namespaces(&plan, duplicate_and_unexpected)
                    .expect_err("duplicate identity must have stable precedence")
                    .to_string(),
                "digest executor returned duplicate result identity"
            );

            let mut missing_and_unexpected = SerialDigestExecutor.execute(&plan.jobs)?;
            let mut extra = missing_and_unexpected
                .pop()
                .expect("the plan contains digest jobs");
            extra.job_id = u64::MAX;
            missing_and_unexpected.push(extra);
            if reverse_results {
                missing_and_unexpected.reverse();
            }
            assert_eq!(
                assemble_digest_namespaces(&plan, missing_and_unexpected)
                    .expect_err("missing result must have stable precedence")
                    .to_string(),
                "digest executor omitted a planned result"
            );
        }

        Ok(())
    }

    fn fixed_digest_items() -> Vec<IssuerSignedItemBytes> {
        vec![
            Tag24::new(IssuerSignedItem {
                digest_id: DigestId::new(7),
                random: vec![0x11; 16].into(),
                element_identifier: "family_name".to_owned(),
                element_value: ciborium::Value::Text("Doe".to_owned()),
            })
            .unwrap(),
            Tag24::new(IssuerSignedItem {
                digest_id: DigestId::new(42),
                random: vec![0xa5; 16].into(),
                element_identifier: "age_over_21".to_owned(),
                element_value: ciborium::Value::Bool(true),
            })
            .unwrap(),
        ]
    }

    fn digest_fixed_items(
        items: &[IssuerSignedItemBytes],
        algorithm: DigestAlgorithm,
        enable_decoy_digests: bool,
        seed: u64,
    ) -> anyhow::Result<DigestIds> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut jobs = Vec::new();
        let mut next_job_id = 0;
        let digests = plan_digest_namespace(
            items,
            algorithm,
            enable_decoy_digests,
            &mut rng,
            &mut next_job_id,
            &mut jobs,
        )?;
        let plan = MdocDigestPlan {
            namespaces: vec![PlannedMdocNamespace {
                name: "org.example.fixed".to_owned(),
                digests,
            }],
            jobs,
        };
        let mut namespaces =
            assemble_digest_namespaces(&plan, SerialDigestExecutor.execute(&plan.jobs)?)?;
        Ok(namespaces
            .remove("org.example.fixed")
            .expect("the fixed namespace must be restored"))
    }

    #[test]
    fn fixed_item_digest_vectors() -> anyhow::Result<()> {
        let items = fixed_digest_items();

        for (algorithm, expected) in [
            (
                DigestAlgorithm::SHA256,
                [
                    "e36bd25994498a512266bf3a676c3730397a372cc84272ae66ffaee7669ab945",
                    "b94ad03a2048d101a1760a776e954ebc024745765a1b56961e33cd54baa54e9f",
                ],
            ),
            (
                DigestAlgorithm::SHA384,
                [
                    "a535280fcf68eaa61d60766757a86bb3c15e9fa47f6eee12f225ce533b9ac381ba6201e98484dce684ce120f7b15353b",
                    "f20df420a735a76cc6faf6cbe2ea74dcad19592b62b2f495a70300922e930189a860255b1355d8998e8015a1cbda2cb5",
                ],
            ),
            (
                DigestAlgorithm::SHA512,
                [
                    "fc81b2b1f4398f3583543b65f9d7e960ee77136ed7ca3d17ccb7cc4d65badbc1f4fac6e8e03b191e30d642a3f3fbe00316acee20a9bcbfdd152beb13b917c2bf",
                    "c619cb13f3b860c7d270d4fe5e585e22c0f9318eae80f412ed980d410a399d377c7c7f80956fb78ca20606842fbb074328d297f1e0126f7e32d6d3e22a9f5662",
                ],
            ),
        ] {
            let digests = digest_fixed_items(&items, algorithm, false, 0x4344_4c41)?;
            for (digest_id, expected) in [DigestId::new(7), DigestId::new(42)]
                .into_iter()
                .zip(expected)
            {
                assert_eq!(
                    hex::encode(digests.get(&digest_id).unwrap().as_ref()),
                    expected
                );
            }
        }

        Ok(())
    }

    #[test]
    fn real_item_digest_covers_the_tag24_wrapper() -> anyhow::Result<()> {
        let items = fixed_digest_items();
        let item = &items[0];
        let wrapper_bytes = crate::cbor::to_vec(item)?;
        let digests = digest_fixed_items(
            std::slice::from_ref(item),
            DigestAlgorithm::SHA256,
            false,
            0x4344_4c41,
        )?;
        let actual = digests.get(&DigestId::new(7)).unwrap().as_ref();

        assert_eq!(actual, Sha256::digest(wrapper_bytes).as_slice());
        assert_ne!(actual, Sha256::digest(&item.inner_bytes).as_slice());
        Ok(())
    }

    #[test]
    fn decoy_digest_count_and_lengths_match_existing_behavior() -> anyhow::Result<()> {
        let items = fixed_digest_items();
        for (algorithm, digest_length) in [
            (DigestAlgorithm::SHA256, 32),
            (DigestAlgorithm::SHA384, 48),
            (DigestAlgorithm::SHA512, 64),
        ] {
            let mut observed_counts = HashSet::new();
            for seed in 0..32 {
                let digests = digest_fixed_items(&items, algorithm, true, seed)?;
                assert!((items.len() + 5..=items.len() + 9).contains(&digests.len()));
                assert!(digests
                    .values()
                    .all(|digest| digest.as_ref().len() == digest_length));
                observed_counts.insert(digests.len());
            }
            assert!(observed_counts.len() > 1);
        }
        Ok(())
    }

    #[test]
    fn decoy_digests() {
        let mdoc_builder = minimal_test_mdoc_builder();
        let x5chain = X5Chain::builder()
            .with_pem_certificate(ISSUER_CERT)
            .unwrap()
            .build()
            .unwrap();
        let signer: SigningKey = SecretKey::from_pkcs8_pem(ISSUER_KEY)
            .expect("failed to parse pem")
            .into();

        let mdoc_decoy = &mdoc_builder
            .clone()
            .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
            .unwrap();

        let mdoc_builder = mdoc_builder.enable_decoy_digests(false);
        let mdoc_no_decoy_1 = &mdoc_builder
            .clone()
            .issue::<SigningKey, Signature>(x5chain.clone(), signer.clone())
            .unwrap();
        let mdoc_no_decoy_2 = &mdoc_builder
            .issue::<SigningKey, Signature>(x5chain, signer)
            .unwrap();

        // Asserting on number of digests
        assert_eq!(
            mdoc_decoy
                .namespaces
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_1
                .namespaces
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
        assert_ne!(
            mdoc_decoy
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_1
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
        assert_eq!(
            mdoc_no_decoy_1
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
            mdoc_no_decoy_2
                .mso
                .value_digests
                .values()
                .fold(0, |acc, x| acc + x.len()),
        );
    }
}
