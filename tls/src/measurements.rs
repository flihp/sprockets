// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use camino::Utf8PathBuf;

pub use dice_mfg_msgs::PlatformId;
use dice_verifier::{
    ipcc::AttestIpcc, Attest, Corim, MeasurementSet, ReferenceMeasurements,
};

pub enum MeasureResult {
    Ok,
    NotASubset,
    EmptyCorpus,
}

pub fn measure_from_corpus(
    corpus: &[Utf8PathBuf],
) -> Result<MeasureResult, Error> {
    if corpus.is_empty() {
        return Ok(MeasureResult::EmptyCorpus);
    }

    let corims = corpus
        .iter()
        .map(|f| Corim::from_file(f).map_err(Error::Corim))
        .collect::<Result<Vec<Corim>, _>>()?;

    let corpus = ReferenceMeasurements::try_from(&corims[..])?;

    let ipcc = AttestIpcc::new()?;
    let log = ipcc.get_measurement_log()?;
    let certs = ipcc.get_certificates()?;

    let measurements = MeasurementSet::from_artifacts(&certs, &log)?;

    if !measurements.is_subset(&corpus) {
        return Ok(MeasureResult::NotASubset);
    }

    Ok(MeasureResult::Ok)
}

pub fn get_platform_id(
    certs: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<String, Error> {
    use der::Decode;

    let mut chain = x509_cert::PkiPath::new();

    for c in certs {
        chain.push(
            crate::Certificate::from_der(c.as_ref()).map_err(Error::Der)?,
        );
    }

    Ok(String::from(
        PlatformId::try_from(&chain).unwrap().as_str().unwrap(),
    ))
}
