// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use attest_data::{DiceTcbInfo, Log, Measurement, DICE_TCB_INFO};
use camino::Utf8PathBuf;
use der::{Decode, DecodeValue, Header, SliceReader};
use rats_corim::Corim;
use std::collections::HashSet;

pub use dice_mfg_msgs::PlatformId;
use x509_cert::PkiPath;

pub fn corim_to_set(
    paths: &Vec<Utf8PathBuf>,
) -> Result<HashSet<Measurement>, Error> {
    let mut set = HashSet::new();
    for path in paths {
        let corim = Corim::from_file(path.into()).map_err(Error::Corim)?;
        for m in corim.iter_measurements() {
            set.insert(Measurement::Sha3_256(m.try_into().unwrap()));
        }
    }
    Ok(set)
}

pub fn artifacts_to_set(
    pki_path: &PkiPath,
    log: &Log,
) -> Result<HashSet<Measurement>, Error> {
    let mut measurements = HashSet::new();

    for cert in pki_path {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions {
                if ext.extn_id == DICE_TCB_INFO {
                    //if !ext.critical {
                    //    warn!("DiceTcbInfo extension is non-critical");
                    //}

                    let mut reader =
                        SliceReader::new(ext.extn_value.as_bytes())?;
                    let header = Header::decode(&mut reader).unwrap();

                    let tcb_info =
                        DiceTcbInfo::decode_value(&mut reader, header).unwrap();
                    if let Some(fwid_vec) = &tcb_info.fwids {
                        for fwid in fwid_vec {
                            let measurement =
                                Measurement::try_from(fwid).unwrap();
                            measurements.insert(measurement);
                        }
                    }
                }
            }
        }
    }

    for measurement in log.iter() {
        measurements.insert(*measurement);
    }

    Ok(measurements)
}

pub enum MeasureResult {
    Ok,
    NotASubset,
    EmptyCorpus,
}

pub fn measure_from_corpus(
    corpus: &Vec<Utf8PathBuf>,
) -> Result<MeasureResult, Error> {
    if corpus.is_empty() {
        return Ok(MeasureResult::EmptyCorpus);
    }

    let corpus = crate::measurements::corim_to_set(corpus)?;

    let ipcc = crate::ipcc::Ipcc::new().map_err(crate::Error::RotRequest)?;
    let log = ipcc.get_measurement_log()?;
    let certs = ipcc.get_certificates()?;

    let measurements = crate::measurements::artifacts_to_set(&certs, &log)?;

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
