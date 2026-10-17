//! Sources de failles branchées sur le cadre de synchronisation
//! (`vulns/sync`) : chacune lit son format et pousse des failles validées
//! par `Advisory::build`. F2 : exports OSV ; F3 : Wordfence,
//! Friends-Of-Presta. Tables d'enrichissement de F4, poussées en lignes
//! typées : CISA KEV, FIRST EPSS.

pub mod epss;
pub mod kev;
pub mod osv;
