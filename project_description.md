5 - Secure Data Lakes
Data lakes are large-scale repositories (frequently cloud-based) designed to store, process and analyze
data across multiple formats and schemas. Their growing adoption in healthcare, finance and scientific
research means they increasingly handle highly sensitive personal data. While collaborative access
multiplies their utility, it simultaneously multiplies the attack surface: data must remain confidential and
authentic against a wide range of adversaries, including compromised cloud infrastructure, malicious
insiders, and network-level attackers. This project explores how trusted hardware can serve as a
foundational security primitive for a collaborative medical data lake, enforcing confidentiality and
integrity guarantees that survive even a compromised cloud provider.
Consider a medical data lake shared among a consortium of hospitals, research institutions and public
health authorities. Each participant contributes patient records (e.g., diagnoses, lab results, treatment
outcomes) and wishes to run aggregate analytical queries (e.g., disease prevalence averages, drug efficacy
correlations) across the combined dataset without exposing individual records to other participants or
to the cloud operator.
Suggested Approach Start by deploying a minimal SGX application (e.g., using the Intel SGX
SDK or the Gramine LibOS) that can receive an encrypted record, decrypt it inside the enclave, and
return an authenticated aggregation. Expand this to support multiple contributors and a range of
SQL-style aggregate queries. Validate remote attestation using Intel’s DCAP (Data Center Attestation
Primitives) infrastructure or an emulated equivalent.
Associated professor: Bernardo Portela