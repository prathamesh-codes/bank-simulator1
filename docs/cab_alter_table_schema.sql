-- Adds a generic execution metadata column for storing bank-specific runtime data in JSON format.
-- For CAB, this is used to persist the bank_ref_no generated during Bank Transaction Create Acknowledgement API,
-- along with related execution details such as acknowledgement status and timestamps. The existing BANK_REF column
-- is left unchanged because it is still used by the common simulator flow, while CAB reuses the value stored here
-- consistently for S2S Callback API and for Double Verification API.

ALTER TABLE PGI_NETBANKING_SIMULATOR
    ADD BANK_EXECUTION_METADATA CLOB;