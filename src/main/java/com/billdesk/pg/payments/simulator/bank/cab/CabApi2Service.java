package com.billdesk.pg.payments.simulator.bank.cab;

import java.net.URI;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.billdesk.pg.payments.simulator.model.SimulatorRecord;
import com.billdesk.pg.payments.simulator.repository.SimulatorRecordStore;
import com.billdesk.pg.payments.simulator.util.UrlUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class CabApi2Service {

    private static final Logger logger =
            LogManager.getLogger(CabApi2Service.class);

    private static final SecureRandom RANDOM =
            new SecureRandom();

    private final SimulatorRecordStore store;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    @Value("${simulator.cab.checksum-key:}")
    private String checksumKey;

    @Value("${simulator.cab.encryption-key}")
    private String encryptionKey;

    @Value("${simulator.cab.iv}")
    private String iv;

    public CabApi2Service(
            SimulatorRecordStore store,
            ObjectMapper objectMapper,
            RestTemplate restTemplate) {

        this.store = store;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplate;
    }

    /**
     * Called immediately after API 1 has been validated
     * and SimulatorRecord has been persisted.
     */
    public void sendAcknowledgement(
            SimulatorRecord record,
            Map<String, String> initFields) {

        String txnId =
                record.getTxnId();

        /*
         * Generate only once.
         *
         * If API 1 is retried for the same transaction,
         * reuse the existing CAB bank reference.
         */
        String bankRef =
                getOrCreateBankRef(record);

        Map<String, String> fields =
                new LinkedHashMap<>();

        /*
         * API 2 positive acknowledgement.
         */
        fields.put(
                "status",
                "P"
        );

        fields.put(
                "payment_ref_no",
                txnId
        );

        fields.put(
                "biller_name",
                safe(
                        initFields.get("biller_name")
                )
        );

        fields.put(
                "bank_ref_no",
                bankRef
        );

        fields.put(
                "amount",
                safe(
                        record.getTxnAmount()
                )
        );

        fields.put(
                "account_no",
                safe(
                        initFields.get("account_no")
                )
        );

        fields.put(
                "error_msg",
                "Maker Initiated"
        );

        /*
         * API 2 checksum.
         */
        String checksumInput =
                CabChecksumUtil
                        .buildApi2ChecksumString(
                                fields,
                                checksumKey
                        );

        String checkval =
                CabChecksumUtil
                        .computeChecksum(
                                checksumInput
                        );

        fields.put(
                "checkval",
                checkval
        );

        String plainPayload =
                buildPipePayload(
                        fields
                );

        String encryptedData =
                CabEncryptionUtil.encrypt(
                        plainPayload,
                        encryptionKey,
                        iv
                );

        /*
         * API 2 goes to return_url received in API 1.
         */
        String returnUrl =
                record.getReturnUrl();

        if (returnUrl == null ||
                returnUrl.isBlank()) {

            throw new IllegalStateException(
                    "CAB API 2 return_url missing for txn="
                            + txnId
            );
        }

        String callbackUrl =
                UrlUtil.withQuery(
                        returnUrl,
                        Map.of(
                                "data",
                                encryptedData
                        )
                );

        logger.info(
                "Sending CAB API 2 acknowledgement txn={} bankRef={} url={}",
                txnId,
                bankRef,
                returnUrl
        );

        try {

            ResponseEntity<String> response =
                    restTemplate.getForEntity(
                            URI.create(
                                    callbackUrl
                            ),
                            String.class
                    );

            logger.info(
                    "CAB API 2 acknowledgement successful txn={} bankRef={} status={}",
                    txnId,
                    bankRef,
                    response.getStatusCode()
            );

            updateApi2Status(
                    record,
                    "SENT"
            );

        } catch (Exception e) {

            /*
             * Important:
             *
             * We DO NOT remove or regenerate bank_ref_no.
             * A retry must reuse the same reference.
             */
            updateApi2Status(
                    record,
                    "FAILED"
            );

            logger.error(
                    "CAB API 2 acknowledgement failed txn={} bankRef={} url={}",
                    txnId,
                    bankRef,
                    returnUrl,
                    e
            );
        }
    }

    /**
     * API 2 owns creation of the CAB bank reference.
     *
     * Existing value is reused on retries.
     */
    public String getOrCreateBankRef(
            SimulatorRecord record) {

        Map<String, String> metadata =
                readMetadata(
                        record
                );

        String existing =
                metadata.get(
                        "bank_ref_no"
                );

        if (existing != null &&
                !existing.isBlank()) {

            logger.debug(
                    "Reusing existing CAB bank reference txn={} bankRef={}",
                    record.getTxnId(),
                    existing
            );

            return existing;
        }

        String bankRef =
                generateBankRef();

        metadata.put(
                "bank_ref_no",
                bankRef
        );

        metadata.put(
                "api2_status",
                "CREATED"
        );

        metadata.put(
                "api2_created_at",
                LocalDateTime.now()
                        .toString()
        );

        writeMetadata(
                record,
                metadata
        );

        /*
         * Persist BEFORE making API 2 network call.
         *
         * This is critical for idempotency.
         */
        store.save(
                record
        );

        logger.info(
                "Generated and persisted CAB bank reference txn={} bankRef={}",
                record.getTxnId(),
                bankRef
        );

        return bankRef;
    }

    /**
     * Used by APIs 3, 4 and 5.
     *
     * Unlike getOrCreateBankRef(), this method does not
     * silently create a new value.
     */
    public String getBankRef(
            SimulatorRecord record) {

        Map<String, String> metadata =
                readMetadata(
                        record
                );

        String bankRef =
                metadata.get(
                        "bank_ref_no"
                );

        if (bankRef == null ||
                bankRef.isBlank()) {

            throw new IllegalStateException(
                    "CAB bank_ref_no missing from BANK_METADATA for txn="
                            + record.getTxnId()
            );
        }

        return bankRef;
    }

    private void updateApi2Status(
            SimulatorRecord record,
            String status) {

        Map<String, String> metadata =
                readMetadata(
                        record
                );

        metadata.put(
                "api2_status",
                status
        );

        metadata.put(
                "api2_updated_at",
                LocalDateTime.now()
                        .toString()
        );

        writeMetadata(
                record,
                metadata
        );

        store.save(
                record
        );
    }

    private Map<String, String> readMetadata(
            SimulatorRecord record) {

        if (record.getBankExecutionMetadata() == null ||
                record.getBankExecutionMetadata().isBlank()) {

            return new LinkedHashMap<>();
        }

        try {

            return objectMapper.readValue(
                    record.getBankExecutionMetadata(),
                    new TypeReference<
                            Map<String, String>>() {
                    }
            );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Could not deserialize CAB BANK_METADATA for txn="
                            + record.getTxnId(),
                    e
            );
        }
    }

    private void writeMetadata(
            SimulatorRecord record,
            Map<String, String> metadata) {

        try {

            record.setBankExecutionMetadata(
                    objectMapper.writeValueAsString(
                            metadata
                    )
            );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Could not serialize CAB BANK_METADATA for txn="
                            + record.getTxnId(),
                    e
            );
        }
    }

    private String generateBankRef() {

        /*
         * Generates a 12-digit numeric reference.
         *
         * Example:
         * 583721849231
         */
        long value =
                100_000_000_000L
                        + nextLong(
                                900_000_000_000L
                        );

        return Long.toString(
                value
        );
    }

    private long nextLong(
            long bound) {

        long value =
                RANDOM.nextLong();

        if (value == Long.MIN_VALUE) {
            value = 0;
        }

        value =
                Math.abs(
                        value
                );

        return value % bound;
    }

    private String buildPipePayload(
            Map<String, String> fields) {

        StringBuilder builder =
                new StringBuilder();

        for (Map.Entry<String, String> entry :
                fields.entrySet()) {

            if (builder.length() > 0) {
                builder.append("|");
            }

            builder
                    .append(entry.getKey())
                    .append("=")
                    .append(
                            safe(
                                    entry.getValue()
                            )
                    );
        }

        return builder.toString();
    }

    private String safe(
            String value) {

        return value == null
                ? ""
                : value;
    }
}