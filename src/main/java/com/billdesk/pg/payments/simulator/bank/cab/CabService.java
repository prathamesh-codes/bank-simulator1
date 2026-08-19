package com.billdesk.pg.payments.simulator.bank.cab;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import com.billdesk.pg.payments.simulator.core.NetbankingBankSimulator;
import com.billdesk.pg.payments.simulator.dto.CallbackDelivery;
import com.billdesk.pg.payments.simulator.dto.ParsedInit;
import com.billdesk.pg.payments.simulator.dto.SimulatedCase;
import com.billdesk.pg.payments.simulator.dto.ValidationResult;
import com.billdesk.pg.payments.simulator.dto.VerificationWireResponse;
import com.billdesk.pg.payments.simulator.model.SimulatorRecord;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class CabService implements NetbankingBankSimulator {

    private static final Logger logger =
            LogManager.getLogger(CabService.class);

    private static final List<String> REQUIRED_INIT_FIELDS =
            List.of(
                    "mode",
                    "payee_id",
                    "biller_name",
                    "payment_ref_no",
                    "amount",
                    "currency",
                    "return_url",
                    "checkval"
            );

    private static final List<String> REQUIRED_VERIFY_FIELDS =
            List.of(
                    "mode",
                    "payment_ref_no",
                    "payee_id",
                    "biller_name",
                    "bank_ref_no",
                    "amount",
                    "currency",
                    "checkval"
            );

    private static final List<String> KNOWN_FAILURE_REASONS =
            List.of(
                    "Insufficient funds",
                    "Checker Rejected",
                    "Transaction cancelled",
                    "Transaction timeout",
                    "Payment failed"
            );

    private final ObjectMapper objectMapper;

    @Value("${simulator.cab.callback-adapter-url}")
    private String callbackAdapterUrl;

    @Value("${simulator.cab.checksum-key:}")
    private String checksumKey;

    @Value("${simulator.cab.encryption-key}")
    private String encryptionKey;

    @Value("${simulator.cab.iv}")
    private String iv;

    public CabService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String bankId() {
        return "CAB";
    }

    // -------------------------------------------------------------------------
    // API 1 / TXN_INIT_URL
    // -------------------------------------------------------------------------

    /**
     * CAB receives:
     *
     * PID=<payee id>
     * data=<encrypted CAB payload>
     *
     * The common simulator already supports preprocessInit(), so CAB-specific
     * decryption is done here.
     */
    @Override
    public Map<String, String> preprocessInit(
            Map<String, String> rawFields) {

        String encryptedData =
                rawFields.get("data");

        if (encryptedData == null ||
                encryptedData.isBlank()) {

            throw new IllegalArgumentException(
                    "CAB init request is missing data"
            );
        }

        String decrypted =
                CabEncryptionUtil.decrypt(
                        encryptedData,
                        encryptionKey,
                        iv
                );

        logger.info(
                "CAB init payload decrypted successfully"
        );

        Map<String, String> decoded =
                parsePipeSeparatedPayload(
                        decrypted
                );

        /*
         * PID exists outside encrypted data.
         *
         * Preserve it under a CAB-internal key so validateInit()
         * can compare PID against payee_id.
         */
        decoded.put(
                "_PID",
                rawFields.get("PID")
        );

        return decoded;
    }

    @Override
    public ValidationResult validateInit(
            Map<String, String> raw) {

        /*
         * 1. Required fields.
         */
        for (String field : REQUIRED_INIT_FIELDS) {

            String value =
                    raw.get(field);

            if (value == null ||
                    value.isBlank()) {

                return ValidationResult.fail(
                        field,
                        "required field missing or blank"
                );
            }
        }

        /*
         * 2. CAB payment-init mode must be P.
         */
        if (!"P".equalsIgnoreCase(
                raw.get("mode"))) {

            return ValidationResult.fail(
                    "mode",
                    "expected literal 'P'"
            );
        }

        /*
         * 3. PID outside encrypted data must equal
         * payee_id inside encrypted data.
         */
        String pid =
                raw.get("_PID");

        if (pid == null ||
                pid.isBlank()) {

            return ValidationResult.fail(
                    "PID",
                    "PID query/form parameter is required"
            );
        }

        if (!pid.equals(
                raw.get("payee_id"))) {

            return ValidationResult.fail(
                    "PID/payee_id",
                    "PID does not match payee_id inside encrypted payload"
            );
        }

        /*
         * 4. Validate amount.
         */
        try {

            double amount =
                    Double.parseDouble(
                            raw.get("amount")
                    );

            if (amount <= 0) {

                return ValidationResult.fail(
                        "amount",
                        "must be greater than zero"
                );
            }

        } catch (NumberFormatException e) {

            return ValidationResult.fail(
                    "amount",
                    "not a valid decimal amount"
            );
        }

        /*
         * 5. Validate return URL.
         */
        try {

            java.net.URI.create(
                    raw.get("return_url")
            ).toURL();

        } catch (Exception e) {

            return ValidationResult.fail(
                    "return_url",
                    "not a well-formed URL"
            );
        }

        /*
         * 6. Validate CAB checksum.
         */
        if (checksumKey != null &&
                !checksumKey.isBlank()) {

            String checksumInput =
                    CabChecksumUtil
                            .buildInitChecksumString(
                                    raw,
                                    checksumKey
                            );

            String expected =
                    CabChecksumUtil
                            .computeChecksum(
                                    checksumInput
                            );

            String received =
                    raw.get("checkval");

            if (!expected.equalsIgnoreCase(
                    received)) {

                logger.warn(
                        "CAB init checksum mismatch txn={} expected={} received={}",
                        raw.get("payment_ref_no"),
                        expected,
                        received
                );

                return ValidationResult.fail(
                        "checkval",
                        "recomputed checksum does not match"
                );
            }
        }

        return ValidationResult.ok();
    }

    @Override
    public ParsedInit parseInit(
            Map<String, String> raw) {

        return new ParsedInit(
                raw.get("payment_ref_no"),
                raw.get("payee_id"),
                raw.get("amount"),
                raw.get("currency"),
                raw.get("return_url")
        );
    }

    // -------------------------------------------------------------------------
    // API 3 / CALLBACK
    // -------------------------------------------------------------------------

    @Override
    public CallbackDelivery buildCallbackResponse(
            SimulatorRecord record,
            SimulatedCase chosenCase) {

        /*
         * The common database already stores RAW_INIT_PARAMS.
         *
         * We reconstruct CAB-specific init metadata from there instead of
         * adding BANK_METADATA to the common SimulatorRecord entity.
         */
        Map<String, String> init =
                getBankMetadata(record);

        Map<String, String> fields =
                new LinkedHashMap<>();

        fields.put(
                "status",
                chosenCase.isSuccess()
                        ? "Y"
                        : "N"
        );

        fields.put(
                "payment_ref_no",
                record.getTxnId()
        );

        fields.put(
                "biller_name",
                safe(
                        init.get("biller_name")
                )
        );

        /*
         * Original SimulatorService generates bankRef immediately
         * before buildCallbackResponse() is called.
         */
        fields.put(
                "bank_ref_no",
                safe(
                        record.getBankRef()
                )
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
                        init.get("account_no")
                )
        );

        fields.put(
                "error_msg",
                chosenCase.isSuccess()
                        ? "Transaction successful"
                        : effectiveFailureReason(
                                chosenCase
                        )
        );

        String checksumInput =
                CabChecksumUtil
                        .buildCallbackChecksumString(
                                fields,
                                checksumKey
                        );

        fields.put("checksumKey", checksumKey);

        String checkval =
                CabChecksumUtil
                        .computeChecksum(
                                checksumInput
                        );

        fields.put(
                "checkval",
                checkval
        );

        String plainResponse =
                buildPipePayload(
                        fields
                );

        String encrypted =
                CabEncryptionUtil.encrypt(
                        plainResponse,
                        encryptionKey,
                        iv
                );

        /*
         * IMPORTANT:
         *
         * Original CallbackDelivery supports:
         *
         * targetUrl
         * queryParams
         * HTTP method
         *
         * It does NOT support formFields.
         *
         * Therefore the common service POSTs:
         *
         * /internal/cab/callback?data=<encrypted>
         *
         * CabCallbackController receives that request and converts it into
         * CAB's required application/x-www-form-urlencoded POST.
         */
        return new CallbackDelivery(
                callbackAdapterUrl,
                Map.of(
                        "data",
                        encrypted
                ),
                HttpMethod.POST
        );
    }

    // -------------------------------------------------------------------------
    // DOUBLE VERIFICATION REQUEST
    // -------------------------------------------------------------------------

    /**
     * Common SimulatorService calls this method BEFORE validateVerification().
     *
     * Since CAB verification comes as:
     *
     * data=<encrypted payload>
     *
     * we decrypt locally here to extract payment_ref_no.
     *
     * This avoids adding preprocessVerification() to the common interface.
     */
    @Override
    public String extractVerificationTxnId(
            Map<String, String> rawParams) {

        Map<String, String> decrypted =
                decryptVerificationRequest(
                        rawParams
                );

        return decrypted.get(
                "payment_ref_no"
        );
    }

    @Override
    public ValidationResult validateVerification(
            Map<String, String> rawParams,
            SimulatorRecord record) {

        /*
         * Decrypt again here.
         *
         * This intentionally avoids modifying SimulatorService or
         * NetbankingBankSimulator.
         */
        Map<String, String> raw;

        try {

            raw =
                    decryptVerificationRequest(
                            rawParams
                    );

        } catch (Exception e) {

            logger.warn(
                    "Could not decrypt CAB verification request txn={}",
                    record.getTxnId(),
                    e
            );

            return ValidationResult.fail(
                    "data",
                    "could not decrypt CAB verification request"
            );
        }

        /*
         * 1. Required fields.
         */
        for (String field :
                REQUIRED_VERIFY_FIELDS) {

            String value =
                    raw.get(field);

            if (value == null ||
                    value.isBlank()) {

                return ValidationResult.fail(
                        field,
                        "required field missing or blank on verification call"
                );
            }
        }

        /*
         * Reconstruct fields captured during API 1.
         */
        Map<String, String> init =
                getBankMetadata(
                        record
                );

        /*
         * 2. Check transaction id.
         */
        if (!safe(record.getTxnId())
                .equals(
                        safe(
                                raw.get(
                                        "payment_ref_no"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "payment_ref_no",
                    "does not match transaction captured at init"
            );
        }

        /*
         * 3. Check payee id.
         */
        if (!safe(init.get("payee_id"))
                .equals(
                        safe(
                                raw.get(
                                        "payee_id"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "payee_id",
                    "does not match value captured at init"
            );
        }

        /*
         * 4. Check biller.
         */
        if (!safe(init.get("biller_name"))
                .equals(
                        safe(
                                raw.get(
                                        "biller_name"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "biller_name",
                    "does not match value captured at init"
            );
        }

        /*
         * 5. Check bank reference.
         */
        if (!safe(record.getBankRef())
                .equals(
                        safe(
                                raw.get(
                                        "bank_ref_no"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "bank_ref_no",
                    "does not match generated bank reference"
            );
        }

        /*
         * 6. Check amount.
         */
        if (!safe(record.getTxnAmount())
                .equals(
                        safe(
                                raw.get(
                                        "amount"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "amount",
                    "does not match value captured at init"
            );
        }

        /*
         * 7. Check currency.
         */
        if (!safe(record.getTxnCurrency())
                .equalsIgnoreCase(
                        safe(
                                raw.get(
                                        "currency"
                                )
                        )
                )) {

            return ValidationResult.fail(
                    "currency",
                    "does not match value captured at init"
            );
        }

        /*
         * 8. Validate CAB verification checksum.
         */
        String checksumInput =
                CabChecksumUtil
                        .buildVerificationRequestChecksumString(
                                raw,
                                checksumKey
                        );

        String expected =
                CabChecksumUtil
                        .computeChecksum(
                                checksumInput
                        );

        String received =
                raw.get("checkval");

        if (!expected.equalsIgnoreCase(
                received)) {

            logger.warn(
                    "CAB verification checksum mismatch txn={} expected={} received={}",
                    record.getTxnId(),
                    expected,
                    received
            );

            return ValidationResult.fail(
                    "checkval",
                    "recomputed verification checksum does not match"
            );
        }

        return ValidationResult.ok();
    }

    // -------------------------------------------------------------------------
    // DOUBLE VERIFICATION RESPONSE
    // -------------------------------------------------------------------------

    @Override
    public VerificationWireResponse buildVerificationResponse(
            SimulatorRecord record,
            SimulatedCase chosenCase) {

        Map<String, String> fields =
                new LinkedHashMap<>();

        fields.put(
                "status",
                chosenCase.isSuccess()
                        ? "Y"
                        : "N"
        );

        fields.put(
                "payment_ref_no",
                safe(
                        record.getTxnId()
                )
        );

        fields.put(
                "bank_ref_no",
                safe(
                        record.getBankRef()
                )
        );

        fields.put(
                "amount",
                safe(
                        record.getTxnAmount()
                )
        );

        fields.put(
                "error_msg",
                chosenCase.isSuccess()
                        ? "TransactionSuccessful"
                        : effectiveFailureReason(
                                chosenCase
                        )
        );

        String checksumInput =
                CabChecksumUtil
                        .buildVerificationResponseChecksumString(
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
         * This is the HTTP RESPONSE body returned by the simulator's
         * double-verification endpoint.
         */
        String body =
                "data=" + encryptedData;

        return new VerificationWireResponse(
                "application/x-www-form-urlencoded",
                body
        );
    }

    @Override
    public VerificationWireResponse
            buildMismatchVerificationResponse(
                    SimulatorRecord record,
                    ValidationResult failure) {

        logger.warn(
                "CAB verification mismatch txn={} field={} reason={}",
                record.getTxnId(),
                failure.getField(),
                failure.getMessage()
        );

        Map<String, String> fields =
                new LinkedHashMap<>();

        fields.put(
                "status",
                "N"
        );

        fields.put(
                "payment_ref_no",
                safe(
                        record.getTxnId()
                )
        );

        fields.put(
                "bank_ref_no",
                safe(
                        record.getBankRef()
                )
        );

        fields.put(
                "amount",
                safe(
                        record.getTxnAmount()
                )
        );

        fields.put(
                "error_msg",
                "Verification mismatch"
        );

        String checksumInput =
                CabChecksumUtil
                        .buildVerificationResponseChecksumString(
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

        return new VerificationWireResponse(
                "application/x-www-form-urlencoded",
                "data=" + encryptedData,
                failure.getField()
                        + ": "
                        + failure.getMessage()
        );
    }

    // -------------------------------------------------------------------------
    // CAB HELPERS
    // -------------------------------------------------------------------------

    /**
     * Reconstruct CAB-specific API-1 information without changing
     * SimulatorRecord.
     *
     * SimulatorService already persists the original request in
     * RAW_INIT_PARAMS.
     */
    private Map<String, String> getBankMetadata(
            SimulatorRecord record) {

        String rawInitParams =
                record.getRawInitParams();

        if (rawInitParams == null ||
                rawInitParams.isBlank()) {

            throw new IllegalStateException(
                    "CAB raw init parameters missing for txn="
                            + record.getTxnId()
            );
        }

        try {

            Map<String, String> raw =
                    objectMapper.readValue(
                            rawInitParams,
                            new TypeReference<Map<String, String>>() {
                            }
                    );

            /*
             * Run CAB's existing API-1 preprocessing again.
             *
             * This decrypts the original `data` value and gives us:
             *
             * payee_id
             * biller_name
             * account_no
             * etc.
             */
            return preprocessInit(
                    raw
            );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Could not reconstruct CAB init metadata for txn="
                            + record.getTxnId(),
                    e
            );
        }
    }

    /**
     * CAB-specific verification request decryption.
     *
     * This stays private so no change to NetbankingBankSimulator is needed.
     */
    private Map<String, String> decryptVerificationRequest(
            Map<String, String> rawParams) {

        if (rawParams == null) {

            throw new IllegalArgumentException(
                    "CAB verification request cannot be null"
            );
        }

        String encryptedData =
                rawParams.get("data");

        if (encryptedData == null ||
                encryptedData.isBlank()) {

            throw new IllegalArgumentException(
                    "CAB verification request missing data"
            );
        }

        String decrypted =
                CabEncryptionUtil.decrypt(
                        encryptedData,
                        encryptionKey,
                        iv
                );

        logger.debug(
                "CAB verification payload decrypted successfully"
        );

        return parsePipeSeparatedPayload(
                decrypted
        );
    }

    private Map<String, String> parsePipeSeparatedPayload(
            String payload) {

        Map<String, String> fields =
                new LinkedHashMap<>();

        if (payload == null ||
                payload.isBlank()) {

            return fields;
        }

        String[] parts =
                payload.split("\\|");

        for (String part : parts) {

            int separator =
                    part.indexOf('=');

            if (separator <= 0) {
                continue;
            }

            String key =
                    part.substring(
                            0,
                            separator
                    ).trim();

            String value =
                    part.substring(
                            separator + 1
                    ).trim();

            fields.put(
                    key,
                    value
            );
        }

        return fields;
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

            builder.append(
                    entry.getKey()
            );

            builder.append("=");

            builder.append(
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

    @Override
    public List<String> knownFailureReasons() {
        return KNOWN_FAILURE_REASONS;
    }

    private String effectiveFailureReason(
            SimulatedCase chosenCase) {

        String reason =
                chosenCase.getFailureReason();

        return reason == null ||
                reason.isBlank()
                ? "Payment failed"
                : reason;
    }
}