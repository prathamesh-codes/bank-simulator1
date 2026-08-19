package com.billdesk.pg.payments.simulator.bank.cab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * CAB-specific callback transport adapter.
 *
 * The common simulator framework supports choosing an HTTP method and
 * query parameters, but does not support bank-specific form bodies.
 *
 * CAB requires:
 *
 * POST <confirmation-url>
 * Content-Type: application/x-www-form-urlencoded
 *
 * data=<encrypted CAB response>
 *
 * Keeping this adapter inside bank/cab allows CAB to support its real
 * wire protocol without modifying CallbackDelivery or SimulatorService.
 */
@RestController
public class CabCallbackController {

    private static final Logger logger =
            LogManager.getLogger(
                    CabCallbackController.class
            );

    private final RestTemplate restTemplate;

    @Value("${simulator.cab.confirmation-url}")
    private String confirmationUrl;

    public CabCallbackController(
            RestTemplate restTemplate) {

        this.restTemplate =
                restTemplate;
    }

    @PostMapping(
            "/internal/cab/callback"
    )
    public ResponseEntity<String> callback(
            @RequestParam("data")
            String encryptedData) {

        logger.info(
                "CAB callback adapter invoked; forwarding form POST to {}",
                confirmationUrl
        );

        MultiValueMap<String, String> form =
                new LinkedMultiValueMap<>();

        form.add(
                "data",
                encryptedData
        );

        HttpHeaders headers =
                new HttpHeaders();

        headers.setContentType(
                MediaType.APPLICATION_FORM_URLENCODED
        );

        HttpEntity<
                MultiValueMap<String, String>>
                request =
                new HttpEntity<>(
                        form,
                        headers
                );

        try {

            ResponseEntity<String> response =
                    restTemplate.postForEntity(
                            confirmationUrl,
                            request,
                            String.class
                    );

            logger.info(
                    "CAB callback forwarded successfully status={}",
                    response.getStatusCode()
            );

            /*
             * Return PG's response unchanged.
             *
             * Original SimulatorService will inspect this response for:
             *
             * return_url
             * transaction_response
             *
             * exactly as it did before CAB was added.
             */
            return response;

        } catch (Exception e) {

            logger.error(
                    "CAB callback forwarding failed url={}",
                    confirmationUrl,
                    e
            );

            throw e;
        }
    }
}