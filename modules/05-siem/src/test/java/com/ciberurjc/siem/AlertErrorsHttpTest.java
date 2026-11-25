package com.ciberurjc.siem;

import com.ciberurjc.siem.controller.*;
import com.ciberurjc.siem.services.*;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AlertErrorsHttpTest {
    @Test
    void bothEndpointsReturn503ForStorageFailure() throws Exception {
        verifyFailure(new AlertStorageUnavailableException(new IllegalStateException("private-db-host")),
            503, "STORAGE_UNAVAILABLE", "Alert storage is temporarily unavailable");
    }

    @Test
    void bothEndpointsReturnGeneric500ForUnexpectedFailure() throws Exception {
        verifyFailure(new IllegalArgumentException("private-internal-data"),
            500, "INTERNAL_ERROR", "An unexpected error occurred");
    }

    @Test
    void unsupportedMethodRemains405() throws Exception {
        var repository = new AlertRepository();
        var mvc = MockMvcBuilders.standaloneSetup(new AlertController(new AlertQueryService(repository), repository))
            .setControllerAdvice(new AlertErrorHandler(), new ApiErrorHandler()).build();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/alerts"))
            .andExpect(status().isMethodNotAllowed());
    }

    private void verifyFailure(RuntimeException failure, int status, String code, String message) throws Exception {
        var repository = mock(AlertRepository.class);
        when(repository.findAll()).thenThrow(failure);
        when(repository.findById("test")).thenThrow(failure);
        var mvc = MockMvcBuilders.standaloneSetup(new AlertController(new AlertQueryService(repository), repository))
            .setControllerAdvice(new AlertErrorHandler(), new ApiErrorHandler()).build();
        for (String path : new String[]{"/alerts", "/alerts/test"}) {
            mvc.perform(get(path)).andExpect(status().is(status))
                .andExpect(content().json("{\"error\":{\"code\":\"" + code
                    + "\",\"message\":\"" + message + "\"}}", true));
        }
    }
}
