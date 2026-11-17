package com.ciberurjc.siem.models;

import com.ciberurjc.siem.services.InvalidHistoryQueryException;
import org.springframework.util.MultiValueMap;
import java.util.List;

public record EventHistoryQuery(int limit, long offset) {
    public EventHistoryQuery {
        if (limit < 1 || limit > 500 || offset < 0 || offset > Long.MAX_VALUE - limit) {
            throw new InvalidHistoryQueryException();
        }
    }

    public static EventHistoryQuery from(MultiValueMap<String, String> parameters) {
        if (parameters.keySet().stream().anyMatch(name -> !name.equals("limit") && !name.equals("offset"))) {
            throw new InvalidHistoryQueryException();
        }
        long limit = readParameter(parameters, "limit", 100);
        long offset = readParameter(parameters, "offset", 0);
        if (limit < 1 || limit > 500) {
            throw new InvalidHistoryQueryException();
        }
        return new EventHistoryQuery((int) limit, offset);
    }

    private static long readParameter(MultiValueMap<String, String> parameters, String name, long defaultValue) {
        List<String> values = parameters.get(name);
        if (values == null) return defaultValue;
        if (values.size() != 1) throw new InvalidHistoryQueryException();
        String value = values.getFirst();
        if (value == null || !value.matches("[0-9]{1,19}")) throw new InvalidHistoryQueryException();
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new InvalidHistoryQueryException();
        }
    }
}
