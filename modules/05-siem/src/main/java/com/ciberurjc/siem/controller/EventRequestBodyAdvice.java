package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.exceptions.MissingEventBodyException;
import com.ciberurjc.siem.models.Event;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;
import java.lang.reflect.Type;

@RestControllerAdvice(assignableTypes = EventController.class)
public class EventRequestBodyAdvice extends RequestBodyAdviceAdapter {
    @Override
    public boolean supports(MethodParameter parameter, Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        return targetType == Event.class;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter,
            Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return requireBody(body, inputMessage);
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter,
            Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        // A JSON null has bytes, but deserializes to no Event.
        return requireBody(body, inputMessage);
    }

    private Object requireBody(Object body, HttpInputMessage inputMessage) {
        if (body == null) throw new MissingEventBodyException(inputMessage);
        return body;
    }
}
