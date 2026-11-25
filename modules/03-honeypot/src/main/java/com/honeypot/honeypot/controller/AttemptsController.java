package com.honeypot.honeypot.controller;

import com.honeypot.honeypot.repository.LoginAttemptRepository;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@Profile("dev")
public class AttemptsController {
    private final LoginAttemptRepository loginAttemptRepository;
    public AttemptsController(LoginAttemptRepository loginAttemptRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
    }
    @GetMapping("/attempts")
    public String attempts(Model model) {
		List<Map<String, Object>> attempts = loginAttemptRepository.findAll().stream()
				.map(attempt -> {
					Map<String, Object> row = new HashMap<>();
					row.put("id", attempt.getId());
					row.put("sourceIp", Objects.toString(attempt.getSourceIp(), ""));
					row.put("occurredAt", Objects.toString(attempt.getOccurredAt(), ""));
					row.put("serviceAttacked", Objects.toString(attempt.getServiceAttacked(), ""));
					row.put("username", Objects.toString(attempt.getUsername(), ""));
					row.put("credentialAttempt", Objects.toString(attempt.getCredentialAttempt(), ""));
					return row;
				})
				.toList();
        model.addAttribute("attempts", attempts);
        return "attempts";
    }

	@PostMapping("/attempts/clear")
	public String clearAttempts() {
		loginAttemptRepository.deleteAll();
		return "redirect:/attempts";
	}
}