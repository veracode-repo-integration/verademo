package com.veracode.verademo.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletContext;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Scope("request")
public class ToolsController {
	private static final Logger logger = LogManager.getLogger("VeraDemo:ToolsController");

	@Autowired
	ServletContext context;

	@RequestMapping(value = "/tools", method = RequestMethod.GET)
	public String tools() {
		return "tools";
	}

	@RequestMapping(value = "/tools", method = RequestMethod.POST)
	public String tools(@RequestParam(value = "host", required = false) String host, @RequestParam(value = "fortunefile", required = false) String fortuneFile, Model model) {
		model.addAttribute("ping", host != null ? ping(host) : "");

		if (fortuneFile == null) {
			fortuneFile = "literature";
		}
		model.addAttribute("fortunes", fortune(fortuneFile));

		return "tools";
	}

	private String ping(String host) {
		String output = "";
		Process proc;

		// Sanitize host for logging to prevent log injection
		try {
			String safeHost = URLEncoder.encode(host, "UTF-8");
			logger.info("Pinging: " + safeHost);
		} catch (UnsupportedEncodingException e) {
			logger.info("Pinging: [encoding error]");
		}

		// Validate host to prevent command injection
		if (!isValidHost(host)) {
			return "Invalid host format";
		}

		try {
			/* START EXAMPLE VULNERABILITY */
			// Use direct command execution without shell to prevent command injection
			proc = Runtime.getRuntime().exec(new String[] { "ping", "-c", "1", host });
			/* END EXAMPLE VULNERABILITY */

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// Use try-with-resources to ensure BufferedReader is properly closed
			try (BufferedReader br = new BufferedReader(isr)) {
				String line;

				while ((line = br.readLine()) != null) {
					output += line + "\n";
				}
			}

			logger.info(proc.exitValue());
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}

	private String fortune(String fortuneFile) {
		String output = "";
		Process proc;

		// Validate fortuneFile to prevent command injection
		if (!isValidFortuneFile(fortuneFile)) {
			return "Invalid fortune file";
		}

		try {
			/* START EXAMPLE VULNERABILITY */
			// Use direct command execution without shell to prevent command injection
			proc = Runtime.getRuntime().exec(new String[] { "/bin/fortune", fortuneFile });
			/* END EXAMPLE VULNERABILITY */

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// Use try-with-resources to ensure BufferedReader is properly closed
			try (BufferedReader br = new BufferedReader(isr)) {
				String line;

				while ((line = br.readLine()) != null) {
					output += line + "\n";
				}
			}
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}

	// Validate host to allow only valid hostname/IP formats
	private boolean isValidHost(String host) {
		if (host == null || host.isEmpty()) {
			return false;
		}
		// Allow alphanumeric, dots, hyphens, and colons (for IPv6)
		// Prevent command injection characters
		return host.matches("^[a-zA-Z0-9.:\\-]+$");
	}

	// Validate fortune file to allow only safe filenames
	private boolean isValidFortuneFile(String fortuneFile) {
		if (fortuneFile == null || fortuneFile.isEmpty()) {
			return false;
		}
		// Allow only alphanumeric and hyphens, no path traversal
		return fortuneFile.matches("^[a-zA-Z0-9\\-]+$");
	}
}
